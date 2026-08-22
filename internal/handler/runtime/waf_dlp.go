package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/internal/runtime/waf"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/group"
)

// WAF rule enforcement was removed (WS-G G1): the /waf/groups CRUD never had
// an agent bundle endpoint, a sync worker, or a DP consumer, so its rules
// never reached the dataplane. DPI Signatures (runtime_signatures.go, backed
// by runtime_dlp_rules + Supervisor.BuildDLPRules) are the single
// authoritative DPI/L7 ruleset that compiles to dp's hyperscan engine. The
// in-process L7 evaluator in internal/runtime/waf (Engine/BuiltinCRS) is kept
// for the runtime pipeline; only the orphan CRUD surface was deleted here.
//
// G2.2: the authored CRS pack (waf.BuiltinCRS — SQLi/XSS/LFI/RCE/scanner-UA)
// now DOES reach the dataplane through a dedicated WAF pattern table, distinct
// from DLP. WAFRuleTable renders the 12 CRS rules as dp.WAFRule entries (one
// PCRE per rule, tagged with its HTTP HEAD/BODY context), and PushWAFRules
// pushes them over dp's WAF RPCs (BuildWAFRules + ConfigureWAFRules → dp's
// ep->waf_cfg_map). Unlike the earlier rules_builtin.go path — which flattened
// WAF patterns into category='signature' DLP rows and so lost the WAF/DLP split
// and per-context matching — this keeps WAF in its own dp table with a
// WAF-flavoured enforce action (RESET), mirroring NeuVector's wafinside table.
//
// Mode parity with DLP: rules ship monitor-by-default; a rule only RESETs when
// the fleet enforce gate is on AND the authored rule's Action is "block".

// wafTargetContext maps a CRS rule's ModSecurity target to the dp WAF pattern
// context. dp scans HTTP into three separate buffers and a rule only matches the
// one its context names, so each target must land in the buffer it actually lives
// in (dpi_http.c): the request line/URL/query args -> "url" (WAFCtxURL); the header
// block and cookies -> "header" (WAFCtxHead); the entity body / POST args -> "body"
// (WAFCtxBody). The old code collapsed everything but REQUEST_BODY into HEAD, so
// ARGS/REQUEST_URI rules scanned the header buffer and missed all URL/query attacks.
//
// ModSec ARGS spans GET (url) + POST (body); we map it to url (GET). No current CRS
// rule targets POST args, so nothing is lost today; a POST-arg rule would need a
// second pattern in the body context.
func wafTargetContext(target string) string {
	switch {
	case target == "REQUEST_BODY" ||
		strings.HasPrefix(target, "ARGS_POST") ||
		strings.HasPrefix(target, "XML") ||
		strings.HasPrefix(target, "JSON"):
		return dp.WAFCtxBody
	case strings.HasPrefix(target, "REQUEST_HEADERS") ||
		strings.HasPrefix(target, "REQUEST_COOKIES"):
		return dp.WAFCtxHead
	case strings.HasPrefix(target, "ARGS") || // ARGS / ARGS_GET / ARGS_NAMES
		target == "QUERY_STRING" ||
		strings.HasPrefix(target, "REQUEST_URI") || // REQUEST_URI / REQUEST_URI_RAW
		target == "REQUEST_FILENAME" ||
		target == "REQUEST_BASENAME" ||
		target == "REQUEST_LINE" ||
		target == "REQUEST_METHOD" ||
		target == "REQUEST_PROTOCOL":
		return dp.WAFCtxURL
	default:
		return dp.WAFCtxHead
	}
}

// WAFRuleTable renders the built-in OWASP-CRS pack as dp WAF rules. Each CRS
// rule becomes one dp.WAFRule carrying a single PCRE pattern (reusing
// wafOpToPattern, the same operator→PCRE lowering the seed path uses) tagged
// with the rule's HTTP context and keyed by the CRS rule ID as the dp sigid.
//
// enforce gates the per-rule mode exactly like the DLP fleet gate: when false
// every rule is monitor (alert-only); when true a rule inherits "enforce" only
// if its authored Action is "block" (so alert-only CRS rules — comment-evasion
// SQLi, event-handler XSS, scanner-UA — stay monitor even under enforce).
func WAFRuleTable(enforce bool) []*dp.WAFRule {
	crs := waf.BuiltinCRS()
	out := make([]*dp.WAFRule, 0, len(crs.Rules))
	for _, r := range crs.Rules {
		pcre := wafOpToPattern(r.Operator)
		if pcre == "" {
			continue
		}
		ctx := wafTargetContext(r.Target)
		// dp scans the raw percent-encoded URI and never url-decodes; widen
		// url-context patterns so single-encoded attacks (UNION%20SELECT) match.
		if ctx == dp.WAFCtxURL && hasTransform(r.Transformations, "urlDecode") {
			pcre = urlEncodeTolerant(pcre)
		}
		mode := "monitor"
		if enforce && r.Action == "block" {
			mode = "enforce"
		}
		// dp rejects names with spaces and sig ids outside 20000-49999
		// (dpi_sig.c / dpi_sigopt_basic.c). CRS names are human strings and CRS
		// ids (942100…) are far out of range, so sanitize the name and assign a
		// sequential in-range WAF sig id — stable across restarts (fixed list).
		out = append(out, &dp.WAFRule{
			Name: dp.SanitizeSigName(r.Msg),
			ID:   dp.WAFSigID(len(out)),
			Patterns: []dp.WAFPattern{{
				Context: ctx,
				Value:   pcre,
			}},
			Mode: mode,
		})
	}
	return out
}

// wafNameByID maps a dp WAF sig id (40000+) back to its human CRS rule message,
// reproducing WAFRuleTable's exact filter+order so id-40000 lines up with the rule
// dp actually matched. dp reports WAF hits as "WAF: id 40002"; this turns that into
// "SQL Injection Attempt (UNION SELECT)" the way NeuVector labels sensor hits.
var wafNameByID = func() map[uint32]string {
	m := map[uint32]string{}
	i := 0
	for _, r := range waf.BuiltinCRS().Rules {
		if wafOpToPattern(r.Operator) == "" {
			continue
		}
		m[dp.WAFSigID(i)] = r.Msg
		i++
	}
	return m
}()

// WAFThreatName returns the CRS rule message for a dp WAF sig id (40000-49999),
// or "" if the id isn't a known WAF rule.
func WAFThreatName(id uint32) string { return wafNameByID[id] }

// resolveThreatName labels a dp threat id: WAF sensor hits (40000-49999) get their
// CRS rule message; everything else falls back to the built-in DPI signature names.
func resolveThreatName(id uint32) string {
	if n := WAFThreatName(id); n != "" {
		return n
	}
	return handler.NeuVectorThreatName(id)
}

// PushWAFRules compiles the CRS pack into dp's hyperscan DB and binds it to the
// given workload MACs under the dedicated WAF table. It is the WAF analogue of
// the DLP sync worker's BuildDLPRules + ConfigureDLPRules pair: BuildWAFRules
// pushes the patterns, ConfigureWAFRules installs the per-rule action so
// enforce-mode rules actually RESET. WAF runs ingress by default (block inbound
// web attacks). No-op when there are no MACs to scan.
//
// STANDALONE ONLY. dp keeps ONE detector per endpoint, so a WAF-only
// ctrl_bld_dlp and a DLP-only ctrl_bld_dlp CLOBBER each other (the second
// build's dpi_dlp_detect_update destroys the first's patterns). The runtime
// agent therefore no longer calls this alongside a DLP build — it uses
// Supervisor.BuildDetector + ConfigureDetector to compile BOTH rule sets into
// one detector. Only use PushWAFRules where a workload has WAF rules and nothing
// else on the shared DLP/WAF detector.
func PushWAFRules(sup *dp.Supervisor, macs []string, enforce bool) error {
	if len(macs) == 0 {
		return nil
	}
	rules := WAFRuleTable(enforce)
	if err := sup.BuildWAFRules(rules, macs, nil, dp.ApplyDirIngress); err != nil {
		return err
	}
	return sup.ConfigureWAFRules(macs, rules)
}

// ----- NET-43: group → DLP/WAF sensor binding --------------------------------
//
// NeuVector binds a DLP/WAF SENSOR (a named rule set) to a GROUP, so every
// current and future member workload of that group inherits the sensor
// (controller/cache dlp_group / waf_group). Constellation's only DPI opt-in was
// per-POD-LABEL (dpi.constellation.alphabravo.io/waf|dlp), which can't express
// "this whole group runs sensor S". group_dpi_sensor_bindings (migration 153)
// adds that binding as an ADDITIONAL path — the label opt-in keeps working
// unchanged.
//
// Resolution (resolveSensorMACs, below) is the tractable, unit-tested core: it
// turns bindings + group membership + a workload→MAC map into the set of MACs
// each sensor must bind to, exactly the scope the DLP push already understands
// (runtime_dlp_rules.scope_macs). Wiring that resolved scope into the agent
// bundle (serving dlp_sensors / waf_groups rows scoped to those MACs) and the
// sensor-authoring REST routes are the documented follow-up — see the note at
// the end of this block. No server.go route is added here.

// SensorKind selects which sensor table a binding references: 'dlp' →
// dlp_sensors(id), 'waf' → waf_groups(id) (026_waf_dlp.sql).
type SensorKind string

const (
	SensorKindDLP SensorKind = "dlp"
	SensorKindWAF SensorKind = "waf"
)

func (k SensorKind) Valid() bool { return k == SensorKindDLP || k == SensorKindWAF }

// GroupSensorBinding is one row of group_dpi_sensor_bindings: sensor SensorID
// (of kind Kind) attached to group GroupID.
type GroupSensorBinding struct {
	ID       uuid.UUID  `json:"id"`
	OrgID    uuid.UUID  `json:"org_id"`
	GroupID  uuid.UUID  `json:"group_id"`
	Kind     SensorKind `json:"sensor_kind"`
	SensorID uuid.UUID  `json:"sensor_id"`
}

// SensorKey identifies a sensor across bindings so multiple groups pointing at
// the same sensor aggregate into one MAC set.
type SensorKey struct {
	Kind SensorKind
	ID   uuid.UUID
}

// GroupSensorBindingStore persists group→sensor bindings.
type GroupSensorBindingStore struct{ db *db.DB }

// NewGroupSensorBindingStore builds the store.
func NewGroupSensorBindingStore(d *db.DB) *GroupSensorBindingStore {
	return &GroupSensorBindingStore{db: d}
}

// Bind attaches a sensor to a group (idempotent on the UNIQUE key). Returns the
// binding id.
func (s *GroupSensorBindingStore) Bind(ctx context.Context, orgID, groupID uuid.UUID, kind SensorKind, sensorID uuid.UUID, by *uuid.UUID) (uuid.UUID, error) {
	if !kind.Valid() {
		return uuid.Nil, errInvalidSensorKind
	}
	var id uuid.UUID
	err := s.db.Pool().QueryRow(ctx, `
INSERT INTO group_dpi_sensor_bindings (org_id, group_id, sensor_kind, sensor_id, created_by)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (group_id, sensor_kind, sensor_id) DO UPDATE SET sensor_id = EXCLUDED.sensor_id
RETURNING id`, orgID, groupID, string(kind), sensorID, by).Scan(&id)
	return id, err
}

// Unbind removes a binding by id, scoped to the org.
func (s *GroupSensorBindingStore) Unbind(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := s.db.Pool().Exec(ctx,
		`DELETE FROM group_dpi_sensor_bindings WHERE id = $1 AND org_id = $2`, id, orgID)
	return err
}

// ListForOrg returns every binding for the org.
func (s *GroupSensorBindingStore) ListForOrg(ctx context.Context, orgID uuid.UUID) ([]GroupSensorBinding, error) {
	rows, err := s.db.Pool().Query(ctx,
		`SELECT id, org_id, group_id, sensor_kind, sensor_id
		   FROM group_dpi_sensor_bindings WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupSensorBinding
	for rows.Next() {
		var b GroupSensorBinding
		var kind string
		if err := rows.Scan(&b.ID, &b.OrgID, &b.GroupID, &kind, &b.SensorID); err != nil {
			return nil, err
		}
		b.Kind = SensorKind(kind)
		out = append(out, b)
	}
	return out, rows.Err()
}

// errInvalidSensorKind is returned by Bind for an unknown sensor kind.
var errInvalidSensorKind = &sensorKindError{}

type sensorKindError struct{}

func (*sensorKindError) Error() string { return "sensor_kind must be 'dlp' or 'waf'" }

// resolveSensorMACs is the tested core of the group→sensor binding: it resolves
// every binding down to the set of workload MACs its sensor must bind to.
//
//	bindings      — group→sensor rows (any org subset the caller loaded).
//	groupMembers  — group id → its member workload ids (ns/name), as the group
//	                membership reconciler computes them (groups.members).
//	workloadMACs  — workload id → the tap MACs of that workload's pods.
//
// The result maps each sensor (kind+id) to the sorted, de-duplicated union of
// the MACs of every group bound to it. A binding whose group has no members, or
// whose members have no known MACs, contributes nothing (not an error) — it
// simply hasn't been observed on the datapath yet. Pure + deterministic so the
// binding logic is unit-testable without a live dp or DB.
func resolveSensorMACs(bindings []GroupSensorBinding, groupMembers map[uuid.UUID][]string, workloadMACs map[string][]string) map[SensorKey][]string {
	acc := map[SensorKey]map[string]struct{}{}
	for _, b := range bindings {
		key := SensorKey{Kind: b.Kind, ID: b.SensorID}
		set := acc[key]
		if set == nil {
			set = map[string]struct{}{}
			acc[key] = set
		}
		for _, wl := range groupMembers[b.GroupID] {
			for _, mac := range workloadMACs[wl] {
				m := strings.ToLower(strings.TrimSpace(mac))
				if m != "" {
					set[m] = struct{}{}
				}
			}
		}
	}
	out := make(map[SensorKey][]string, len(acc))
	for key, set := range acc {
		macs := make([]string, 0, len(set))
		for m := range set {
			macs = append(macs, m)
		}
		sort.Strings(macs)
		out[key] = macs
	}
	return out
}

// ResolveSensorMACs is the exported entry point to resolveSensorMACs so the
// runtime-agent (package main) can reuse the tested resolution core when it maps
// its locally-tapped pods → bound groups → the MACs each sensor must scope to.
func ResolveSensorMACs(bindings []GroupSensorBinding, groupMembers map[uuid.UUID][]string, workloadMACs map[string][]string) map[SensorKey][]string {
	return resolveSensorMACs(bindings, groupMembers, workloadMACs)
}

// ----- NET-43: bundle delivery of bound group definitions --------------------
//
// The agent resolves bindings against its LOCAL pods (deployments carry no MAC
// server-side; only the agent knows a pod's MAC + labels), so the bundle ships
// each bound group's SELECTOR (namespace + label criteria) alongside the
// bindings. The agent matches its tapped pods against those selectors (pkg/group
// Group.Matches) to derive per-pod group membership, then scopes the DLP/WAF push
// to the matched pods' MACs.

// BoundGroupDef is one bound group's identity + selector, delivered in the agent
// bundle so the agent can match local pods to the group without a server-side
// workload→MAC map. Criteria are the group's raw selector rows ([{key,value,op}]).
type BoundGroupDef struct {
	ID       uuid.UUID         `json:"id"`
	Name     string            `json:"name"`
	Criteria []group.Criterion `json:"criteria"`
}

// BoundGroupDefs loads the selector of every group that has at least one
// group_dpi_sensor_binding in the org. Only bound groups are returned — an
// unbound group's selector is irrelevant to the DPI push.
func (s *GroupSensorBindingStore) BoundGroupDefs(ctx context.Context, orgID uuid.UUID) ([]BoundGroupDef, error) {
	rows, err := s.db.Pool().Query(ctx, `
SELECT g.id, g.name, COALESCE(g.criteria,'[]'::jsonb)
  FROM groups g
 WHERE g.org_id = $1
   AND EXISTS (SELECT 1 FROM group_dpi_sensor_bindings b WHERE b.group_id = g.id AND b.org_id = $1)`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BoundGroupDef
	for rows.Next() {
		var d BoundGroupDef
		var criteria []byte
		if err := rows.Scan(&d.ID, &d.Name, &criteria); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(criteria, &d.Criteria)
		out = append(out, d)
	}
	return out, rows.Err()
}

// ----- NET-43: group→sensor binding HTTP surface -----------------------------

// GroupSensorBindingsHTTP wraps the binding store with org-scoped, audited HTTP
// handlers. Bind/Unbind write hash-chained audit rows exactly like the DLP-rule
// CRUD; List is a plain read.
type GroupSensorBindingsHTTP struct {
	store    *GroupSensorBindingStore
	auditLog *audit.Logger
}

// NewGroupSensorBindingsHTTP builds the HTTP surface. auditLog may be nil in tests.
func NewGroupSensorBindingsHTTP(d *db.DB, auditLog *audit.Logger) *GroupSensorBindingsHTTP {
	return &GroupSensorBindingsHTTP{store: NewGroupSensorBindingStore(d), auditLog: auditLog}
}

// bindActionCreate / bindActionDelete are the audit action codes for the two
// mutations, mirroring the runtime.* namespace pkg/audit already uses.
const (
	bindActionCreate = "runtime.dpi_sensor_binding.create"
	bindActionDelete = "runtime.dpi_sensor_binding.delete"
)

// BindRequest is the POST body: attach sensor SensorID (kind SensorKind) to GroupID.
type BindRequest struct {
	GroupID    uuid.UUID  `json:"group_id"`
	SensorKind SensorKind `json:"sensor_kind"`
	SensorID   uuid.UUID  `json:"sensor_id"`
}

// Bind handles POST /runtime/dpi-sensor-bindings.
func (h *GroupSensorBindingsHTTP) Bind(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req BindRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.GroupID == uuid.Nil {
		jsonError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	if req.SensorID == uuid.Nil {
		jsonError(w, http.StatusBadRequest, "sensor_id is required")
		return
	}
	if !req.SensorKind.Valid() {
		jsonError(w, http.StatusBadRequest, "sensor_kind must be 'dlp' or 'waf'")
		return
	}
	id, err := h.store.Bind(r.Context(), sub.OrgID, req.GroupID, req.SensorKind, req.SensorID, &sub.UserID)
	if err != nil {
		// A group_id that isn't in this org trips the FK; surface it as a 400
		// rather than a 500 so the caller can correct it.
		if strings.Contains(err.Error(), "foreign key") || strings.Contains(err.Error(), "violates") {
			jsonError(w, http.StatusBadRequest, "group not found")
			return
		}
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	binding := GroupSensorBinding{
		ID: id, OrgID: sub.OrgID, GroupID: req.GroupID,
		Kind: req.SensorKind, SensorID: req.SensorID,
	}
	if h.auditLog != nil {
		_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
			OrgID: &sub.OrgID, ActorID: &sub.UserID,
			Action: bindActionCreate, TargetKind: "dpi_sensor_binding", TargetID: id.String(),
			After: binding, RequestID: requestIDFrom(r),
		})
	}
	httpx.WriteJSON(w, http.StatusCreated, binding)
}

// List handles GET /runtime/dpi-sensor-bindings — every binding in the org.
func (h *GroupSensorBindingsHTTP) List(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	rows, err := h.store.ListForOrg(r.Context(), sub.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"bindings": rows})
}

// Unbind handles DELETE /runtime/dpi-sensor-bindings/{id}.
func (h *GroupSensorBindingsHTTP) Unbind(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id, err := uuid.Parse(pathTail(r.URL.Path))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.store.Unbind(r.Context(), sub.OrgID, id); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.auditLog != nil {
		_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
			OrgID: &sub.OrgID, ActorID: &sub.UserID,
			Action: bindActionDelete, TargetKind: "dpi_sensor_binding", TargetID: id.String(),
			RequestID: requestIDFrom(r),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ROUTES TO WIRE (internal/server/server.go — left as a comment per task
// constraints). Bindings mutate DPI scope, so create/delete take VerbManagePolicies
// and the read takes VerbReadFindings. Register alongside the other /runtime
// user-RBAC routes (the JWT group near /runtime-dlp-rules):
//
//	bindingsHTTP := runtime.NewGroupSensorBindingsHTTP(s.db, s.auditLog)
//	r.Post("/runtime/dpi-sensor-bindings", s.requireVerb(rbac.VerbManagePolicies, bindingsHTTP.Bind))
//	r.Get("/runtime/dpi-sensor-bindings", s.requireVerb(rbac.VerbReadFindings, bindingsHTTP.List))
//	r.Delete("/runtime/dpi-sensor-bindings/{id}", s.requireVerb(rbac.VerbManagePolicies, bindingsHTTP.Unbind))

// DLP sensors CRUD (the /dlp/sensors REST surface + ConstellationDLPSensor CRD)
// was removed following the WS-G G1 precedent: like the deleted /waf/groups CRUD,
// the dlp_sensors table it wrote never reached the dataplane — no agent bundle
// endpoint, no sync worker, and no dp consumer ever read it, so authored sensors
// enforced nothing. The authoritative enforced DLP path is runtime_dlp_rules
// (runtime_dlp.go, seeded from the code-level dlp.DefaultCatalog() in
// rules_builtin.go and served to agents via AgentBundle). See
// internal/handler/dlp_sensors_removed_test.go for the orphan-surface guard.
