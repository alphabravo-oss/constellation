// Wave C4: HTTP CRUD + storage for user-authored DLP regex rules.
//
//	GET    /api/v1/runtime-dlp-rules?cluster_id=...     list (read-findings)
//	GET    /api/v1/runtime-dlp-rules/{id}              get one
//	POST   /api/v1/runtime-dlp-rules                   create (manage-policies)
//	PUT    /api/v1/runtime-dlp-rules/{id}              update patterns / mode / severity
//	POST   /api/v1/runtime-dlp-rules/{id}/promote      → enforce
//	POST   /api/v1/runtime-dlp-rules/{id}/demote       → monitor
//	POST   /api/v1/runtime-dlp-rules/{id}/disable      → disabled
//	DELETE /api/v1/runtime-dlp-rules/{id}              delete
//
// dp-side wiring uses the existing BuildDLPRules RPC scaffolded in Wave A1.
// The agent's push loop (not in this wave; tracked as C4-followup) reads
// runtime_dlp_rules for its cluster periodically and calls BuildDLPRules
// to keep dp's hyperscan database in sync.
//
// Audit: every mutation writes a hash-chained audit_events row using the
// same constants pkg/audit defines, mirroring runtime_policies.
package runtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/runtime/dlp"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// DLPMode mirrors the CHECK constraint on runtime_dlp_rules.mode.
type DLPMode string

const (
	DLPModeMonitor  DLPMode = "monitor"
	DLPModeEnforce  DLPMode = "enforce"
	DLPModeDisabled DLPMode = "disabled"
)

func (m DLPMode) Valid() bool {
	switch m {
	case DLPModeMonitor, DLPModeEnforce, DLPModeDisabled:
		return true
	}
	return false
}

// DLPCategory taxonomises a rule. dlp = payload-exfiltration patterns
// (default, applies egress); signature = attack-pattern matchers (custom
// DPI, applies bidirectionally by default).
type DLPCategory string

const (
	CategoryDLP       DLPCategory = "dlp"
	CategorySignature DLPCategory = "signature"
	// CategoryWAF (NET-42) marks a user-authored WAF rule: an inbound
	// web-attack matcher that must enforce on dp's WAF path (RESET the
	// offending HTTP session) rather than the DLP path (silent DROP). The
	// agent's dlp_sync worker routes these rows into the dp WAF rule set
	// (sig ids 40000-49999) alongside the built-in CRS pack; every other
	// category feeds the DLP detector. Defaults to ingress (apply_dir=2).
	CategoryWAF DLPCategory = "waf"
)

func (c DLPCategory) Valid() bool {
	return c == CategoryDLP || c == CategorySignature || c == CategoryWAF
}

// DLPRule is one row in runtime_dlp_rules. Despite the table name, a row
// can be either a DLP exfiltration pattern OR a custom DPI signature —
// distinguished by Category (Wave D4). Both feed dp's hyperscan engine
// via the same wire RPC.
type DLPRule struct {
	ID        uuid.UUID       `json:"id"`
	DPRuleID  int64           `json:"dp_rule_id"`
	OrgID     uuid.UUID       `json:"org_id"`
	ClusterID uuid.UUID       `json:"cluster_id"`
	Name      string          `json:"name"`
	Category  DLPCategory     `json:"category"`
	ApplyDir  int16           `json:"apply_dir"` // 1=egress, 2=ingress, 3=both
	Severity  int16           `json:"severity"`
	Mode      DLPMode         `json:"mode"`
	Patterns  json.RawMessage `json:"patterns"` // []string PCRE
	// ScopeMACs is the optional per-workload/group scope (P1-5). Empty ⇒
	// apply to every tapped workload on the cluster (fleet-wide default). A
	// non-empty list restricts the rule to those workload MACs; the agent
	// intersects it with the MACs it taps. Group selectors are expanded to
	// member MACs before they reach here.
	ScopeMACs   []string   `json:"scope_macs,omitempty"`
	Description string     `json:"description,omitempty"`
	Source      string     `json:"source"`
	CfgType     string     `json:"cfg_type"`
	SourcePath  string     `json:"source_path,omitempty"`
	Version     int64      `json:"version"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// DecodePatterns reads the JSONB patterns column as a slice of pattern strings.
// It accepts both the legacy bare-string array and the NET-40
// {pattern, op, context} object array, returning just the pattern strings (used
// for the audit count). Use DecodePatternSpecs when the op/context are needed.
func (r *DLPRule) DecodePatterns() ([]string, error) {
	specs, err := dlp.ParsePatternSpecs(r.Patterns)
	if err != nil {
		return nil, err
	}
	if specs == nil {
		return nil, nil
	}
	out := make([]string, len(specs))
	for i, sp := range specs {
		out[i] = sp.Pattern
	}
	return out, nil
}

// DecodePatternSpecs reads the JSONB patterns column as structured NET-40 specs
// (pattern + op + context), accepting the legacy bare-string form too.
func (r *DLPRule) DecodePatternSpecs() ([]dlp.PatternSpec, error) {
	return dlp.ParsePatternSpecs(r.Patterns)
}

// RuntimeDLPStore is the persistence layer.
type RuntimeDLPStore struct {
	db       *db.DB
	auditLog *audit.Logger

	// seeded remembers which clusters we've already seeded built-ins for this
	// process, so the lazy seed in AgentBundle runs one INSERT batch per
	// cluster per lifetime instead of on every 60s agent poll. The DB's
	// ON CONFLICT DO NOTHING is the durable guarantee; this is just a cache.
	seeded sync.Map // dlpSeedScope → struct{}
}

// NewRuntimeDLPStore — auditLog may be nil in tests.
func NewRuntimeDLPStore(d *db.DB, auditLog *audit.Logger) *RuntimeDLPStore {
	return &RuntimeDLPStore{db: d, auditLog: auditLog}
}

func snapshotDLP(r *DLPRule) audit.PolicySnapshot {
	pc := 0
	if p, err := r.DecodePatterns(); err == nil {
		pc = len(p)
	}
	return audit.PolicySnapshot{
		ID: r.ID, Workload: "dlp", Namespace: "dlp",
		Name: r.Name, Mode: string(r.Mode),
		RuleCount: pc, Version: r.Version,
	}
}

const dlpSelectCols = `
  id, dp_rule_id, org_id, cluster_id, name, category, apply_dir, severity, mode,
  patterns, COALESCE(scope_macs::text,''), COALESCE(description,''), version,
  created_by, created_at, updated_by, updated_at,
  COALESCE(source,'user'), COALESCE(cfg_type,'user_created'), COALESCE(source_path,'')`

// Insert persists a new rule. Always starts in monitor mode (the safety
// contract that runtime_policies has).
func (s *RuntimePolicyStore_DLP) Insert(ctx context.Context, r *DLPRule, requestID string) (uuid.UUID, error) {
	return s.inner.Insert(ctx, r, requestID)
}

// Insert persists a new DLP rule + writes an audit row. Defaults:
// Category=dlp, ApplyDir=egress (1). Signature rules should set Category
// explicitly; the handler does that when called from the signatures
// endpoints.
func (s *RuntimeDLPStore) Insert(ctx context.Context, r *DLPRule, requestID string) (uuid.UUID, error) {
	saved, err := s.insertDLPRule(ctx, r, requestID)
	if err != nil {
		return uuid.Nil, err
	}
	return saved.ID, nil
}

func validDLPRuleSource(source string) bool {
	switch source {
	case "user", "neuvector", "import", "builtin", "federation":
		return true
	default:
		return false
	}
}

func validDLPRuleCfgType(cfgType string) bool {
	switch cfgType {
	case "user_created", "imported", "learned", "federated", "predefined":
		return true
	default:
		return false
	}
}

type dlpSeedScope struct{ org, cluster uuid.UUID }

// Cache only a successfully committed seed for this exact organization/cluster.
func (s *RuntimeDLPStore) ensureBuiltinsOnce(ctx context.Context, orgID, clusterID uuid.UUID) error {
	if err := s.requireOwnedCluster(ctx, orgID, clusterID); err != nil {
		return err
	}
	key := dlpSeedScope{orgID, clusterID}
	if _, done := s.seeded.Load(key); done {
		return nil
	}
	if _, err := s.EnsureBuiltins(ctx, orgID, clusterID); err != nil {
		return err
	}
	s.seeded.Store(key, struct{}{})
	return nil
}

// Get fetches one rule, scoped to the org.
func (s *RuntimeDLPStore) Get(ctx context.Context, orgID, id uuid.UUID) (*DLPRule, error) {
	row := s.db.Pool().QueryRow(ctx, `SELECT `+dlpSelectCols+
		` FROM runtime_dlp_rules WHERE id = $1 AND org_id = $2 AND EXISTS (SELECT 1 FROM clusters c WHERE c.id=runtime_dlp_rules.cluster_id AND c.org_id=$2)`, id, orgID)
	return scanDLP(row)
}

// ListForCluster returns every non-disabled rule for the cluster, sorted
// by name. The agent uses this to know what to push to dp. category="" (or
// "all") returns both DLP and signature rules — the agent pushes them as
// one batch since dp's engine doesn't distinguish.
func (s *RuntimeDLPStore) ListForCluster(ctx context.Context, orgID, clusterID uuid.UUID, category DLPCategory) ([]*DLPRule, error) {
	if err := s.requireOwnedCluster(ctx, orgID, clusterID); err != nil {
		return nil, err
	}
	rows, err := s.db.Pool().Query(ctx, `SELECT `+dlpSelectCols+
		` FROM runtime_dlp_rules
 WHERE org_id = $1 AND cluster_id = $2 AND mode <> 'disabled'
   AND EXISTS (SELECT 1 FROM clusters c WHERE c.id=runtime_dlp_rules.cluster_id AND c.org_id=$1)
   AND ($3::text = '' OR category = $3)
 ORDER BY name`, orgID, clusterID, string(category))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*DLPRule, 0, 8)
	for rows.Next() {
		r, err := scanDLP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanDLP(s rowScanner) (*DLPRule, error) {
	var r DLPRule
	var mode, category, patternsText, scopeText string
	if err := s.Scan(
		&r.ID, &r.DPRuleID, &r.OrgID, &r.ClusterID, &r.Name, &category, &r.ApplyDir, &r.Severity, &mode,
		&patternsText, &scopeText, &r.Description, &r.Version,
		&r.CreatedBy, &r.CreatedAt, &r.UpdatedBy, &r.UpdatedAt,
		&r.Source, &r.CfgType, &r.SourcePath,
	); err != nil {
		return nil, err
	}
	r.Mode = DLPMode(mode)
	r.Category = DLPCategory(category)
	r.Patterns = json.RawMessage(patternsText)
	if scopeText != "" && scopeText != "null" {
		_ = json.Unmarshal([]byte(scopeText), &r.ScopeMACs)
	}
	return &r, nil
}

// scopeMACsJSON renders a scope list as a JSONB argument: NULL for empty
// (the "apply to all workloads" default), a normalised lowercase JSON array
// otherwise. Returning nil makes pgx send SQL NULL for the $::jsonb param.
func scopeMACsJSON(macs []string) any {
	if len(macs) == 0 {
		return nil
	}
	norm := make([]string, 0, len(macs))
	for _, m := range macs {
		m = strings.ToLower(strings.TrimSpace(m))
		if m != "" {
			norm = append(norm, m)
		}
	}
	if len(norm) == 0 {
		return nil
	}
	b, err := json.Marshal(norm)
	if err != nil {
		return nil
	}
	return string(b)
}

// Update changes patterns + severity + description in one shot. Mode goes
// through dedicated promote/demote/disable endpoints so the UI's
// confirmation hooks can fire per-route.
func (s *RuntimeDLPStore) Update(ctx context.Context, orgID, id uuid.UUID,
	patterns json.RawMessage, severity int16, description string, scope *[]string, by uuid.UUID, requestID string) (*DLPRule, error) {
	return s.updateDLPRule(ctx, orgID, id, UpdateDLPRequest{Patterns: &patterns, Severity: severity, Description: description, ScopeMACs: scope}, by, requestID, nil)
}

func (s *RuntimeDLPStore) SetMode(ctx context.Context, orgID, id uuid.UUID, mode DLPMode, by uuid.UUID, requestID string) error {
	_, err := s.setDLPMode(ctx, orgID, id, mode, by, requestID, nil)
	return err
}

func (s *RuntimeDLPStore) Delete(ctx context.Context, orgID, id uuid.UUID, by *uuid.UUID, requestID string) error {
	return s.deleteDLPRule(ctx, orgID, id, by, requestID, nil)
}

// ---------------- HTTP handlers ----------------

// RuntimeDLPHTTP wraps the store with HTTP handlers.
type RuntimeDLPHTTP struct {
	store      *RuntimeDLPStore
	categories []DLPCategory
}

func NewRuntimeDLPHTTP(d *db.DB, auditLog *audit.Logger) *RuntimeDLPHTTP {
	return &RuntimeDLPHTTP{store: NewRuntimeDLPStore(d, auditLog)}
}

func (h *RuntimeDLPHTTP) List(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	// ?category=dlp|signature|"" — empty/missing returns both for the
	// agent's sync poller; the UI passes the specific category it shows.
	category := DLPCategory(strings.TrimSpace(r.URL.Query().Get("category")))
	if category != "" && !category.Valid() {
		jsonError(w, http.StatusBadRequest, "invalid category")
		return
	}
	rows, err := h.store.ListForCluster(r.Context(), sub.OrgID, clusterID, category)
	if err != nil {
		writeDLPError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rules": rows})
}

// AgentBundle serves a cluster's DLP/signature rules to the runtime-agent sync
// poller, authenticated by the runtime-agent token. The user-facing List is
// guarded by user RBAC, so a bearer-token agent 401s against it (observed in
// agent logs). Mirrors the file-profile/process-baseline bundle endpoints; same
// {"rules": [...]} envelope the agent already decodes. Org-scoped via the token.
func (h *RuntimeDLPHTTP) AgentBundle(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	if len(r.URL.Query()["cluster_id"]) != 1 {
		jsonError(w, http.StatusBadRequest, "one cluster_id is required")
		return
	}
	if !h.authorizeDLPAgent(w, r, clusterID) {
		return
	}
	// A failed seed must not replace the agent's existing rules with an incomplete bundle.
	if err := h.store.ensureBuiltinsOnce(r.Context(), tok.OrgID, clusterID); err != nil {
		writeDLPError(w, err)
		return
	}
	rows, err := h.store.ListForCluster(r.Context(), tok.OrgID, clusterID, "")
	if err != nil {
		writeDLPError(w, err)
		return
	}
	// NET-45: merge master-authored (federated) DLP/WAF rules read-only. On a joint
	// these were replicated from its master into fed_runtime_profiles and apply
	// fleet-wide across every cluster; on a master/standalone the table is empty so
	// this is a no-op. A load error must not deny the (authoritative) local bundle.
	if fedPayloads, ferr := fetchFedRuntimeProfilePayloads(r.Context(), h.store.db.Pool(), tok.OrgID, handler.FedKindRuntimeDLP); ferr != nil {
		slog.Default().Warn("dlp bundle: load fed rules failed",
			slog.String("org", tok.OrgID.String()), slog.String("err", ferr.Error()))
	} else {
		rows = appendFedDLPRows(rows, fedPayloads)
	}
	// NET-43: also deliver the org's group→sensor bindings and each bound group's
	// SELECTOR so the agent can scope the DLP/WAF push to a bound group's member
	// pods. The agent matches its LOCAL pods (namespace + labels) against these
	// selectors — deployments carry no MAC server-side, so resolution has to
	// happen where a MAC's pod labels are known (the agent). Best-effort: a load
	// error must not deny the (authoritative) rule bundle, so we log-and-continue
	// with empty binding metadata rather than 500 the whole poll.
	bindingStore := NewGroupSensorBindingStore(h.store.db)
	bindings, berr := bindingStore.ListForOrg(r.Context(), tok.OrgID)
	if berr != nil {
		slog.Default().Warn("dlp bundle: load group bindings failed",
			slog.String("org", tok.OrgID.String()), slog.String("err", berr.Error()))
		bindings = nil
	}
	groupDefs, gerr := bindingStore.BoundGroupDefs(r.Context(), tok.OrgID)
	if gerr != nil {
		slog.Default().Warn("dlp bundle: load bound group defs failed",
			slog.String("org", tok.OrgID.String()), slog.String("err", gerr.Error()))
		groupDefs = nil
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"rules":              rows,
		"dpi_group_bindings": bindings,
		"dpi_groups":         groupDefs,
	})
}

func (h *RuntimeDLPHTTP) Get(w http.ResponseWriter, r *http.Request) {
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
	got, err := h.store.Get(r.Context(), sub.OrgID, id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		writeDLPError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, got)
}

// CreateDLPRequest is the POST body. Category and ApplyDir are optional —
// defaults differ for the dlp vs signature endpoints (handler stamps
// Category before calling Insert).
type CreateDLPRequest struct {
	ClusterID   uuid.UUID       `json:"cluster_id"`
	Name        string          `json:"name"`
	Category    DLPCategory     `json:"category,omitempty"`
	ApplyDir    int16           `json:"apply_dir,omitempty"`
	Severity    int16           `json:"severity"`
	Mode        DLPMode         `json:"mode,omitempty"`
	Patterns    json.RawMessage `json:"patterns"`
	ScopeMACs   []string        `json:"scope_macs,omitempty"` // P1-5: empty ⇒ all workloads
	Description string          `json:"description,omitempty"`
}

func (h *RuntimeDLPHTTP) Create(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req CreateDLPRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = DLPModeMonitor
	}
	if mode != DLPModeMonitor && mode != DLPModeDisabled {
		jsonError(w, http.StatusBadRequest, "new DLP rules must start in monitor or disabled mode; promote separately")
		return
	}
	rule := &DLPRule{
		OrgID: sub.OrgID, ClusterID: req.ClusterID,
		Name: req.Name, Category: req.Category, ApplyDir: req.ApplyDir,
		Severity: req.Severity, Mode: mode,
		Patterns: req.Patterns, ScopeMACs: req.ScopeMACs, Description: req.Description,
		CreatedBy: &sub.UserID,
	}
	got, err := h.store.insertDLPRule(r.Context(), rule, requestIDFrom(r))
	if err != nil {
		writeDLPError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, got)
}

// UpdateDLPRequest is the PUT body — patterns/severity/description.
type UpdateDLPRequest struct {
	Patterns    *json.RawMessage `json:"patterns,omitempty"`
	Severity    int16            `json:"severity,omitempty"`
	Description string           `json:"description,omitempty"`
	// ScopeMACs is a pointer so the caller can clear the scope (send []) vs
	// leave it unchanged (omit). P1-5.
	ScopeMACs *[]string `json:"scope_macs,omitempty"`
}

func (h *RuntimeDLPHTTP) Update(w http.ResponseWriter, r *http.Request) {
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
	var req UpdateDLPRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	got, err := h.store.updateDLPRule(r.Context(), sub.OrgID, id, req, sub.UserID, requestIDFrom(r), h.categories)
	if err != nil {
		writeDLPError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, got)
}

func (h *RuntimeDLPHTTP) Promote(w http.ResponseWriter, r *http.Request) {
	h.modeChange(w, r, DLPModeEnforce)
}
func (h *RuntimeDLPHTTP) Demote(w http.ResponseWriter, r *http.Request) {
	h.modeChange(w, r, DLPModeMonitor)
}
func (h *RuntimeDLPHTTP) Disable(w http.ResponseWriter, r *http.Request) {
	h.modeChange(w, r, DLPModeDisabled)
}

func (h *RuntimeDLPHTTP) modeChange(w http.ResponseWriter, r *http.Request, target DLPMode) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		jsonError(w, http.StatusBadRequest, "missing id")
		return
	}
	id, err := uuid.Parse(parts[len(parts)-2])
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	got, err := h.store.setDLPMode(r.Context(), sub.OrgID, id, target, sub.UserID, requestIDFrom(r), h.categories)
	if err != nil {
		writeDLPError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, got)
}

func (h *RuntimeDLPHTTP) Delete(w http.ResponseWriter, r *http.Request) {
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
	if err := h.store.deleteDLPRule(r.Context(), sub.OrgID, id, &sub.UserID, requestIDFrom(r), h.categories); err != nil {
		writeDLPError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// RuntimePolicyStore_DLP exists only to satisfy a chained signature in case
// callers want a typed alias. Not used by router wiring.
type RuntimePolicyStore_DLP struct{ inner *RuntimeDLPStore }
