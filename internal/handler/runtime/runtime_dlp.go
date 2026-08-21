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
	"errors"
	"fmt"
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
	Version     int64      `json:"version"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// DecodePatterns reads the JSONB patterns column as a string slice.
func (r *DLPRule) DecodePatterns() ([]string, error) {
	if len(r.Patterns) == 0 || string(r.Patterns) == "null" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(r.Patterns, &out); err != nil {
		return nil, fmt.Errorf("decode patterns: %w", err)
	}
	return out, nil
}

// RuntimeDLPStore is the persistence layer.
type RuntimeDLPStore struct {
	db       *db.DB
	auditLog *audit.Logger

	// seeded remembers which clusters we've already seeded built-ins for this
	// process, so the lazy seed in AgentBundle runs one INSERT batch per
	// cluster per lifetime instead of on every 60s agent poll. The DB's
	// ON CONFLICT DO NOTHING is the durable guarantee; this is just a cache.
	seeded sync.Map // clusterID(uuid.UUID) → struct{}
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
  created_by, created_at, updated_by, updated_at`

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
	if !r.Mode.Valid() {
		return uuid.Nil, fmt.Errorf("invalid mode %q", r.Mode)
	}
	if r.Name == "" {
		return uuid.Nil, errors.New("name is required")
	}
	if r.Severity < 1 || r.Severity > 9 {
		return uuid.Nil, errors.New("severity must be 1..9")
	}
	if r.Category == "" {
		r.Category = CategoryDLP
	}
	if !r.Category.Valid() {
		return uuid.Nil, fmt.Errorf("invalid category %q", r.Category)
	}
	if r.ApplyDir == 0 {
		// Default differs per category: DLP is egress-only (catches data
		// exfil); custom signatures match bidirectionally (could be an
		// inbound attack or outbound C2).
		switch r.Category {
		case CategorySignature:
			r.ApplyDir = 3 // both
		case CategoryWAF:
			r.ApplyDir = 2 // ingress: WAF blocks inbound web attacks
		default:
			r.ApplyDir = 1 // egress
		}
	}
	if r.ApplyDir < 1 || r.ApplyDir > 3 {
		return uuid.Nil, errors.New("apply_dir must be 1 (egress), 2 (ingress), or 3 (both)")
	}
	if len(r.Patterns) > 0 && !json.Valid(r.Patterns) {
		return uuid.Nil, errors.New("patterns is not valid JSON")
	}
	// Authoring-time validation (P1-03): reject rules dp would silently drop —
	// >=1 pattern, count/length caps, no wildcard-only, and every pattern must
	// compile. Without this a typo'd regex returns 201, shows "enforce", and
	// never fires (fail-open). Mirrors NeuVector's validateDlpRuleConfig.
	pats, err := r.DecodePatterns()
	if err != nil {
		return uuid.Nil, errors.New("patterns is not valid JSON")
	}
	if err := dlp.ValidatePatterns(pats); err != nil {
		return uuid.Nil, err
	}
	scopeArg := scopeMACsJSON(r.ScopeMACs)
	var id uuid.UUID
	var dpRuleID int64
	err = s.db.Pool().QueryRow(ctx, `
INSERT INTO runtime_dlp_rules
  (org_id, cluster_id, name, category, apply_dir, severity, mode, patterns,
   scope_macs, description, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$11)
RETURNING id, dp_rule_id`,
		r.OrgID, r.ClusterID, r.Name, string(r.Category), r.ApplyDir, r.Severity,
		string(r.Mode), string(r.Patterns), scopeArg, r.Description, r.CreatedBy).Scan(&id, &dpRuleID)
	if err != nil {
		return uuid.Nil, err
	}
	r.ID = id
	r.DPRuleID = dpRuleID
	r.Version = 1
	if s.auditLog != nil {
		_ = s.auditLog.LogPolicyCreate(ctx, r.OrgID, r.CreatedBy, snapshotDLP(r), requestID)
	}
	return id, nil
}

// ensureBuiltinsOnce seeds built-ins for a cluster at most once per process,
// swallowing errors (logged) so a seed hiccup never blocks the agent bundle.
func (s *RuntimeDLPStore) ensureBuiltinsOnce(ctx context.Context, orgID, clusterID uuid.UUID) {
	if _, done := s.seeded.Load(clusterID); done {
		return
	}
	n, err := s.EnsureBuiltins(ctx, orgID, clusterID)
	if err != nil {
		// Don't cache a failure — retry on the next poll.
		slog.Default().Warn("dlp: seed built-ins failed",
			slog.String("cluster", clusterID.String()), slog.String("err", err.Error()))
		return
	}
	s.seeded.Store(clusterID, struct{}{})
	if n > 0 {
		slog.Default().Info("dlp: seeded built-in rules",
			slog.String("cluster", clusterID.String()), slog.Int("inserted", n))
	}
}

// Get fetches one rule, scoped to the org.
func (s *RuntimeDLPStore) Get(ctx context.Context, orgID, id uuid.UUID) (*DLPRule, error) {
	row := s.db.Pool().QueryRow(ctx, `SELECT `+dlpSelectCols+
		` FROM runtime_dlp_rules WHERE id = $1 AND org_id = $2`, id, orgID)
	return scanDLP(row)
}

// ListForCluster returns every non-disabled rule for the cluster, sorted
// by name. The agent uses this to know what to push to dp. category="" (or
// "all") returns both DLP and signature rules — the agent pushes them as
// one batch since dp's engine doesn't distinguish.
func (s *RuntimeDLPStore) ListForCluster(ctx context.Context, orgID, clusterID uuid.UUID, category DLPCategory) ([]*DLPRule, error) {
	rows, err := s.db.Pool().Query(ctx, `SELECT `+dlpSelectCols+
		` FROM runtime_dlp_rules
 WHERE org_id = $1 AND cluster_id = $2 AND mode <> 'disabled'
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
	// Empty patterns means "leave unchanged" (the SQL COALESCEs it away). When a
	// new set IS supplied, validate it the same way Insert does (P1-03) so an
	// edit can't slip an unparseable / over-cap / wildcard-only rule past the
	// authoring gate and into a silently-dropped dp sig.
	if len(patterns) > 0 {
		if !json.Valid(patterns) {
			return nil, errors.New("patterns is not valid JSON")
		}
		var pats []string
		if err := json.Unmarshal(patterns, &pats); err != nil {
			return nil, errors.New("patterns is not valid JSON")
		}
		if err := dlp.ValidatePatterns(pats); err != nil {
			return nil, err
		}
	}
	before, err := s.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	// scope is a pointer so callers can distinguish "leave unchanged" (nil)
	// from "set/clear scope" (non-nil, possibly empty → NULL = all workloads).
	setScope := scope != nil
	var scopeArg any
	if setScope {
		scopeArg = scopeMACsJSON(*scope)
	}
	_, err = s.db.Pool().Exec(ctx, `
UPDATE runtime_dlp_rules
   SET patterns = COALESCE(NULLIF($1::text,'')::jsonb, patterns),
       severity = COALESCE(NULLIF($2,0::smallint), severity),
       description = COALESCE(NULLIF($3,''), description),
       scope_macs = CASE WHEN $7 THEN $8::jsonb ELSE scope_macs END,
       updated_by = $4
 WHERE id = $5 AND org_id = $6`,
		string(patterns), severity, description, by, id, orgID, setScope, scopeArg)
	if err != nil {
		return nil, err
	}
	after, err := s.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if s.auditLog != nil {
		_ = s.auditLog.LogPolicyEvent(ctx, orgID, &by, audit.ActionPolicyUpdate,
			ptrSnapDLP(before), ptrSnapDLP(after), requestID)
	}
	return after, nil
}

func ptrSnapDLP(r *DLPRule) *audit.PolicySnapshot {
	if r == nil {
		return nil
	}
	s := snapshotDLP(r)
	return &s
}

// SetMode flips a rule's mode. Same {promote, demote, disable, update}
// audit-action selector as runtime_policies; system=false because DLP
// rules don't have auto-rollback today (no analogue of the deny-rate
// signal — DLP fires-on-payload, not fires-on-rate).
func (s *RuntimeDLPStore) SetMode(ctx context.Context, orgID, id uuid.UUID,
	mode DLPMode, by uuid.UUID, requestID string) error {
	if !mode.Valid() {
		return fmt.Errorf("invalid mode %q", mode)
	}
	before, err := s.Get(ctx, orgID, id)
	if err != nil {
		return err
	}
	tag, err := s.db.Pool().Exec(ctx,
		`UPDATE runtime_dlp_rules SET mode=$1, updated_by=$2 WHERE id=$3 AND org_id=$4`,
		string(mode), by, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("not found")
	}
	if s.auditLog != nil {
		after, err := s.Get(ctx, orgID, id)
		if err == nil {
			_ = s.auditLog.LogPolicyModeChange(ctx, orgID, &by,
				snapshotDLP(before), snapshotDLP(after), false /*system*/, requestID)
		}
	}
	return nil
}

// Delete removes a rule.
func (s *RuntimeDLPStore) Delete(ctx context.Context, orgID, id uuid.UUID, by *uuid.UUID, requestID string) error {
	before, err := s.Get(ctx, orgID, id)
	if err != nil {
		return err
	}
	tag, err := s.db.Pool().Exec(ctx,
		`DELETE FROM runtime_dlp_rules WHERE id=$1 AND org_id=$2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("not found")
	}
	if s.auditLog != nil {
		_ = s.auditLog.LogPolicyDelete(ctx, orgID, by, snapshotDLP(before), requestID)
	}
	return nil
}

// ---------------- HTTP handlers ----------------

// RuntimeDLPHTTP wraps the store with HTTP handlers.
type RuntimeDLPHTTP struct {
	store *RuntimeDLPStore
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
		jsonError(w, http.StatusInternalServerError, err.Error())
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
	// P1-4: lazily seed the built-in DLP + WAF packs (MONITOR mode) the first
	// time an agent syncs a cluster. Idempotent; failure is non-fatal — we
	// still serve whatever rules exist. This is the "seed on provision"
	// contract realised at the natural provision signal (first agent sync),
	// which also covers clusters that predate this code.
	h.store.ensureBuiltinsOnce(r.Context(), tok.OrgID, clusterID)
	rows, err := h.store.ListForCluster(r.Context(), tok.OrgID, clusterID, "")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rules": rows})
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
		jsonError(w, http.StatusInternalServerError, err.Error())
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
	mode := DLPModeMonitor
	switch req.Mode {
	case DLPModeMonitor, DLPModeDisabled, "":
		if req.Mode != "" {
			mode = req.Mode
		}
	default:
		jsonError(w, http.StatusBadRequest,
			"new DLP rules must start in monitor or disabled mode; promote separately")
		return
	}
	rule := &DLPRule{
		OrgID: sub.OrgID, ClusterID: req.ClusterID,
		Name: req.Name, Category: req.Category, ApplyDir: req.ApplyDir,
		Severity: req.Severity, Mode: mode,
		Patterns: req.Patterns, ScopeMACs: req.ScopeMACs, Description: req.Description,
		CreatedBy: &sub.UserID,
	}
	id, err := h.store.Insert(r.Context(), rule, requestIDFrom(r))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			jsonError(w, http.StatusConflict, "DLP rule with this name already exists")
			return
		}
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	got, _ := h.store.Get(r.Context(), sub.OrgID, id)
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
	patterns := json.RawMessage("")
	if req.Patterns != nil {
		patterns = *req.Patterns
	}
	got, err := h.store.Update(r.Context(), sub.OrgID, id, patterns, req.Severity, req.Description, req.ScopeMACs, sub.UserID, requestIDFrom(r))
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
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
	if err := h.store.SetMode(r.Context(), sub.OrgID, id, target, sub.UserID, requestIDFrom(r)); err != nil {
		if strings.Contains(err.Error(), "not found") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, _ := h.store.Get(r.Context(), sub.OrgID, id)
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
	if err := h.store.Delete(r.Context(), sub.OrgID, id, &sub.UserID, requestIDFrom(r)); err != nil {
		if strings.Contains(err.Error(), "not found") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = slog.Default()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// RuntimePolicyStore_DLP exists only to satisfy a chained signature in case
// callers want a typed alias. Not used by router wiring.
type RuntimePolicyStore_DLP struct{ inner *RuntimeDLPStore }
