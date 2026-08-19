// Wave B1: HTTP handlers for runtime_policies CRUD.
//
//	GET    /api/v1/runtime-policies              list (read-findings)
//	GET    /api/v1/runtime-policies/{id}         get one (read-findings)
//	POST   /api/v1/runtime-policies              create (manage-policies)
//	PUT    /api/v1/runtime-policies/{id}         update mode + rules (manage-policies)
//	POST   /api/v1/runtime-policies/{id}/promote → enforce (manage-policies)
//	POST   /api/v1/runtime-policies/{id}/demote  → monitor (manage-policies)
//	DELETE /api/v1/runtime-policies/{id}         delete (manage-policies)
//
// Promote/demote are dedicated endpoints (vs PUT with a mode body) so the
// UI's confirmation dialog can hit a distinct route — easier to add a
// per-route "this is a hot operation, double-confirm" affordance.
package runtime

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// RuntimePoliciesHTTP wraps the store with HTTP handlers. Constructed once
// per server; route registration lives in server.go.
type RuntimePoliciesHTTP struct {
	store *RuntimePolicyStore
}

func NewRuntimePoliciesHTTP(d *db.DB, auditLog *audit.Logger) *RuntimePoliciesHTTP {
	return &RuntimePoliciesHTTP{store: NewRuntimePolicyStore(d, auditLog)}
}

// CreatePolicyRequest is the POST body. Cluster scoping comes from the URL
// param or the body; we accept either to keep the UI flexible.
type CreatePolicyRequest struct {
	ClusterID uuid.UUID       `json:"cluster_id"`
	Workload  string          `json:"workload"`
	Namespace string          `json:"namespace"`
	Name      string          `json:"name"`
	Mode      PolicyMode      `json:"mode,omitempty"` // defaults to monitor
	DefAction *uint8          `json:"def_action,omitempty"`
	ApplyDir  *int            `json:"apply_dir,omitempty"`
	Rules     json.RawMessage `json:"rules,omitempty"`
}

// UpdatePolicyRequest is the PUT body. Only the fields present in the
// payload are updated; the rest stay unchanged. Mode changes go through
// the dedicated promote / demote routes — not here.
type UpdatePolicyRequest struct {
	Rules     *json.RawMessage `json:"rules,omitempty"`
	DefAction *uint8           `json:"def_action,omitempty"`
	ApplyDir  *int             `json:"apply_dir,omitempty"`
	Name      *string          `json:"name,omitempty"`
}

// List handles GET /api/v1/runtime-policies?cluster_id=...&namespace=...
func (h *RuntimePoliciesHTTP) List(w http.ResponseWriter, r *http.Request) {
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
	rows, err := h.store.ListForCluster(r.Context(), sub.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"policies": rows})
}

// Get handles GET /api/v1/runtime-policies/{id}.
func (h *RuntimePoliciesHTTP) Get(w http.ResponseWriter, r *http.Request) {
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
	p, err := h.store.Get(r.Context(), sub.OrgID, id)
	if err != nil {
		// pgx errors fall through with the noisier "no rows" string check;
		// rather than depend on the driver here, treat NOT FOUND as 404.
		if strings.Contains(err.Error(), "no rows") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

// Create handles POST /api/v1/runtime-policies.
//
// Safety: ignores any mode value other than "monitor" or "disabled" on
// create. Operators MUST go through the explicit promote endpoint to enter
// enforce mode — that's the "monitor-only by default" guarantee in code form.
func (h *RuntimePoliciesHTTP) Create(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req CreatePolicyRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.ClusterID == uuid.Nil || req.Workload == "" || req.Namespace == "" || req.Name == "" {
		jsonError(w, http.StatusBadRequest, "cluster_id, workload, namespace, name are required")
		return
	}
	mode := PolicyModeMonitor
	switch req.Mode {
	case PolicyModeMonitor, PolicyModeDisabled, "":
		// monitor (default) or disabled — both safe on create
		if req.Mode != "" {
			mode = req.Mode
		}
	default:
		// enforce on create is refused per the Wave A safety contract;
		// caller must POST /promote after the row exists.
		jsonError(w, http.StatusBadRequest,
			"new policies must start in monitor or disabled mode; promote separately")
		return
	}
	def := uint8(2) // PolicyActionAllow
	if req.DefAction != nil {
		def = *req.DefAction
	}
	dir := 3 // ApplyDirBoth
	if req.ApplyDir != nil {
		dir = *req.ApplyDir
	}
	p := &RuntimePolicy{
		OrgID: sub.OrgID, ClusterID: req.ClusterID,
		Workload: req.Workload, Namespace: req.Namespace, Name: req.Name,
		Mode: mode, DefAction: def, ApplyDir: dir,
		Rules:     req.Rules,
		CreatedBy: &sub.UserID,
	}
	id, err := h.store.Insert(r.Context(), p, requestIDFrom(r))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			jsonError(w, http.StatusConflict, "policy with this name already exists for this workload")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, _ := h.store.Get(r.Context(), sub.OrgID, id)
	httpx.WriteJSON(w, http.StatusCreated, got)
}

// Update handles PUT /api/v1/runtime-policies/{id} — rules + side fields.
// Mode is intentionally NOT updatable here; use /promote or /demote.
func (h *RuntimePoliciesHTTP) Update(w http.ResponseWriter, r *http.Request) {
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
	var req UpdatePolicyRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	// Build a SET clause dynamically. Empty body → no-op (we still return
	// the current row so the UI can refresh).
	current, err := h.store.Get(r.Context(), sub.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if req.Rules != nil {
		if !json.Valid(*req.Rules) {
			jsonError(w, http.StatusBadRequest, "rules is not valid JSON")
			return
		}
		current.Rules = *req.Rules
	}
	if req.DefAction != nil {
		current.DefAction = *req.DefAction
	}
	if req.ApplyDir != nil {
		current.ApplyDir = *req.ApplyDir
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	_, err = h.store.db.Pool().Exec(r.Context(), `
UPDATE runtime_policies
   SET rules = $1::jsonb, def_action = $2, apply_dir = $3, name = $4, updated_by = $5
 WHERE id = $6 AND org_id = $7`,
		string(current.Rules), int16(current.DefAction), int16(current.ApplyDir),
		current.Name, sub.UserID, id, sub.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, _ := h.store.Get(r.Context(), sub.OrgID, id)
	// Audit the update with the trimmed snapshot diff. The bump-version
	// trigger already incremented version + updated_at.
	if h.store.auditLog != nil {
		_ = h.store.auditLog.LogPolicyEvent(r.Context(), sub.OrgID, &sub.UserID,
			audit.ActionPolicyUpdate, ptrSnap(current), ptrSnap(got), requestIDFrom(r))
	}
	httpx.WriteJSON(w, http.StatusOK, got)
}

// ptrSnap is a small helper since LogPolicyEvent takes *PolicySnapshot.
func ptrSnap(p *RuntimePolicy) *audit.PolicySnapshot {
	if p == nil {
		return nil
	}
	s := snapshot(p)
	return &s
}

// Promote handles POST /api/v1/runtime-policies/{id}/promote — monitor → enforce.
// The auto-rollback watcher kicks in once the policy's deny rate spikes; see
// runtime_policies_rollback.go.
func (h *RuntimePoliciesHTTP) Promote(w http.ResponseWriter, r *http.Request) {
	h.modeChange(w, r, PolicyModeEnforce)
}

// Demote handles POST /api/v1/runtime-policies/{id}/demote — anything → monitor.
func (h *RuntimePoliciesHTTP) Demote(w http.ResponseWriter, r *http.Request) {
	h.modeChange(w, r, PolicyModeMonitor)
}

// Disable handles POST /api/v1/runtime-policies/{id}/disable — anything → disabled.
// Useful for emergency turn-off without losing the rule definitions.
func (h *RuntimePoliciesHTTP) Disable(w http.ResponseWriter, r *http.Request) {
	h.modeChange(w, r, PolicyModeDisabled)
}

func (h *RuntimePoliciesHTTP) modeChange(w http.ResponseWriter, r *http.Request, target PolicyMode) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	// URL shape: /runtime-policies/{id}/promote — pick the id segment.
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
	if err := h.store.SetMode(r.Context(), sub.OrgID, id, target,
		sub.UserID, false /*operator-initiated*/, requestIDFrom(r)); err != nil {
		if errors.Is(err, errors.New("not found")) || strings.Contains(err.Error(), "not found") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, _ := h.store.Get(r.Context(), sub.OrgID, id)
	httpx.WriteJSON(w, http.StatusOK, got)
}

// Delete handles DELETE /api/v1/runtime-policies/{id}.
func (h *RuntimePoliciesHTTP) Delete(w http.ResponseWriter, r *http.Request) {
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
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// requestIDFrom — small helper so audit row gets the request_id if one's
// in the standard header. Many other handlers do this inline; the existing
// `RequestID` value on context isn't used by audit.Logger, so we read off
// the header directly. Empty when absent.
func requestIDFrom(r *http.Request) string {
	return r.Header.Get("X-Request-Id")
}
