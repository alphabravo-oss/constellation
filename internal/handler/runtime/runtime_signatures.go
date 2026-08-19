// Wave D4: signatures-flavored facade over RuntimeDLPHTTP.
//
// Same backing store (runtime_dlp_rules), same wire RPC to dp, distinct
// HTTP surface so the UI can present "DPI Signatures" as its own concept
// without merging the two into one page.
//
//	GET    /api/v1/runtime-signatures               list (category='signature')
//	GET    /api/v1/runtime-signatures/{id}          get one
//	POST   /api/v1/runtime-signatures               create — stamps Category='signature'
//	PUT    /api/v1/runtime-signatures/{id}          update
//	POST   /api/v1/runtime-signatures/{id}/promote  → enforce
//	POST   /api/v1/runtime-signatures/{id}/demote   → monitor
//	POST   /api/v1/runtime-signatures/{id}/disable  → disabled
//	DELETE /api/v1/runtime-signatures/{id}          delete
//
// The shared store applies the right defaults: when Category='signature'
// and ApplyDir=0, the row defaults to ApplyDir=3 (both ingress + egress).
// DLP rules default to egress-only.
//
// Why this shape rather than a parallel table:
//   - dp's hyperscan engine matches every rule against every payload it
//     scans, regardless of our taxonomy. Two tables would duplicate the
//     sequence + audit + sync plumbing for zero real-world distinction.
//   - The category column is the only data difference; everything else
//     is UX framing.
package runtime

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// RuntimeSignaturesHTTP is the signatures-flavored handler. It wraps the
// shared RuntimeDLPStore + auto-stamps category='signature' on every
// mutation so the UI can pretend each is its own little table.
type RuntimeSignaturesHTTP struct {
	store *RuntimeDLPStore
}

// NewRuntimeSignaturesHTTP — shares the store with RuntimeDLPHTTP if the
// caller passes the same db + auditLog. No state collision; they're CRUD
// surfaces over the same rows.
func NewRuntimeSignaturesHTTP(d *db.DB, auditLog *audit.Logger) *RuntimeSignaturesHTTP {
	return &RuntimeSignaturesHTTP{store: NewRuntimeDLPStore(d, auditLog)}
}

// List returns only signature-category rows.
func (h *RuntimeSignaturesHTTP) List(w http.ResponseWriter, r *http.Request) {
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
	rows, err := h.store.ListForCluster(r.Context(), sub.OrgID, clusterID, CategorySignature)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"signatures": rows})
}

// Get fetches one — same as DLP's Get but returns 404 if the row exists
// but its category is dlp (this surface only serves signature rows).
func (h *RuntimeSignaturesHTTP) Get(w http.ResponseWriter, r *http.Request) {
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
	if got.Category != CategorySignature {
		// The row exists but it's a DLP rule, not a signature — surface
		// as 404 from this endpoint so the UI doesn't get confused.
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, got)
}

// Create stamps Category='signature' before delegating to the shared store.
func (h *RuntimeSignaturesHTTP) Create(w http.ResponseWriter, r *http.Request) {
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
	// Force the category even if the caller passed something else.
	req.Category = CategorySignature
	mode := DLPModeMonitor
	switch req.Mode {
	case DLPModeMonitor, DLPModeDisabled, "":
		if req.Mode != "" {
			mode = req.Mode
		}
	default:
		jsonError(w, http.StatusBadRequest,
			"new signatures must start in monitor or disabled mode; promote separately")
		return
	}
	rule := &DLPRule{
		OrgID: sub.OrgID, ClusterID: req.ClusterID,
		Name: req.Name, Category: CategorySignature, ApplyDir: req.ApplyDir,
		Severity: req.Severity, Mode: mode,
		Patterns: req.Patterns, ScopeMACs: req.ScopeMACs, Description: req.Description,
		CreatedBy: &sub.UserID,
	}
	id, err := h.store.Insert(r.Context(), rule, requestIDFrom(r))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			jsonError(w, http.StatusConflict, "signature with this name already exists")
			return
		}
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	got, _ := h.store.Get(r.Context(), sub.OrgID, id)
	httpx.WriteJSON(w, http.StatusCreated, got)
}

// Update / Promote / Demote / Disable / Delete delegate straight to the
// DLP handlers' identical implementations — we built one HTTP layer that
// services both categories, gated by a 404 if the caller hits the wrong
// surface for the row's actual category.

func (h *RuntimeSignaturesHTTP) Update(w http.ResponseWriter, r *http.Request) {
	if !h.requireSignatureRow(w, r) {
		return
	}
	(&RuntimeDLPHTTP{store: h.store}).Update(w, r)
}
func (h *RuntimeSignaturesHTTP) Promote(w http.ResponseWriter, r *http.Request) {
	if !h.requireSignatureRow(w, r) {
		return
	}
	(&RuntimeDLPHTTP{store: h.store}).Promote(w, r)
}
func (h *RuntimeSignaturesHTTP) Demote(w http.ResponseWriter, r *http.Request) {
	if !h.requireSignatureRow(w, r) {
		return
	}
	(&RuntimeDLPHTTP{store: h.store}).Demote(w, r)
}
func (h *RuntimeSignaturesHTTP) Disable(w http.ResponseWriter, r *http.Request) {
	if !h.requireSignatureRow(w, r) {
		return
	}
	(&RuntimeDLPHTTP{store: h.store}).Disable(w, r)
}
func (h *RuntimeSignaturesHTTP) Delete(w http.ResponseWriter, r *http.Request) {
	if !h.requireSignatureRow(w, r) {
		return
	}
	(&RuntimeDLPHTTP{store: h.store}).Delete(w, r)
}

// requireSignatureRow checks the row's category before delegating to the
// shared mutator. Without this, a /runtime-signatures/{id}/promote on a
// DLP row would silently promote the DLP rule.
func (h *RuntimeSignaturesHTTP) requireSignatureRow(w http.ResponseWriter, r *http.Request) bool {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return false
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		jsonError(w, http.StatusBadRequest, "invalid path")
		return false
	}
	// id is either the tail or the second-to-last segment (for /promote etc).
	idStr := parts[len(parts)-1]
	if !looksLikeUUID(idStr) && len(parts) >= 2 {
		idStr = parts[len(parts)-2]
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return false
	}
	got, err := h.store.Get(r.Context(), sub.OrgID, id)
	if err != nil || got == nil || got.Category != CategorySignature {
		jsonError(w, http.StatusNotFound, "not found")
		return false
	}
	return true
}

// looksLikeUUID is a cheap heuristic — 36 chars with dashes at the right
// positions. Doesn't fully validate; uuid.Parse does that after.
func looksLikeUUID(s string) bool {
	return len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}
