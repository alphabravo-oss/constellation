// Wave D4: signatures-flavored facade over RuntimeDLPHTTP.
//
// Same backing store (runtime_dlp_rules), same wire RPC to dp, distinct
// HTTP surface so the UI can present "DPI Signatures" as its own concept
// without merging the two into one page.
//
//	GET    /api/v1/runtime-signatures               list (category='signature')
//	GET    /api/v1/runtime-signatures:export        YAML bundle export
//	POST   /api/v1/runtime-signatures:import        YAML bundle import
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
	"sort"
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

// List returns custom DPI signatures plus imported WAF-category rows. The UI
// presents this surface as "WAF / DPI Signatures"; Constellation-authored rows
// are category=signature and NeuVector WAF imports are category=waf.
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
		writeDLPError(w, err)
		return
	}
	wafRows, err := h.store.ListForCluster(r.Context(), sub.OrgID, clusterID, CategoryWAF)
	if err != nil {
		writeDLPError(w, err)
		return
	}
	rows = append(rows, wafRows...)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].Name < rows[j].Name
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"signatures": rows})
}

// Get fetches one — same as DLP's Get but returns 404 if the row exists
// but its category is plain dlp (this surface serves signature + waf rows).
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
		writeDLPError(w, err)
		return
	}
	if got.Category != CategorySignature && got.Category != CategoryWAF {
		// The row exists but it's a DLP rule, not a signature/WAF rule — surface
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
	mode := req.Mode
	if mode == "" {
		mode = DLPModeMonitor
	}
	if mode != DLPModeMonitor && mode != DLPModeDisabled {
		jsonError(w, http.StatusBadRequest, "new signatures must start in monitor or disabled mode; promote separately")
		return
	}
	rule := &DLPRule{
		OrgID: sub.OrgID, ClusterID: req.ClusterID,
		Name: req.Name, Category: CategorySignature, ApplyDir: req.ApplyDir,
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

// Category authorization runs against the locked row in the mutation transaction.
func (h *RuntimeSignaturesHTTP) mutationHTTP() *RuntimeDLPHTTP {
	return &RuntimeDLPHTTP{store: h.store, categories: []DLPCategory{CategorySignature, CategoryWAF}}
}
func (h *RuntimeSignaturesHTTP) Update(w http.ResponseWriter, r *http.Request) {
	h.mutationHTTP().Update(w, r)
}
func (h *RuntimeSignaturesHTTP) Promote(w http.ResponseWriter, r *http.Request) {
	h.mutationHTTP().Promote(w, r)
}
func (h *RuntimeSignaturesHTTP) Demote(w http.ResponseWriter, r *http.Request) {
	h.mutationHTTP().Demote(w, r)
}
func (h *RuntimeSignaturesHTTP) Disable(w http.ResponseWriter, r *http.Request) {
	h.mutationHTTP().Disable(w, r)
}
func (h *RuntimeSignaturesHTTP) Delete(w http.ResponseWriter, r *http.Request) {
	h.mutationHTTP().Delete(w, r)
}
