// VEX (Vulnerability-Exploitability eXchange) endpoints.
//
//	GET /api/v1/vex/openvex/{asset_id}     — OpenVEX 0.2.0 JSON
//	GET /api/v1/vex/cyclonedx/{asset_id}   — CycloneDX 1.6 VEX JSON
//
// A VEX document restates the asset's vulnerability findings as machine-readable
// exploitability statements (under_investigation / fixed / not_affected / affected),
// derived from each finding's lifecycle by pkg/vex. Downstream consumers use it to
// suppress noise the producer has already triaged. Documents are built on the fly from the
// latest findings — there is no separate VEX store.
//
// SCAN-VEX-37: pkg/vex previously had zero importers; this handler is its first consumer,
// so the advertised VEX coverage is now actually reachable over the API.
//
// Route wiring (add under the authed /api/v1 group in internal/server/server.go, e.g.
// alongside the /sbom/... routes):
//
//	vex := handler.NewVEX(s.db)
//	r.Get("/vex/openvex/{asset_id}", s.requireVerb(rbac.VerbReadFindings, vex.OpenVEX))
//	r.Get("/vex/cyclonedx/{asset_id}", s.requireVerb(rbac.VerbReadFindings, vex.CycloneDX))
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/vex"
)

// VEX serves per-asset VEX documents built from the asset's vulnerability findings.
type VEX struct {
	db *db.DB
}

// NewVEX constructs the handler.
func NewVEX(d *db.DB) *VEX { return &VEX{db: d} }

// OpenVEX serves the OpenVEX 0.2.0 document for an asset.
func (h *VEX) OpenVEX(w http.ResponseWriter, r *http.Request) {
	author, findings, ok := h.buildFindings(w, r)
	if !ok {
		return
	}
	writeVEX(w, vex.OpenVEX(author, findings), "openvex.json")
}

// CycloneDX serves the CycloneDX 1.6 VEX document for an asset.
func (h *VEX) CycloneDX(w http.ResponseWriter, r *http.Request) {
	author, findings, ok := h.buildFindings(w, r)
	if !ok {
		return
	}
	writeVEX(w, vex.CycloneDXVEX(author, findings), "cyclonedx-vex.json")
}

// buildFindings loads the asset (org-scoped) and its vulnerability findings, mapping each to
// a pkg/vex.Finding. Returns the document author, the sorted findings, and ok=false (after
// writing an error response) on any failure.
func (h *VEX) buildFindings(w http.ResponseWriter, r *http.Request) (string, []vex.Finding, bool) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return "", nil, false
	}
	assetID, err := uuid.Parse(chi.URLParam(r, "asset_id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad asset id")
		return "", nil, false
	}
	var assetName string
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT name FROM assets WHERE id = $1 AND org_id = $2`, assetID, subj.OrgID).Scan(&assetName); err != nil {
		jsonError(w, http.StatusNotFound, "asset not found")
		return "", nil, false
	}

	// Vulnerability findings for the asset. The 'workload' pod-scan rows are a duplicate of
	// the canonical 'image-workload' rows (see findings.go / dashboard.go); excluding them
	// keeps one VEX statement per CVE.
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT COALESCE(external_id, ''), lifecycle, COALESCE(description, ''), COALESCE(severity, ''), last_seen_at
  FROM findings
 WHERE org_id = $1
   AND asset_id = $2
   AND kind = 'vulnerability'
   AND COALESCE(external_id, '') <> ''
	   AND COALESCE(target_type, '') <> 'workload'
 ORDER BY external_id`, subj.OrgID, assetID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return "", nil, false
	}
	defer rows.Close()

	findings := []vex.Finding{}
	for rows.Next() {
		var f vex.Finding
		if err := rows.Scan(&f.VulnerabilityID, &f.Lifecycle, &f.Rationale, &f.Severity, &f.UpdatedAt); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return "", nil, false
		}
		f.Product = assetName
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return "", nil, false
	}

	author := subj.Email
	if author == "" {
		author = "Constellation"
	}
	return author, vex.SortByCVE(findings), true
}

func writeVEX(w http.ResponseWriter, doc map[string]interface{}, fname string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	_ = json.NewEncoder(w).Encode(doc)
}
