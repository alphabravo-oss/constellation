// SBOM endpoints.
//
//	GET /api/v1/sbom/spdx/{asset_id}        — SPDX 2.3 JSON
//	GET /api/v1/sbom/cyclonedx/{asset_id}   — CycloneDX 1.6 JSON
//	GET /api/v1/sbom/mbom/{asset_id}        — CycloneDX 1.6 ML-BOM (for ml-model assets)
//
// SBOMs are served from the latest image_scan_artifacts row for the asset's image scan.
// When a known asset has not been scanned yet, the endpoint synthesizes a well-formed
// empty document keyed on the asset name.
package findings

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/sbom"
)

type SBOM struct {
	db *db.DB
}

func NewSBOM(d *db.DB) *SBOM { return &SBOM{db: d} }

// SPDX serves the SPDX 2.3 document for an asset.
func (h *SBOM) SPDX(w http.ResponseWriter, r *http.Request) {
	assetID, orgID, assetName, ok := h.loadAsset(w, r)
	if !ok {
		return
	}
	if h.writeLatestImageScanSBOM(w, r, orgID, assetID, "spdx-2.3", "spdx-2.3.json") {
		return
	}
	res, ok := h.loadScanResultForAsset(w, r, orgID, assetID, assetName)
	if !ok {
		return
	}
	doc := sbom.SPDX2_3("v0.1.0", res)
	writeSBOM(w, doc, "spdx-2.3.json")
}

// CycloneDX serves the CycloneDX 1.6 document for an asset.
func (h *SBOM) CycloneDX(w http.ResponseWriter, r *http.Request) {
	assetID, orgID, assetName, ok := h.loadAsset(w, r)
	if !ok {
		return
	}
	if h.writeLatestImageScanSBOM(w, r, orgID, assetID, "cyclonedx-1.6", "cyclonedx-1.6.json") {
		return
	}
	res, ok := h.loadScanResultForAsset(w, r, orgID, assetID, assetName)
	if !ok {
		return
	}
	doc := sbom.CycloneDX1_6("v0.1.0", res)
	writeSBOM(w, doc, "cyclonedx-1.6.json")
}

// MBOM serves the CycloneDX ML-BOM for ml-model assets. At v1 this is just the CycloneDX
// doc with the component-type set to "machine-learning-model" (the ML-BOM 1.6 extension
// is a strict superset of CycloneDX 1.6 — same JSON shape, narrower type discriminator).
func (h *SBOM) MBOM(w http.ResponseWriter, r *http.Request) {
	res, ok := h.loadScanResult(w, r)
	if !ok {
		return
	}
	doc := sbom.CycloneDX1_6("v0.1.0", res)
	if md, ok := doc["metadata"].(map[string]interface{}); ok {
		if comp, ok := md["component"].(map[string]interface{}); ok {
			comp["type"] = "machine-learning-model"
		}
	}
	writeSBOM(w, doc, "mbom-1.6.json")
}

func (h *SBOM) loadAsset(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, string, bool) {
	assetID, err := uuid.Parse(chi.URLParam(r, "asset_id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad asset id"})
		return uuid.Nil, uuid.Nil, "", false
	}
	subj, _ := authctx.SubjectFrom(r.Context())

	var assetName string
	err = h.db.Pool().QueryRow(r.Context(),
		`SELECT name FROM assets WHERE id = $1 AND org_id = $2`, assetID, subj.OrgID).Scan(&assetName)
	if err != nil {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "asset not found"})
		return uuid.Nil, uuid.Nil, "", false
	}
	return assetID, subj.OrgID, assetName, true
}

func (h *SBOM) writeLatestImageScanSBOM(w http.ResponseWriter, r *http.Request, orgID, assetID uuid.UUID, format, fname string) bool {
	var raw []byte
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT a.payload
  FROM image_scan_results r
  JOIN image_scan_artifacts a
    ON a.org_id = r.org_id
   AND a.image_scan_result_id = r.id
 WHERE r.org_id = $1
   AND r.asset_id = $2
   AND a.artifact_type = 'sbom'
   AND a.format = $3
 ORDER BY r.last_scanned_at DESC, a.created_at DESC
 LIMIT 1`, orgID, assetID, format).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return true
	}
	httpx.WriteRawSBOM(w, raw, fname)
	return true
}

// loadScanResult fetches the persisted scan result for an asset. When no SBOM is on file,
// returns an empty result keyed on the asset name so the SBOM is well-formed but empty.
func (h *SBOM) loadScanResult(w http.ResponseWriter, r *http.Request) (*scanner.ScanResult, bool) {
	assetID, orgID, assetName, ok := h.loadAsset(w, r)
	if !ok {
		return nil, false
	}
	return h.loadScanResultForAsset(w, r, orgID, assetID, assetName)
}

func (h *SBOM) loadScanResultForAsset(w http.ResponseWriter, r *http.Request, orgID, assetID uuid.UUID, assetName string) (*scanner.ScanResult, bool) {
	result := &scanner.ScanResult{ImageRef: assetName}
	var raw []byte
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT r.image_ref, COALESCE(a.payload, '{}'::jsonb)
  FROM image_scan_results r
  LEFT JOIN image_scan_artifacts a
    ON a.org_id = r.org_id
   AND a.image_scan_result_id = r.id
   AND a.artifact_type = 'package-inventory'
   AND a.format = 'constellation-package-inventory-v1'
 WHERE r.org_id = $1
   AND r.asset_id = $2
 ORDER BY r.last_scanned_at DESC
 LIMIT 1`, orgID, assetID).Scan(&result.ImageRef, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, true
	}
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return nil, false
	}
	result.Packages = packagesFromInventory(raw)
	return result, true
}

func packagesFromInventory(raw []byte) []scanner.Package {
	var inventory struct {
		Packages []scanner.Package `json:"packages"`
	}
	_ = json.Unmarshal(raw, &inventory)
	return inventory.Packages
}

func writeSBOM(w http.ResponseWriter, doc map[string]interface{}, fname string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	_ = json.NewEncoder(w).Encode(doc)
}
