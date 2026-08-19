package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
)

// AssetVuln serves the per-asset vulnerability rollup (A5). The rollup is
// materialized in asset_vuln_summary and re-counted without rescanning by
// rolling up the already-stored findings for the asset (generic findings +
// image_scan_findings). Cheap, always reflects the last scan's results.
type AssetVuln struct {
	db *db.DB
}

func NewAssetVuln(d *db.DB) *AssetVuln {
	return &AssetVuln{db: d}
}

type assetVulnSummaryDTO struct {
	AssetID        uuid.UUID      `json:"asset_id"`
	SeverityCounts map[string]int `json:"severity_counts"`
	FindingCount   int            `json:"finding_count"`
	MaxRiskScore   int            `json:"max_risk_score"`
	BundleVersion  string         `json:"bundle_version"`
	Source         string         `json:"source"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// Get handles GET /assets/{id}/vulnerabilities. It recomputes the rollup on the
// requested source, persists it to asset_vuln_summary, and returns it.
func (h *AssetVuln) Get(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	var exists bool
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM assets WHERE id = $1 AND org_id = $2)`, id, subj.OrgID).Scan(&exists); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	summary, err := recountAssetVulnFromFindings(r.Context(), h.db.Pool(), subj.OrgID, id, "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// recountAssetVulnFromFindings rolls up the stored findings for one asset and
// upserts asset_vuln_summary. No scan is performed. Image assets count their
// latest image_scan_findings; everything else counts generic findings.
func recountAssetVulnFromFindings(ctx context.Context, pool *pgxpool.Pool, orgID, assetID uuid.UUID, bundleVersion string) (assetVulnSummaryDTO, error) {
	var c counts
	err := pool.QueryRow(ctx, `
WITH image_results AS (
    SELECT DISTINCT ON (image_digest, platform, scanner_profile) id
      FROM image_scan_results
     WHERE org_id = $1 AND asset_id = $2
     ORDER BY image_digest, platform, scanner_profile, last_scanned_at DESC
),
image_findings AS (
    SELECT f.severity, f.risk_score
      FROM image_results ir
      JOIN image_scan_findings f ON f.image_scan_result_id = ir.id
     WHERE f.org_id = $1
),
generic_findings AS (
    SELECT severity, risk_score
      FROM findings
     WHERE org_id = $1 AND asset_id = $2
       AND lifecycle NOT IN ('resolved', 'suppressed')
),
asset_kind AS (
    SELECT kind FROM assets WHERE id = $2 AND org_id = $1
),
all_findings AS (
    -- Count image_scan_findings for image assets ONLY, generic findings for
    -- everything else. Image findings are mirrored into the generic findings
    -- table (one row per running cluster) by promoteImageFindingsToWorkloads,
    -- so UNION-ing both unconditionally would multiply image-asset CVE counts.
    SELECT * FROM image_findings   WHERE (SELECT kind FROM asset_kind) = 'image'
    UNION ALL
    SELECT * FROM generic_findings WHERE (SELECT kind FROM asset_kind) IS DISTINCT FROM 'image'
)
SELECT
    COUNT(*) FILTER (WHERE severity = 'critical')::int,
    COUNT(*) FILTER (WHERE severity = 'high')::int,
    COUNT(*) FILTER (WHERE severity = 'medium')::int,
    COUNT(*) FILTER (WHERE severity = 'low')::int,
    COUNT(*) FILTER (WHERE severity = 'info')::int,
    COUNT(*)::int,
    COALESCE(MAX(risk_score), 0)::int
  FROM all_findings`, orgID, assetID).Scan(
		&c.critical, &c.high, &c.medium, &c.low, &c.info, &c.total, &c.maxRisk)
	if err != nil {
		return assetVulnSummaryDTO{}, err
	}
	return upsertAssetVulnSummary(ctx, pool, orgID, assetID, c, bundleVersion, "findings")
}

type counts struct {
	critical, high, medium, low, info, total, maxRisk int
}

func upsertAssetVulnSummary(ctx context.Context, pool *pgxpool.Pool, orgID, assetID uuid.UUID, c counts, bundleVersion, source string) (assetVulnSummaryDTO, error) {
	now := time.Now().UTC()
	_, err := pool.Exec(ctx, `
INSERT INTO asset_vuln_summary (
    asset_id, org_id, critical_count, high_count, medium_count, low_count, info_count,
    finding_count, max_risk_score, bundle_version, source, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (asset_id) DO UPDATE SET
    org_id         = EXCLUDED.org_id,
    critical_count = EXCLUDED.critical_count,
    high_count     = EXCLUDED.high_count,
    medium_count   = EXCLUDED.medium_count,
    low_count      = EXCLUDED.low_count,
    info_count     = EXCLUDED.info_count,
    finding_count  = EXCLUDED.finding_count,
    max_risk_score = EXCLUDED.max_risk_score,
    bundle_version = EXCLUDED.bundle_version,
    source         = EXCLUDED.source,
    updated_at     = EXCLUDED.updated_at`,
		assetID, orgID, c.critical, c.high, c.medium, c.low, c.info,
		c.total, c.maxRisk, bundleVersion, source, now)
	if err != nil {
		return assetVulnSummaryDTO{}, err
	}
	return assetVulnSummaryDTO{
		AssetID: assetID,
		SeverityCounts: map[string]int{
			"critical": c.critical,
			"high":     c.high,
			"medium":   c.medium,
			"low":      c.low,
			"info":     c.info,
		},
		FindingCount:  c.total,
		MaxRiskScore:  c.maxRisk,
		BundleVersion: bundleVersion,
		Source:        source,
		UpdatedAt:     now,
	}, nil
}
