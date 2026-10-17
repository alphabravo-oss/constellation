package findings

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

type CVE struct {
	db *db.DB
}

// NewCVE builds the CVE handler. vulndbPath is retained for call-site
// compatibility but no longer used: CVE metadata is served from the cve_records
// table (fed by the KEV+EPSS and NVD importers), not a bbolt bundle.
func NewCVE(database *db.DB, vulndbPath string) *CVE {
	_ = vulndbPath
	return &CVE{db: database}
}

type cveDTO struct {
	CVEID           string          `json:"cve_id"`
	Title           string          `json:"title,omitempty"`
	Description     string          `json:"description,omitempty"`
	CVSSBase        *float64        `json:"cvss_base,omitempty"`
	CVSSVector      *string         `json:"cvss_vector,omitempty"`
	KEVListed       bool            `json:"kev_listed"`
	KEVAdded        *time.Time      `json:"kev_added,omitempty"`
	EPSSProbability *float64        `json:"epss_probability,omitempty"`
	EPSSUpdatedAt   *time.Time      `json:"epss_updated_at,omitempty"`
	Aliases         []string        `json:"aliases"`
	Affected        json.RawMessage `json:"affected"`
	Sources         []string        `json:"sources"`
	PublishedAt     *time.Time      `json:"published_at,omitempty"`
	ModifiedAt      *time.Time      `json:"modified_at,omitempty"`
}

type cveAffectedPackageDTO struct {
	FindingID        uuid.UUID `json:"finding_id"`
	PackageEcosystem string    `json:"package_ecosystem,omitempty"`
	PackageName      string    `json:"package_name,omitempty"`
	PackageVersion   string    `json:"package_version,omitempty"`
	PackagePURL      string    `json:"package_purl,omitempty"`
	FixedVersion     string    `json:"fixed_version,omitempty"`
	Severity         string    `json:"severity"`
	RiskScore        int       `json:"risk_score"`
}

type cveAffectedImageDTO struct {
	ImageScanResultID   uuid.UUID               `json:"image_scan_result_id"`
	AssetID             *uuid.UUID              `json:"asset_id,omitempty"`
	ImageRef            string                  `json:"image_ref"`
	ImageRefNormalized  string                  `json:"image_ref_normalized"`
	ImageRepository     string                  `json:"image_repository"`
	ImageTag            *string                 `json:"image_tag,omitempty"`
	ImageDigest         string                  `json:"image_digest"`
	Platform            string                  `json:"platform,omitempty"`
	ScannerProfile      string                  `json:"scanner_profile"`
	VulnDBBundleVersion string                  `json:"vulndb_bundle_version,omitempty"`
	VulnDBBundleHash    string                  `json:"vulndb_bundle_hash,omitempty"`
	FindingCount        int                     `json:"finding_count"`
	MaxRiskScore        int                     `json:"max_risk_score"`
	SeverityCounts      map[string]int          `json:"severity_counts"`
	Packages            []cveAffectedPackageDTO `json:"packages"`
	LastSeenAt          time.Time               `json:"last_seen_at"`
	LastScannedAt       time.Time               `json:"last_scanned_at"`
}

type cveAffectedWorkloadDTO struct {
	ClusterID          uuid.UUID `json:"cluster_id"`
	ClusterName        string    `json:"cluster_name,omitempty"`
	DeploymentID       uuid.UUID `json:"deployment_id"`
	WorkloadID         string    `json:"workload_id"`
	Namespace          string    `json:"namespace"`
	Name               string    `json:"name"`
	Kind               string    `json:"kind"`
	ImageRef           string    `json:"image_ref"`
	ImageRefNormalized string    `json:"image_ref_normalized"`
	ImageRepository    string    `json:"image_repository,omitempty"`
	ImageTag           string    `json:"image_tag,omitempty"`
	ImageDigest        string    `json:"image_digest,omitempty"`
	FindingCount       int       `json:"finding_count"`
	MaxRiskScore       int       `json:"max_risk_score"`
	CriticalCount      int       `json:"critical_count"`
	HighCount          int       `json:"high_count"`
	LastSeenAt         time.Time `json:"last_seen_at"`
}

type cveAffectedClusterDTO struct {
	ClusterID     uuid.UUID `json:"cluster_id"`
	Name          string    `json:"name,omitempty"`
	WorkloadCount int       `json:"workload_count"`
	FindingCount  int       `json:"finding_count"`
	MaxRiskScore  int       `json:"max_risk_score"`
}

type cveAffectedSummaryDTO struct {
	ImageCount    int `json:"image_count"`
	WorkloadCount int `json:"workload_count"`
	ClusterCount  int `json:"cluster_count"`
	FindingCount  int `json:"finding_count"`
	MaxRiskScore  int `json:"max_risk_score"`
}

// nicknames maps well-known human-readable vulnerability names to their canonical
// CVE-IDs. A substring (ILIKE) match against the official title ("Apache Log4j2
// Remote Code Execution") doesn't surface a "log4shell" query because the nickname
// isn't in the title or description; we resolve these as exact aliases up-front.
var cveNicknames = map[string]string{
	"log4shell":       "CVE-2021-44228",
	"log4j":           "CVE-2021-44228",
	"heartbleed":      "CVE-2014-0160",
	"shellshock":      "CVE-2014-6271",
	"eternalblue":     "CVE-2017-0144",
	"bluekeep":        "CVE-2019-0708",
	"spring4shell":    "CVE-2022-22965",
	"spectre":         "CVE-2017-5753",
	"meltdown":        "CVE-2017-5754",
	"dirtypipe":       "CVE-2022-0847",
	"dirtycow":        "CVE-2016-5195",
	"printnightmare":  "CVE-2021-34527",
	"proxyshell":      "CVE-2021-34473",
	"proxylogon":      "CVE-2021-26855",
	"polkit":          "CVE-2021-4034",
	"pwnkit":          "CVE-2021-4034",
	"sudoedit":        "CVE-2023-22809",
	"ghostcat":        "CVE-2020-1938",
	"badalloc":        "CVE-2021-22156",
	"zerologon":       "CVE-2020-1472",
	"sigred":          "CVE-2020-1350",
	"smbghost":        "CVE-2020-0796",
	"krack":           "CVE-2017-13077",
	"text4shell":      "CVE-2022-42889",
	"ratelimit":       "CVE-2023-44487",
	"http2rapidreset": "CVE-2023-44487",
	"openssl3":        "CVE-2022-3602",
	"xz":              "CVE-2024-3094",
	"xzbackdoor":      "CVE-2024-3094",
	"regresshion":     "CVE-2024-6387",
	"loop-dos":        "CVE-2024-2169",
	"loopdos":         "CVE-2024-2169",
}

// resolveNickname returns the canonical CVE-ID for a human-readable query, or
// empty string. The lookup is case+space+hyphen-insensitive.
func resolveNickname(q string) string {
	k := strings.ToLower(strings.TrimSpace(q))
	k = strings.ReplaceAll(k, " ", "")
	k = strings.ReplaceAll(k, "-", "")
	k = strings.ReplaceAll(k, "_", "")
	if v, ok := cveNicknames[k]; ok {
		return v
	}
	return ""
}

// severityRange returns the inclusive CVSS-base lower bound and exclusive upper
// bound for a given severity bucket (CVSS v3.1 conventions).
func severityRange(s string) (lo, hi float64, ok bool) {
	switch strings.ToLower(s) {
	case "critical":
		return 9.0, 10.001, true
	case "high":
		return 7.0, 9.0, true
	case "medium":
		return 4.0, 7.0, true
	case "low":
		return 0.1, 4.0, true
	case "info", "none":
		return 0.0, 0.1, true
	}
	return 0, 0, false
}

// cveSortColumns whitelists the sortable columns for CVE search → SQL expression, so
// the client's chosen sort column can be applied server-side across the whole catalog
// (not just the current page). Keys match the frontend column ids.
var cveSortColumns = map[string]string{
	"cve_id":    "cve_id",
	"cvss":      "cvss_base",
	"severity":  "cvss_base",
	"epss":      "epss_probability",
	"kev":       "kev_listed",
	"published": "published_at",
}

func (c *CVE) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var d cveDTO
	var affected []byte
	err := c.db.Pool().QueryRow(r.Context(), `
SELECT cve_id, COALESCE(title,''), COALESCE(description,''), cvss_base, cvss_vector,
       kev_listed, kev_added, epss_probability, epss_updated_at, aliases, affected, sources,
       published_at, modified_at
  FROM cve_records WHERE cve_id = $1`, id).
		Scan(&d.CVEID, &d.Title, &d.Description, &d.CVSSBase, &d.CVSSVector,
			&d.KEVListed, &d.KEVAdded, &d.EPSSProbability, &d.EPSSUpdatedAt,
			&d.Aliases, &affected, &d.Sources, &d.PublishedAt, &d.ModifiedAt)
	if err == nil {
		// Populated row wins — don't regress existing cve_records data.
		d.Affected = affected
		httpx.WriteJSON(w, http.StatusOK, d)
		return
	}

	httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func (c *CVE) Affected(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	id := strings.ToUpper(strings.TrimSpace(chi.URLParam(r, "id")))
	if id == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "missing cve id"})
		return
	}
	// Optional cluster scope: when the CVE detail is opened from inside a cluster,
	// the blast radius (images/workloads/clusters + summary) is restricted to that
	// cluster so the page reflects the cluster context, not the whole org.
	var clusterArg any
	if cs := strings.TrimSpace(r.URL.Query().Get("cluster_id")); cs != "" {
		cid, perr := uuid.Parse(cs)
		if perr != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster_id"})
			return
		}
		var owned bool
		if err := c.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, cid, subj.OrgID).Scan(&owned); err != nil {
			httpx.WriteJSON(w, 500, map[string]string{"error": "Affected evidence could not be loaded"})
			return
		}
		if !owned {
			httpx.WriteJSON(w, 404, map[string]string{"error": "cluster not found"})
			return
		}
		clusterArg = cid
	}

	imageRows, err := c.db.Pool().Query(r.Context(), `
SELECT r.id,
       r.asset_id,
       r.image_ref,
       r.image_ref_normalized,
       r.image_repository,
       r.image_tag,
       r.image_digest,
       r.platform,
       r.scanner_profile,
       r.vulndb_bundle_version,
       r.vulndb_bundle_hash,
       COUNT(DISTINCT f.id)::int AS finding_count,
       COALESCE(MAX(f.risk_score), 0)::int AS max_risk_score,
       COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'critical')::int AS critical_count,
       COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'high')::int AS high_count,
       COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'medium')::int AS medium_count,
       COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'low')::int AS low_count,
       COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'info')::int AS info_count,
       COALESCE(jsonb_agg(jsonb_build_object(
           'finding_id', f.id,
           'package_ecosystem', COALESCE(f.package_ecosystem, ''),
           'package_name', COALESCE(f.package_name, ''),
           'package_version', COALESCE(f.package_version, ''),
           'package_purl', COALESCE(f.package_purl, ''),
           'fixed_version', COALESCE(f.fixed_version, ''),
           'severity', f.severity,
           'risk_score', f.risk_score
       ) ORDER BY f.risk_score DESC, f.package_name, f.package_version) FILTER (WHERE f.id IS NOT NULL), '[]'::jsonb),
       MAX(f.last_seen_at),
       r.last_scanned_at
  FROM image_scan_findings f
  JOIN image_scan_results r ON r.id = f.image_scan_result_id AND r.org_id = f.org_id
 WHERE f.org_id = $1
   AND UPPER(COALESCE(f.external_id, '')) = $2
   AND ($3::uuid IS NULL OR EXISTS (
        SELECT 1 FROM image_workload_links l
         JOIN deployments owned_deployment ON owned_deployment.id=l.deployment_id AND owned_deployment.org_id=f.org_id AND owned_deployment.cluster_id=l.cluster_id
         WHERE l.org_id = f.org_id AND l.cluster_id = $3
           AND ((COALESCE(l.image_digest,'')<>'' AND l.image_digest=r.image_digest)
             OR (COALESCE(l.image_digest,'')='' AND ((r.image_ref<>'' AND l.image_ref=r.image_ref)
                OR (r.image_ref_normalized<>'' AND l.image_ref_normalized=r.image_ref_normalized)
                OR (COALESCE(r.image_repository,'')<>'' AND l.image_repository=r.image_repository
                    AND (COALESCE(r.image_tag,'')='' OR l.image_tag=r.image_tag)))))))
 GROUP BY r.id, r.asset_id, r.image_ref, r.image_ref_normalized, r.image_repository,
          r.image_tag, r.image_digest, r.platform, r.scanner_profile,
          r.vulndb_bundle_version, r.vulndb_bundle_hash, r.last_scanned_at
 ORDER BY max_risk_score DESC, r.last_scanned_at DESC, r.id ASC
 LIMIT 500`, subj.OrgID, id, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Affected evidence could not be loaded"})
		return
	}
	defer imageRows.Close()

	images := []cveAffectedImageDTO{}
	totalFindings := 0
	maxRisk := 0
	for imageRows.Next() {
		var row cveAffectedImageDTO
		var packagesRaw []byte
		var critical, high, medium, low, info int
		if err := imageRows.Scan(
			&row.ImageScanResultID,
			&row.AssetID,
			&row.ImageRef,
			&row.ImageRefNormalized,
			&row.ImageRepository,
			&row.ImageTag,
			&row.ImageDigest,
			&row.Platform,
			&row.ScannerProfile,
			&row.VulnDBBundleVersion,
			&row.VulnDBBundleHash,
			&row.FindingCount,
			&row.MaxRiskScore,
			&critical,
			&high,
			&medium,
			&low,
			&info,
			&packagesRaw,
			&row.LastSeenAt,
			&row.LastScannedAt,
		); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Affected evidence could not be loaded"})
			return
		}
		row.SeverityCounts = map[string]int{
			"critical": critical,
			"high":     high,
			"medium":   medium,
			"low":      low,
			"info":     info,
		}
		if len(packagesRaw) > 0 {
			_ = json.Unmarshal(packagesRaw, &row.Packages)
		}
		totalFindings += row.FindingCount
		if row.MaxRiskScore > maxRisk {
			maxRisk = row.MaxRiskScore
		}
		images = append(images, row)
	}
	if err := imageRows.Err(); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Affected evidence could not be loaded"})
		return
	}

	workloadRows, err := c.db.Pool().Query(r.Context(), `
WITH matches AS (
    SELECT f.id AS finding_id,
           f.severity,
           f.risk_score,
           r.image_ref,
           r.image_ref_normalized,
           r.image_repository,
           COALESCE(r.image_tag, '') AS image_tag,
           r.image_digest
      FROM image_scan_findings f
      JOIN image_scan_results r ON r.id = f.image_scan_result_id AND r.org_id = f.org_id
     WHERE f.org_id = $1
       AND UPPER(COALESCE(f.external_id, '')) = $2
)
SELECT l.cluster_id,
       COALESCE(c.name, ''),
       l.deployment_id,
       l.workload_id,
       l.namespace,
       l.name,
       l.kind,
       MAX(l.image_ref),
       MAX(l.image_ref_normalized),
       COALESCE(MAX(l.image_repository), ''),
       COALESCE(MAX(l.image_tag), ''),
       COALESCE(MAX(l.image_digest), ''),
       COUNT(DISTINCT m.finding_id)::int AS finding_count,
       COALESCE(MAX(m.risk_score), 0)::int AS max_risk_score,
       COUNT(DISTINCT m.finding_id) FILTER (WHERE m.severity = 'critical')::int AS critical_count,
       COUNT(DISTINCT m.finding_id) FILTER (WHERE m.severity = 'high')::int AS high_count,
       MAX(l.last_seen_at)
  FROM matches m
  JOIN image_workload_links l
    ON l.org_id = $1
   AND ($3::uuid IS NULL OR l.cluster_id = $3)
   AND ((COALESCE(l.image_digest,'')<>'' AND l.image_digest=m.image_digest)
     OR (COALESCE(l.image_digest,'')='' AND ((m.image_ref<>'' AND l.image_ref=m.image_ref)
     OR (m.image_ref_normalized<>'' AND l.image_ref_normalized=m.image_ref_normalized)
     OR (m.image_repository<>'' AND l.image_repository=m.image_repository AND (m.image_tag='' OR l.image_tag=m.image_tag)))))
  JOIN clusters c ON c.id = l.cluster_id AND c.org_id = $1
  JOIN deployments owned_deployment ON owned_deployment.id=l.deployment_id AND owned_deployment.org_id=$1 AND owned_deployment.cluster_id=l.cluster_id
 GROUP BY l.cluster_id, c.name, l.deployment_id, l.workload_id, l.namespace, l.name, l.kind
 ORDER BY max_risk_score DESC, MAX(l.last_seen_at) DESC, l.cluster_id, l.deployment_id, l.workload_id, l.namespace, l.name, l.kind
 LIMIT 1000`, subj.OrgID, id, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Affected evidence could not be loaded"})
		return
	}
	defer workloadRows.Close()

	workloads := []cveAffectedWorkloadDTO{}
	clustersByID := map[uuid.UUID]*cveAffectedClusterDTO{}
	for workloadRows.Next() {
		var row cveAffectedWorkloadDTO
		if err := workloadRows.Scan(
			&row.ClusterID,
			&row.ClusterName,
			&row.DeploymentID,
			&row.WorkloadID,
			&row.Namespace,
			&row.Name,
			&row.Kind,
			&row.ImageRef,
			&row.ImageRefNormalized,
			&row.ImageRepository,
			&row.ImageTag,
			&row.ImageDigest,
			&row.FindingCount,
			&row.MaxRiskScore,
			&row.CriticalCount,
			&row.HighCount,
			&row.LastSeenAt,
		); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Affected evidence could not be loaded"})
			return
		}
		cluster := clustersByID[row.ClusterID]
		if cluster == nil {
			cluster = &cveAffectedClusterDTO{ClusterID: row.ClusterID, Name: row.ClusterName}
			clustersByID[row.ClusterID] = cluster
		}
		cluster.WorkloadCount++
		cluster.FindingCount += row.FindingCount
		if row.MaxRiskScore > cluster.MaxRiskScore {
			cluster.MaxRiskScore = row.MaxRiskScore
		}
		if row.MaxRiskScore > maxRisk {
			maxRisk = row.MaxRiskScore
		}
		workloads = append(workloads, row)
	}
	if err := workloadRows.Err(); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Affected evidence could not be loaded"})
		return
	}

	clusters := make([]cveAffectedClusterDTO, 0, len(clustersByID))
	for _, cluster := range clustersByID {
		clusters = append(clusters, *cluster)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"cve_id":    id,
		"summary":   cveAffectedSummaryDTO{ImageCount: len(images), WorkloadCount: len(workloads), ClusterCount: len(clusters), FindingCount: totalFindings, MaxRiskScore: maxRisk},
		"images":    images,
		"workloads": workloads,
		"clusters":  clusters,
	})
}

// Stats returns aggregate counts for the live cve_records table — used by the
// /cve page stat tiles and the dashboard CVE panel. All COUNTs lean on partial
// or expression indexes (idx_cve_kev, idx_cve_epss) so the response is fast
// even with hundreds of thousands of rows.
func (c *CVE) Stats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pool := c.db.Pool()

	type bucket struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}
	type sourceBucket struct {
		Source string `json:"source"`
		Count  int64  `json:"count"`
	}

	resp := map[string]any{}

	var (
		total     int64
		kev       int64
		epssGt50  int64
		cvssGt70  int64
		hasCVSS   int64
		oldest    *time.Time
		latest    *time.Time
		critCount int64
		highCount int64
		medCount  int64
		lowCount  int64
		infoCount int64
	)
	// Single pass over cve_records: all headline counts + the cvss_base severity
	// histogram via FILTER aggregates. Previously this ran ~8 separate full scans
	// of the whole CVE catalog (7 scalar subqueries + a GROUP BY), ~8s total.
	if err := pool.QueryRow(ctx, `
SELECT
  COUNT(*),
  COUNT(*) FILTER (WHERE kev_listed = TRUE),
  COUNT(*) FILTER (WHERE epss_probability > 0.5),
  COUNT(*) FILTER (WHERE cvss_base >= 7.0),
  COUNT(*) FILTER (WHERE cvss_base IS NOT NULL),
  MIN(published_at),
  MAX(published_at),
  COUNT(*) FILTER (WHERE cvss_base >= 9.0),
  COUNT(*) FILTER (WHERE cvss_base >= 7.0 AND cvss_base < 9.0),
  COUNT(*) FILTER (WHERE cvss_base >= 4.0 AND cvss_base < 7.0),
  COUNT(*) FILTER (WHERE cvss_base >= 0.1 AND cvss_base < 4.0),
  COUNT(*) FILTER (WHERE cvss_base IS NOT NULL AND cvss_base < 0.1)
  FROM cve_records
`).Scan(&total, &kev, &epssGt50, &cvssGt70, &hasCVSS, &oldest, &latest,
		&critCount, &highCount, &medCount, &lowCount, &infoCount); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	resp["total"] = total
	resp["kev_listed"] = kev
	resp["epss_gt_50"] = epssGt50
	resp["cvss_gt_70"] = cvssGt70
	resp["has_cvss"] = hasCVSS
	resp["latest_published_at"] = latest
	resp["oldest_published_at"] = oldest
	resp["by_severity"] = []bucket{
		{Severity: "critical", Count: critCount},
		{Severity: "high", Count: highCount},
		{Severity: "medium", Count: medCount},
		{Severity: "low", Count: lowCount},
		{Severity: "info", Count: infoCount},
	}

	// Source histogram via unnest(sources) — uses a seq scan but is cheap on
	// the indexed text[] column. Limit to the 8 most common to keep response small.
	sourceRows, err := pool.Query(ctx, `
SELECT s AS source, COUNT(*)
  FROM cve_records, unnest(sources) AS s
 GROUP BY s
 ORDER BY 2 DESC
 LIMIT 8`)
	if err == nil {
		defer sourceRows.Close()
		bySrc := make([]sourceBucket, 0, 8)
		for sourceRows.Next() {
			var b sourceBucket
			if err := sourceRows.Scan(&b.Source, &b.Count); err == nil {
				bySrc = append(bySrc, b)
			}
		}
		resp["by_source"] = bySrc
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (c *CVE) BundleStatus(w http.ResponseWriter, r *http.Request) {
	var version, ociRef, sha256 string
	var recordCount int64
	var signed bool
	var importedAt time.Time
	var publishedAt *time.Time
	err := c.db.Pool().QueryRow(r.Context(),
		`SELECT version, oci_ref, sha256, record_count, signed, imported_at, published_at
           FROM cve_bundles ORDER BY id DESC LIMIT 1`,
	).Scan(&version, &ociRef, &sha256, &recordCount, &signed, &importedAt, &publishedAt)

	// Always include the live cve_records count so the dashboard panel can
	// show both the bundle's record_count (the imported OCI artifact) AND the
	// actual row count in postgres.
	var liveRows int64
	_ = c.db.Pool().QueryRow(r.Context(), `SELECT COUNT(*) FROM cve_records`).Scan(&liveRows)

	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"available": false,
			"row_count": liveRows,
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"available":    true,
		"version":      version,
		"oci_ref":      ociRef,
		"sha256":       sha256,
		"record_count": recordCount,
		"row_count":    liveRows,
		"signed":       signed,
		"imported_at":  importedAt,
		"published_at": publishedAt,
	})
}
