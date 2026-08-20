package findings

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// ByCVE returns findings ROLLED UP by CVE — one row per vulnerability with the blast
// radius (how many images/clusters/instances it hits), mirroring NeuVector's
// vulnerability-asset view (RESTVulnerabilityAsset: a CVE + its affected assets). The
// raw findings table stores one row per (CVE × image-workload), so a single CVE across
// many workloads is many rows; this collapses them so the operator sees "CVE-X hits N
// images" instead of N duplicate-looking rows.
//
//	GET /api/v1/findings/by-cve?cluster_id=&lifecycle=open&limit=&offset=
func (f *Findings) ByCVE(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "no subject"})
		return
	}
	lifecycle := r.URL.Query().Get("lifecycle") // "" = all
	var clusterArg any
	if cs := r.URL.Query().Get("cluster_id"); cs != "" {
		cid, err := uuid.Parse(cs)
		if err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster_id"})
			return
		}
		clusterArg = cid
	}
	limit := 200
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 2000 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o > 0 {
		offset = o
	}
	// fixable=true keeps only CVEs that have at least one fixed version available.
	fixable := r.URL.Query().Get("fixable") == "true" || r.URL.Query().Get("fixable") == "1"
	// q is a server-side search over CVE id + package name so the client never has to
	// fetch-all-then-filter (which silently truncated at the row cap).
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	// Total distinct CVEs matching the same filters, so the client can render a real pager
	// instead of guessing from a truncated page.
	var total int
	if err := f.db.Pool().QueryRow(r.Context(), `
SELECT count(*) FROM (
  SELECT external_id
    FROM findings
   WHERE org_id = $1
     AND kind = 'vulnerability'
     AND external_id LIKE 'CVE-%'
     AND ($2::text = '' OR lifecycle = $2)
     AND ($3::uuid IS NULL OR cluster_id = $3)
     AND target_type <> 'workload'
     AND ($4::text = '' OR external_id ILIKE '%'||$4||'%' OR detail_json->>'package_name' ILIKE '%'||$4||'%')
   GROUP BY external_id
  HAVING ($5::bool IS NOT TRUE OR bool_or(COALESCE(detail_json->>'fixed', detail_json->>'fixed_version','') NOT IN ('','false')))
) t`, subj.OrgID, lifecycle, clusterArg, q, fixable).Scan(&total); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	rows, err := f.db.Pool().Query(r.Context(), `
SELECT external_id,
       (array_agg(severity ORDER BY risk_score DESC))[1]                              AS severity,
       max(risk_score)                                                                AS risk_score,
       (array_agg(NULLIF(detail_json->>'package_name','') ORDER BY risk_score DESC))[1] AS package,
       (array_agg(COALESCE(NULLIF(detail_json->>'fixed',''), NULLIF(detail_json->>'fixed_version','')) ORDER BY risk_score DESC) FILTER (WHERE COALESCE(detail_json->>'fixed', detail_json->>'fixed_version','') NOT IN ('','false')))[1] AS fixed_version,
       count(*)                                                                       AS instances,
       count(DISTINCT target_ref)                                                     AS affected_images,
       count(DISTINCT cluster_id) FILTER (WHERE cluster_id IS NOT NULL)               AS affected_clusters,
       (array_agg(DISTINCT target_ref))[1:25]                                         AS images,
       max(last_seen_at)                                                              AS last_seen_at,
       max(NULLIF(detail_json->>'cvss_base','')::float8)                              AS cvss,
       bool_or((detail_json->>'kev')::bool)                                           AS kev,
       bool_or(COALESCE(detail_json->>'fixed', detail_json->>'fixed_version','') NOT IN ('','false')) AS has_fix
  FROM findings
 WHERE org_id = $1
   AND kind = 'vulnerability'
   AND external_id LIKE 'CVE-%'
   AND ($2::text = '' OR lifecycle = $2)
   AND ($3::uuid IS NULL OR cluster_id = $3)
   -- Canonical: count image-workload instances only, not the redundant runtime-agent
   -- 'workload' pod-scan copies (see findings.go) which would inflate instance/image counts.
   AND target_type <> 'workload'
   AND ($7::text = '' OR external_id ILIKE '%'||$7||'%' OR detail_json->>'package_name' ILIKE '%'||$7||'%')
 GROUP BY external_id
 HAVING ($6::bool IS NOT TRUE OR bool_or(COALESCE(detail_json->>'fixed', detail_json->>'fixed_version','') NOT IN ('','false')))
 ORDER BY max(risk_score) DESC, external_id
 LIMIT $4 OFFSET $5`, subj.OrgID, lifecycle, clusterArg, limit, offset, fixable, q)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type cveRollup struct {
		CVE              string   `json:"cve"`
		Severity         string   `json:"severity"`
		RiskScore        float64  `json:"risk_score"`
		Package          string   `json:"package,omitempty"`
		FixedVersion     string   `json:"fixed_version,omitempty"`
		Instances        int      `json:"instances"`
		AffectedImages   int      `json:"affected_images"`
		AffectedClusters int      `json:"affected_clusters"`
		Images           []string `json:"images"`
		LastSeenAt       string   `json:"last_seen_at"`
		CVSS             float64  `json:"cvss,omitempty"`
		KEV              bool     `json:"kev"`
		HasFix           bool     `json:"has_fix"`
	}
	out := make([]cveRollup, 0, limit)
	for rows.Next() {
		var c cveRollup
		var pkg, fixed *string
		var cvss *float64
		var kev, hasFix *bool
		var lastSeen time.Time
		if err := rows.Scan(&c.CVE, &c.Severity, &c.RiskScore, &pkg, &fixed,
			&c.Instances, &c.AffectedImages, &c.AffectedClusters, &c.Images, &lastSeen,
			&cvss, &kev, &hasFix); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if cvss != nil {
			c.CVSS = *cvss
		}
		c.KEV = kev != nil && *kev
		c.HasFix = hasFix != nil && *hasFix
		if pkg != nil {
			c.Package = *pkg
		}
		if fixed != nil {
			c.FixedVersion = *fixed
		}
		c.LastSeenAt = lastSeen.UTC().Format(time.RFC3339)
		if c.Images == nil {
			c.Images = []string{}
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"cves": out, "limit": limit, "offset": offset, "total": total})
}
