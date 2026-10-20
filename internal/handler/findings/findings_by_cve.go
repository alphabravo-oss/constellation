package findings

import (
	"net/http"
	"strconv"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

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
		apiutil.WriteStatus(r.Context(), w, http.StatusUnauthorized, "no subject")
		return
	}
	values := r.URL.Query()
	values.Set("kind", "vulnerability")
	where, args, err := findingFilter(subj.OrgID, values, true, false)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	if values.Get("id_scope") != "all" {
		where += " AND external_id LIKE 'CVE-%'"
	}
	limit := 200
	if value, err := strconv.Atoi(values.Get("limit")); err == nil && value > 0 && value <= 2000 {
		limit = value
	}
	offset := findingOffset(values)
	having := ""
	if findingFixableRequested(values) {
		having = " HAVING bool_or(" + findingFixableSQL + ")"
	}
	var total int
	if err := f.db.Pool().QueryRow(r.Context(), "SELECT count(*) FROM (SELECT external_id FROM findings WHERE "+where+" GROUP BY external_id"+having+") matched", args...).Scan(&total); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	args = append(args, limit, offset)
	rows, err := f.db.Pool().Query(r.Context(), `
SELECT external_id,
       (array_agg(severity ORDER BY risk_score DESC))[1]                              AS severity,
       max(risk_score)                                                                AS risk_score,
       (array_agg(NULLIF(`+findingPackageSQL+`, '') ORDER BY risk_score DESC))[1] AS package,
       (array_agg(`+findingFixedSQL+` ORDER BY risk_score DESC) FILTER (WHERE `+findingFixableSQL+`))[1] AS fixed_version,
       count(*)                                                                       AS instances,
       count(DISTINCT target_ref)                                                     AS affected_images,
       count(DISTINCT cluster_id) FILTER (WHERE cluster_id IS NOT NULL)               AS affected_clusters,
       COALESCE((array_agg(DISTINCT target_ref) FILTER (WHERE target_ref IS NOT NULL))[1:25], ARRAY[]::text[])                                         AS images,
       max(last_seen_at)                                                              AS last_seen_at,
       max(CASE
             WHEN COALESCE(detail_json->>'cvss_base', '') ~ '^[0-9]+(\.[0-9]+)?$'
             THEN (detail_json->>'cvss_base')::float8
           END)                                                                        AS cvss,
       (array_agg(NULLIF(detail_json->>'cvss_vector','')
          ORDER BY
            CASE
              WHEN COALESCE(detail_json->>'cvss_base', '') ~ '^[0-9]+(\.[0-9]+)?$'
              THEN (detail_json->>'cvss_base')::float8
            END DESC NULLS LAST,
            risk_score DESC)
          FILTER (WHERE COALESCE(detail_json->>'cvss_vector','') <> ''))[1]            AS cvss_vector,
       bool_or(lower(COALESCE(detail_json->>'kev','')) IN ('true','t','1','yes'))      AS kev,
       bool_or(`+findingFixableSQL+`) AS has_fix
  FROM findings WHERE `+where+`
 GROUP BY external_id`+having+`
 ORDER BY max(risk_score) DESC, external_id
 LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
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
		CVSSBase         float64  `json:"cvss_base,omitempty"`
		CVSSVector       string   `json:"cvss_vector,omitempty"`
		KEV              bool     `json:"kev"`
		HasFix           bool     `json:"has_fix"`
	}
	out := make([]cveRollup, 0, limit)
	for rows.Next() {
		var c cveRollup
		var pkg, fixed *string
		var cvss *float64
		var cvssVector *string
		var kev, hasFix *bool
		var lastSeen time.Time
		if err := rows.Scan(&c.CVE, &c.Severity, &c.RiskScore, &pkg, &fixed,
			&c.Instances, &c.AffectedImages, &c.AffectedClusters, &c.Images, &lastSeen,
			&cvss, &cvssVector, &kev, &hasFix); err != nil {
			apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
			return
		}
		if cvss != nil {
			c.CVSS = *cvss
			c.CVSSBase = *cvss
		}
		if cvssVector != nil {
			c.CVSSVector = *cvssVector
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
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"cves": out, "limit": limit, "offset": offset, "total": total})
}
