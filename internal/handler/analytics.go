// Trend analytics + backup status endpoints.
//
//	GET /api/v1/analytics/trend       — 90-day finding velocity by severity
//	GET /api/v1/analytics/mttr        — mean-time-to-resolve per severity
//	GET /api/v1/analytics/backups     — last 50 backups + freshness
package handler

import (
	"net/http"

	"github.com/alphabravocompany/constellation/internal/db"
)

type Analytics struct {
	db *db.DB
}

func NewAnalytics(d *db.DB) *Analytics { return &Analytics{db: d} }

// Trend returns daily finding counts by severity for the last 90 days.
func (a *Analytics) Trend(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	rows, err := a.db.Pool().Query(r.Context(), `
SELECT day, severity, SUM(finding_count) AS cnt
  FROM metrics_daily
 WHERE org_id = $1 AND day >= CURRENT_DATE - INTERVAL '90 days'
 GROUP BY 1, 2
 ORDER BY 1`, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var day string
		var sev string
		var cnt int64
		if err := rows.Scan(&day, &sev, &cnt); err == nil {
			out = append(out, map[string]any{"day": day, "severity": sev, "count": cnt})
		}
	}
	writeJSON(w, 200, map[string]any{"points": out})
}

// MTTR returns mean-time-to-resolve in days, bucketed by severity, for the trailing 90d.
func (a *Analytics) MTTR(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	rows, err := a.db.Pool().Query(r.Context(), `
SELECT severity,
       COALESCE(AVG(mttr_seconds), 0) / 86400.0 AS mttr_days,
       SUM(resolved_count) AS resolved
  FROM metrics_daily
 WHERE org_id = $1 AND day >= CURRENT_DATE - INTERVAL '90 days'
 GROUP BY 1
 ORDER BY 1`, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var sev string
		var mttr float64
		var resolved int64
		if err := rows.Scan(&sev, &mttr, &resolved); err == nil {
			out = append(out, map[string]any{"severity": sev, "mttr_days": mttr, "resolved": resolved})
		}
	}
	writeJSON(w, 200, map[string]any{"by_severity": out})
}

// Backups lists the most recent backup runs.
func (a *Analytics) Backups(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Pool().Query(r.Context(), `
SELECT id, started_at, finished_at, status, COALESCE(object_uri,''), COALESCE(sha256,''),
       COALESCE(size_bytes,0), COALESCE(cosign_signature,'') <> '' AS signed
  FROM backups
 ORDER BY started_at DESC
 LIMIT 50`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var (
			id, status, uri, sha string
			started, finished    *string
			size                 int64
			signed               bool
		)
		if err := rows.Scan(&id, &started, &finished, &status, &uri, &sha, &size, &signed); err == nil {
			out = append(out, map[string]any{
				"id": id, "started_at": started, "finished_at": finished, "status": status,
				"object_uri": uri, "sha256": sha, "size_bytes": size, "signed": signed,
			})
		}
	}
	writeJSON(w, 200, map[string]any{"backups": out})
}
