package handler

// B1 — Unified incident timeline.
//
// GET /api/v1/security/timeline returns a merged, time-ordered stream that
// unifies the four NeuVector-style event consoles into one investigation view:
//
//	dpi_threat        ← runtime_threats  (DPI signature hits from the dp data-plane)
//	runtime_event     ← events           (eBPF / L7-DPI / WAF / DLP / Falco runtime telemetry)
//	network_violation ← violations       (admission / policy / drift / runtime violations)
//	audit             ← audit_events     (hash-chained control-plane activity)
//
// All four already exist as separate tables; this endpoint normalises them
// into a common projection with a shared text severity and time-orders the
// union. Filters: ?type=, ?severity=, ?from=/?to=, ?cluster_id=, pagination.
//
// The union is one SQL statement (no per-source round-trips) so pagination is
// correct across sources. Each source branch is gated by a boolean include
// flag so a ?type= filter simply flips branches off — the SQL stays static
// (all $N placeholders are always referenced) which keeps pgx happy.

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/db"
)

// SecurityTimeline serves the unified incident timeline.
type SecurityTimeline struct {
	db *db.DB
}

// NewSecurityTimeline constructs the handler.
func NewSecurityTimeline(database *db.DB) *SecurityTimeline { return &SecurityTimeline{db: database} }

type timelineItem struct {
	Source     string    `json:"source"` // dpi_threat | runtime_event | network_violation | audit
	ID         string    `json:"id"`
	Severity   string    `json:"severity"` // info | low | medium | high | critical
	At         time.Time `json:"at"`
	Title      string    `json:"title"`
	WorkloadID string    `json:"workload_id,omitempty"`
	Namespace  string    `json:"namespace,omitempty"`
	ClusterID  string    `json:"cluster_id,omitempty"`
	Ref        string    `json:"ref,omitempty"` // source-specific reference (threat_id, verdict, policy, target_kind)
}

// validTimelineSeverities is the normalised text vocabulary the union emits.
var validTimelineSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// allTimelineSources is the canonical source list. A ?type= filter intersects
// with this; an empty/absent filter enables all.
var allTimelineSources = []string{"dpi_threat", "runtime_event", "network_violation", "audit"}

// List handles GET /api/v1/security/timeline.
func (t *SecurityTimeline) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Time window. Defaults to the last 7 days so the first page is bounded.
	to := time.Now().Add(time.Minute)
	from := to.Add(-7 * 24 * time.Hour)
	if v := strings.TrimSpace(r.URL.Query().Get("from")); v != "" {
		if parsed, perr := time.Parse(time.RFC3339, v); perr == nil {
			from = parsed
		} else {
			jsonError(w, http.StatusBadRequest, "invalid from (want RFC3339)")
			return
		}
	}
	if v := strings.TrimSpace(r.URL.Query().Get("to")); v != "" {
		if parsed, perr := time.Parse(time.RFC3339, v); perr == nil {
			to = parsed
		} else {
			jsonError(w, http.StatusBadRequest, "invalid to (want RFC3339)")
			return
		}
	}

	// Type filter → per-source include flags. When a cluster is selected we
	// exclude audit events: audit_events has no cluster_id column and is an
	// org-level activity feed (same contract the /audit/events handler uses).
	enabled := parseTimelineSources(r.URL.Query().Get("type"))
	inclThreat := enabled["dpi_threat"]
	inclEvent := enabled["runtime_event"]
	inclViolation := enabled["network_violation"]
	inclAudit := enabled["audit"] && clusterArg == nil

	// Severity filter (text, comma-separated). nil ⇒ no filter.
	var sevArr []string
	for _, s := range strings.Split(r.URL.Query().Get("severity"), ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if validTimelineSeverities[s] {
			sevArr = append(sevArr, s)
		}
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	// $1 org, $2 cluster (nullable uuid), $3 from, $4 to, $5 severity text[]
	// (nullable), $6 limit, $7 offset, $8..$11 per-source include flags.
	//
	// runtime_threats.severity is NeuVector's 1..9 scale — mapped to text
	// via CASE. events/violations already carry text severity; audit rows
	// are informational.
	const q = `
SELECT source, id, severity, at, title, workload_id, namespace, cluster_id, ref
  FROM (
    SELECT 'dpi_threat' AS source, id::text AS id,
           CASE WHEN severity >= 8 THEN 'critical'
                WHEN severity >= 6 THEN 'high'
                WHEN severity >= 4 THEN 'medium'
                WHEN severity >= 2 THEN 'low'
                ELSE 'info' END AS severity,
           at, COALESCE(NULLIF(msg,''), 'DPI threat') AS title,
           COALESCE(workload_id,'') AS workload_id, COALESCE(namespace,'') AS namespace,
           cluster_id::text AS cluster_id, threat_id::text AS ref
      FROM runtime_threats
     WHERE $8 AND org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2)
       AND at >= $3 AND at < $4
    UNION ALL
    SELECT 'runtime_event', id::text,
           lower(severity), at, COALESCE(NULLIF(kind,''),'runtime event'),
           COALESCE(workload_id,''), '',
           cluster_id::text, COALESCE(source,'') || CASE WHEN verdict <> '' THEN ' · '||verdict ELSE '' END
      FROM events
     WHERE $9 AND org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2)
       AND at >= $3 AND at < $4
    UNION ALL
    SELECT 'network_violation', v.id::text,
           lower(v.severity), v.at, COALESCE(NULLIF(v.message,''), v.kind),
           COALESCE(d.name,''), COALESCE(d.namespace,''),
           COALESCE(d.cluster_id::text,''), COALESCE(v.policy_name,'')
      FROM violations v
      LEFT JOIN deployments d ON d.id = v.deployment_id
     WHERE $10 AND v.org_id = $1 AND ($2::uuid IS NULL OR d.cluster_id = $2)
       AND v.at >= $3 AND v.at < $4
    UNION ALL
    SELECT 'audit', a.id::text,
           'info', a.at, a.action,
           '', '', '', COALESCE(a.target_kind,'')
      FROM audit_events a
     WHERE $11 AND a.org_id = $1 AND ($2::uuid IS NULL)
       AND a.at >= $3 AND a.at < $4
  ) t
 WHERE ($5::text[] IS NULL OR severity = ANY($5))
 ORDER BY at DESC
 LIMIT $6 OFFSET $7`

	rows, err := t.db.Pool().Query(r.Context(), q,
		subj.OrgID, clusterArg, from, to, sevArr, limit, offset,
		inclThreat, inclEvent, inclViolation, inclAudit)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	out := make([]timelineItem, 0, limit)
	for rows.Next() {
		var it timelineItem
		if err := rows.Scan(&it.Source, &it.ID, &it.Severity, &it.At, &it.Title,
			&it.WorkloadID, &it.Namespace, &it.ClusterID, &it.Ref); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":  out,
		"limit":  limit,
		"offset": offset,
		"from":   from.UTC().Format(time.RFC3339),
		"to":     to.UTC().Format(time.RFC3339),
	})
}

// parseTimelineSources turns a ?type=a,b,c filter into a per-source enable map.
// An empty/absent filter enables every source. Unknown tokens are ignored.
func parseTimelineSources(raw string) map[string]bool {
	out := map[string]bool{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		for _, s := range allTimelineSources {
			out[s] = true
		}
		return out
	}
	want := map[string]bool{}
	for _, tok := range strings.Split(raw, ",") {
		want[strings.ToLower(strings.TrimSpace(tok))] = true
	}
	for _, s := range allTimelineSources {
		if want[s] {
			out[s] = true
		}
	}
	return out
}
