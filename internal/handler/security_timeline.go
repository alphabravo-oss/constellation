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
	"encoding/csv"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
	PlatformRole *string `json:"platform_role,omitempty"`
	roleLabels   json.RawMessage
	Source       string    `json:"source"` // dpi_threat | runtime_event | network_violation | audit
	ID           string    `json:"id"`
	Severity     string    `json:"severity"` // info | low | medium | high | critical
	At           time.Time `json:"at"`
	Title        string    `json:"title"`
	WorkloadID   string    `json:"workload_id,omitempty"`
	Namespace    string    `json:"namespace,omitempty"`
	ClusterID    string    `json:"cluster_id,omitempty"`
	Verdict      string    `json:"verdict,omitempty"`
	Ref          string    `json:"ref,omitempty"` // source-specific reference (threat_id, verdict, policy, target_kind)
}

// validTimelineSeverities is the normalised text vocabulary the union emits.
var validTimelineSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// allTimelineSources is the canonical source list. A ?type= filter intersects
// with this; an empty/absent filter enables all.
var allTimelineSources = []string{"dpi_threat", "runtime_event", "network_violation", "audit"}

// List handles GET /api/v1/security/timeline.
func (t *SecurityTimeline) List(w http.ResponseWriter, r *http.Request) { t.read(w, r, false) }

// ExportCSV uses the identical filters and snapshot as List; pagination is
// intentionally ignored and a documented 10,000-record export limit applies.
func (t *SecurityTimeline) ExportCSV(w http.ResponseWriter, r *http.Request) { t.read(w, r, true) }

func (t *SecurityTimeline) read(w http.ResponseWriter, r *http.Request, export bool) {
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
	if clusterArg != nil {
		var owned bool
		if err := t.db.Pool().QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM clusters WHERE id = $1 AND org_id = $2)`, clusterArg, subj.OrgID).Scan(&owned); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !owned {
			jsonError(w, http.StatusNotFound, "cluster not found")
			return
		}
	}

	window, err := parseTimelineWindow(r.URL.Query(), time.Now())
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	from, to := window.from, window.to

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

	verdicts, err := parseTimelineVerdicts(r.URL.Query().Get("verdict"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(verdicts) > 0 && (!inclEvent || inclThreat || inclViolation || enabled["audit"]) {
		jsonError(w, http.StatusBadRequest, "verdict requires the runtime_event source only")
		return
	}
	limit, offset, err := parseTimelinePagination(r.URL.Query())
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if export {
		limit, offset = 10000, 0
	}
	fetch := limit + 1

	qFilter := strings.TrimSpace(r.URL.Query().Get("q"))
	namespaceFilter := strings.TrimSpace(r.URL.Query().Get("namespace"))
	workloadFilter := strings.TrimSpace(r.URL.Query().Get("workload"))
	refFilter := strings.TrimSpace(r.URL.Query().Get("ref"))

	// $1 org, $2 cluster (nullable uuid), $3 from, $4 to, $5 severity text[]
	// (nullable), $6 limit, $7 offset, $8..$11 per-source include flags,
	// $12..$15 normalized text filters.
	//
	// runtime_threats.severity is NeuVector's 1..9 scale — mapped to text
	// via CASE. events/violations already carry text severity; audit rows
	// are informational.
	const q = `
SELECT source, id, severity, at, title, workload_id, namespace, cluster_id, verdict, ref, role_labels
  FROM (
    SELECT 'dpi_threat' AS source, id::text AS id,
           CASE WHEN severity >= 8 THEN 'critical'
                WHEN severity >= 6 THEN 'high'
                WHEN severity >= 4 THEN 'medium'
                WHEN severity >= 2 THEN 'low'
                ELSE 'info' END AS severity,
           at, COALESCE(NULLIF(msg,''), 'DPI threat') AS title,
           COALESCE(workload_id,'') AS workload_id, COALESCE(namespace,'') AS namespace,
           cluster_id::text AS cluster_id, ''::text AS verdict, threat_id::text AS ref, NULL::jsonb AS role_labels
      FROM runtime_threats
     WHERE $6 AND org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2)
       AND (($14 AND at > $3) OR (NOT $14 AND at >= $3)) AND (NOT $15 OR at < $4)
    UNION ALL
    SELECT 'runtime_event', id::text,
           lower(severity), at, COALESCE(NULLIF(kind,''),'runtime event'),
           COALESCE(workload_id,''), COALESCE(namespace,''),
           cluster_id::text, COALESCE(verdict,''), COALESCE(source,'') || CASE WHEN verdict <> '' THEN ' · '||verdict ELSE '' END, NULL::jsonb
      FROM events
     WHERE $7 AND org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2)
       AND (($14 AND at > $3) OR (NOT $14 AND at >= $3)) AND (NOT $15 OR at < $4)
       AND (NOT $16 OR $5::text[] IS NULL OR severity = ANY($5))
    UNION ALL
    SELECT 'network_violation', v.id::text,
           lower(v.severity), v.at, COALESCE(NULLIF(v.message,''), v.kind),
           COALESCE(d.name,''), COALESCE(d.namespace,''),
           COALESCE(d.cluster_id::text,''), '', COALESCE(v.policy_name,''), COALESCE(d.labels,'{}'::jsonb)
      FROM violations v
      LEFT JOIN deployments d ON d.id = v.deployment_id AND d.org_id = v.org_id
     WHERE $8 AND v.org_id = $1 AND ($2::uuid IS NULL OR d.cluster_id = $2)
       AND (($14 AND v.at > $3) OR (NOT $14 AND v.at >= $3)) AND (NOT $15 OR v.at < $4)
    UNION ALL
    SELECT 'audit', a.id::text,
           'info', a.at, a.action,
           '', '', '', '', COALESCE(a.target_kind,''), NULL::jsonb
      FROM audit_events a
     WHERE $9 AND a.org_id = $1 AND ($2::uuid IS NULL)
       AND (($14 AND a.at > $3) OR (NOT $14 AND a.at >= $3)) AND (NOT $15 OR a.at < $4)
  ) t
 WHERE ($5::text[] IS NULL OR severity = ANY($5))
   AND ($17::text[] IS NULL OR verdict = ANY($17))
   AND ($10 = '' OR title ILIKE '%' || $10 || '%'
        OR workload_id ILIKE '%' || $10 || '%'
        OR namespace ILIKE '%' || $10 || '%'
        OR ref ILIKE '%' || $10 || '%'
        OR id ILIKE '%' || $10 || '%')
   AND ($11 = '' OR namespace ILIKE '%' || $11 || '%')
   AND ($12 = '' OR workload_id ILIKE '%' || $12 || '%')
   AND ($13 = '' OR ref ILIKE '%' || $13 || '%')
`

	args := []any{subj.OrgID, clusterArg, from, to, sevArr, inclThreat, inclEvent, inclViolation, inclAudit, qFilter, namespaceFilter, workloadFilter, refFilter, window.exclusive, window.upperBound, window.lowerOnly, verdicts}
	// Exact event-only counts are affordable and correspond to Dashboard event
	// units. Broad mixed-source browsing retains its existing has_more contract.
	var total *int
	var tx pgx.Tx
	if export || inclEvent && !inclThreat && !inclViolation && !inclAudit {
		tx, err = t.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer tx.Rollback(r.Context())
		var count int
		if err = tx.QueryRow(r.Context(), "SELECT COUNT(*)::int FROM ("+q+") matched", args...).Scan(&count); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		total = &count
	}
	pageSQL := q + " ORDER BY at DESC, source, id DESC LIMIT $18 OFFSET $19"
	pageArgs := append(append([]any{}, args...), fetch, offset)
	var rows pgx.Rows
	if tx != nil {
		rows, err = tx.Query(r.Context(), pageSQL, pageArgs...)
	} else {
		rows, err = t.db.Pool().Query(r.Context(), pageSQL, pageArgs...)
	}

	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	out := make([]timelineItem, 0, limit)
	for rows.Next() {
		var it timelineItem
		if err := rows.Scan(&it.Source, &it.ID, &it.Severity, &it.At, &it.Title,
			&it.WorkloadID, &it.Namespace, &it.ClusterID, &it.Verdict, &it.Ref, &it.roleLabels); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	hasMore := false
	if len(out) > limit {
		hasMore = true
		out = out[:limit]
	}
	rows.Close()
	// Threat and runtime rows retain their actual cluster. Violations already
	// join an exact tenant-owned deployment, so use its actual labels rather
	// than guessing an owner from a name that can span workload kinds.
	identities := []PlatformWorkloadIdentity{}
	indices := []int{}
	for i := range out {
		if out[i].Source == "audit" {
			continue
		}
		role := ""
		if out[i].Source == "network_violation" {
			role = PlatformRoleJSON(out[i].Namespace, out[i].roleLabels)
			out[i].PlatformRole = &role
			continue
		}
		cluster, _ := uuid.Parse(out[i].ClusterID)
		identities = append(identities, PlatformWorkloadIdentity{ClusterID: cluster, Workload: out[i].WorkloadID, Namespace: out[i].Namespace})
		indices = append(indices, i)
	}
	var roleQuery PlatformRoleQuerier = t.db.Pool()
	if tx != nil {
		roleQuery = tx
	}
	roles, err := EvidencePlatformRoles(r.Context(), roleQuery, subj.OrgID, identities)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i, index := range indices {
		out[index].PlatformRole = &roles[i]
	}
	if tx != nil {
		if err := tx.Commit(r.Context()); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if export {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="constellation-security-events.csv"`)
		w.Header().Set("X-Export-Total", strconv.Itoa(*total))
		w.Header().Set("X-Export-Limit", strconv.Itoa(limit))
		w.Header().Set("X-Export-Truncated", strconv.FormatBool(*total > limit))
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"id", "source", "cluster_id", "at", "severity", "verdict", "title", "namespace", "workload_id", "reference", "platform_role"})
		for _, item := range out {
			role := ""
			if item.PlatformRole != nil {
				role = *item.PlatformRole
			}
			_ = writer.Write([]string{item.ID, item.Source, item.ClusterID, item.At.UTC().Format(time.RFC3339Nano), item.Severity, item.Verdict, item.Title, item.Namespace, item.WorkloadID, item.Ref, role})
		}
		writer.Flush()
		return
	}
	response := map[string]any{
		"items":           out,
		"limit":           limit,
		"offset":          offset,
		"has_more":        hasMore,
		"from":            from.UTC().Format(time.RFC3339Nano),
		"to":              to.UTC().Format(time.RFC3339Nano),
		"lower_only":      window.lowerOnly,
		"after_exclusive": window.exclusive,
	}
	if total != nil {
		response["total"] = *total
	}
	writeJSON(w, http.StatusOK, response)
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
