package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

type baselineInventoryFilters struct {
	Search       string `json:"q"`
	Namespace    string `json:"namespace"`
	Mode         string `json:"mode"`
	HidePlatform bool   `json:"hide_platform"`
}
type baselineInventoryOptions struct {
	inventorylist.Options
	ClusterID uuid.UUID
	baselineInventoryFilters
}
type baselineInventoryRow struct {
	baselineSummaryDTO
	RowID          string `json:"row_id"`
	OwnerCount     int    `json:"owner_count"`
	OwnerAmbiguous bool   `json:"owner_ambiguous"`
	PlatformRole   string `json:"platform_role"`
	Configured     bool   `json:"configured"`
	RuleCount      int    `json:"rule_count"`
}

var baselineInventorySorts = map[string]string{"workload": "lower(workload_id)", "namespace": "lower(namespace)", "mode": "mode", "processes": "learned_processes_count", "alerts": "monitored_alerts_24h", "blocks": "enforced_blocks_24h", "rules": "rule_count", "last_new": "last_new_process_at", "learn_started": "learn_started_at"}

func parseBaselineInventory(values url.Values) (baselineInventoryOptions, error) {
	o := baselineInventoryOptions{}
	for _, entries := range values {
		if len(entries) != 1 {
			return o, fmt.Errorf("duplicate query parameter")
		}
	}
	raw := values.Get("cluster_id")
	if raw == "" {
		return o, fmt.Errorf("cluster_id is required")
	}
	cluster, err := uuid.Parse(raw)
	if err != nil {
		return o, fmt.Errorf("invalid cluster_id")
	}
	o.ClusterID = cluster
	o.Options, err = inventorylist.Parse(values, baselineInventorySorts, "workload")
	if err != nil {
		return o, err
	}
	if !values.Has("order") {
		o.Order = "asc"
	}
	for key, target := range map[string]*int{"limit": &o.Limit, "offset": &o.Offset} {
		if values.Has(key) {
			n, e := strconv.Atoi(values.Get(key))
			if e != nil || n < 0 || key == "limit" && (n < 1 || n > 500) || key == "offset" && n > inventorylist.MaxOffset {
				return o, fmt.Errorf("invalid %s", key)
			}
			*target = n
		}
	}
	o.OrderSQL = baselineInventorySorts[o.Sort] + " " + strings.ToUpper(o.Order) + " NULLS LAST,id ASC"
	o.Search = strings.ToLower(strings.TrimSpace(values.Get("q")))
	o.Namespace = strings.TrimSpace(values.Get("namespace"))
	o.Mode, err = inventorylist.Filter(values, "mode", "learn", "monitor", "enforce")
	if err != nil {
		return o, err
	}
	switch values.Get("hide_platform") {
	case "", "false":
	case "true":
		o.HidePlatform = true
	default:
		return o, fmt.Errorf("invalid hide_platform")
	}
	return o, nil
}

// One shared namespace/name profile survives duplicate deployment kinds. Saved
// state and authored-rule-only profiles remain visible even after inventory loss.
const baselineKeysSQL = `WITH owners AS (
 SELECT d.cluster_id,d.namespace||'/'||d.name AS workload_id,d.namespace,d.name,COUNT(*)::int AS owner_count,
 CASE WHEN COUNT(*)=1 THEN min(d.id::text)::uuid ELSE NULL END AS owner_id
 FROM deployments d JOIN clusters c ON c.id=d.cluster_id AND c.org_id=d.org_id
 WHERE d.org_id=$1 AND d.cluster_id=$2 GROUP BY d.cluster_id,d.namespace,d.name
), keys AS (
 SELECT cluster_id,workload_id FROM owners
 UNION SELECT cluster_id,workload_id FROM process_baseline_states WHERE org_id=$1 AND cluster_id=$2
 UNION SELECT cluster_id,workload_id FROM process_profile_rules WHERE org_id=$1 AND cluster_id=$2
), profiles AS (
 SELECT k.cluster_id,k.workload_id,COALESCE(o.namespace,s.namespace,CASE WHEN strpos(k.workload_id,'/')>0 THEN split_part(k.workload_id,'/',1) ELSE '' END) AS namespace,
 COALESCE(o.name,s.name,CASE WHEN strpos(k.workload_id,'/')>0 THEN substr(k.workload_id,strpos(k.workload_id,'/')+1) ELSE k.workload_id END) AS name,
 COALESCE(o.owner_count,0) AS owner_count,o.owner_id,COALESCE(s.mode,'learn') AS mode,s.id IS NOT NULL AS configured,s.learn_started_at,s.monitor_started_at,s.enforce_started_at
 FROM keys k LEFT JOIN owners o USING(cluster_id,workload_id)
 LEFT JOIN process_baseline_states s ON s.org_id=$1 AND s.cluster_id=k.cluster_id AND s.workload_id=k.workload_id
)`

func baselineInventorySQL() string { return baselineInventorySQLWithKeys(baselineKeysSQL) }
func baselineInventorySQLWithKeys(keys string) string {
	role := handler.EvidencePlatformRoleSQL("$1", "p.cluster_id", "p.workload_id", "p.namespace")
	sql := keys + `, refs AS (
 SELECT cluster_id,workload_id,workload_id AS observed_workload FROM profiles
 UNION SELECT p.cluster_id,p.workload_id,l.pod_workload_id FROM profiles p
 JOIN pod_workload_links l ON l.org_id=$1 AND l.cluster_id=p.cluster_id AND l.namespace=p.namespace AND l.deployment_id=p.owner_id AND l.owner_workload_id=p.workload_id
 WHERE p.owner_count=1 AND l.pod_workload_id<>''
), evidence AS (
 SELECT refs.workload_id,e.id AS event_id,e.verdict,e.severity,e.at,
 CASE WHEN jsonb_typeof(payload->'exe_sha256')='string' THEN btrim(payload->>'exe_sha256') ELSE '' END AS sha256,
 CASE WHEN jsonb_typeof(payload->'parent_name')='string' THEN btrim(payload->>'parent_name') ELSE '' END AS parent_name,
 CASE WHEN jsonb_typeof(payload->'comm')='string' AND payload->>'comm'<>'' THEN btrim(payload->>'comm') WHEN jsonb_typeof(payload->'filename')='string' THEN btrim(regexp_replace(payload->>'filename','^.*/','')) ELSE '' END AS process_name,
 CASE WHEN jsonb_typeof(payload->'exe_path')='string' AND btrim(payload->>'exe_path')<>'' THEN btrim(payload->>'exe_path') WHEN jsonb_typeof(payload->'filename')='string' THEN btrim(payload->>'filename') ELSE '' END AS process_path
 FROM refs JOIN events e ON e.org_id=$1 AND e.cluster_id=refs.cluster_id AND e.workload_id=refs.observed_workload AND e.kind='process_exec'
), process_counts AS (
 SELECT workload_id,process_name,process_path,count(*) AS observations,min(at) AS first_seen,max(at) AS last_seen FROM evidence WHERE process_name<>'' GROUP BY workload_id,process_name,process_path
), activity AS (
 SELECT workload_id,COUNT(*) FILTER(WHERE at>NOW()-INTERVAL '24 hours' AND (severity IN ('high','critical') OR verdict='alert'))::bigint AS alerts,
 COUNT(*) FILTER(WHERE at>NOW()-INTERVAL '24 hours' AND verdict IN ('block','deny'))::bigint AS blocks FROM evidence GROUP BY workload_id
), learned AS (
 SELECT workload_id,count(*)::bigint AS processes,max(first_seen) AS last_new,
 (array_agg(process_name ORDER BY observations DESC,process_name,process_path))[1:5] AS top_processes FROM process_counts GROUP BY workload_id
), rules AS (SELECT workload_id,count(*)::bigint AS rules FROM process_profile_rules WHERE org_id=$1 AND cluster_id=$2 GROUP BY workload_id), inventory AS (
 SELECT jsonb_build_array(p.cluster_id,p.workload_id)::text AS id,p.cluster_id,p.workload_id,p.namespace,p.name,p.mode,p.owner_count,p.owner_count>1 AS owner_ambiguous,` + role + ` AS platform_role,p.configured,
 COALESCE(l.processes,0) AS learned_processes_count,COALESCE(a.alerts,0) AS monitored_alerts_24h,COALESCE(a.blocks,0) AS enforced_blocks_24h,COALESCE(r.rules,0) AS rule_count,p.learn_started_at,p.monitor_started_at,p.enforce_started_at,l.last_new AS last_new_process_at,COALESCE(l.top_processes,'{}') AS top_processes
 FROM profiles p LEFT JOIN learned l USING(workload_id) LEFT JOIN activity a USING(workload_id) LEFT JOIN rules r USING(workload_id)
) `
	// Match Go strings.TrimSpace used by existing observation matching, including
	// Unicode whitespace in legacy process metadata.
	whitespace := "' \t\r\n\v\f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000'"
	for _, field := range []string{"comm", "filename", "exe_path", "exe_sha256", "parent_name"} {
		sql = strings.ReplaceAll(sql, "btrim(payload->>'"+field+"')", "btrim(payload->>'"+field+"',"+whitespace+")")
	}
	sql = strings.ReplaceAll(sql, "btrim(regexp_replace(payload->>'filename','^.*/',''))", "btrim(regexp_replace(payload->>'filename','^.*/',''),"+whitespace+")")
	return sql

}

const baselineInventoryWhere = `($3::text='' OR strpos(lower(concat_ws(' ',workload_id,namespace,name)),$3)>0) AND ($4::text='' OR namespace=$4) AND ($5::text='' OR mode=$5) AND (NOT $6::boolean OR platform_role<>'core')`
const baselineInventorySummary = `jsonb_build_object('total',count(*),'learn',count(*) FILTER(WHERE mode='learn'),'monitor',count(*) FILTER(WHERE mode='monitor'),'enforce',count(*) FILTER(WHERE mode='enforce'),'processes',COALESCE(sum(learned_processes_count),0),'alerts_24h',COALESCE(sum(monitored_alerts_24h),0),'blocks_24h',COALESCE(sum(enforced_blocks_24h),0),'rules',COALESCE(sum(rule_count),0),'ambiguous_owners',count(*) FILTER(WHERE owner_ambiguous))`

func scanBaselineInventory(row inventorylist.Row) (baselineInventoryRow, error) {
	var p baselineInventoryRow
	var cluster uuid.UUID
	var learn, monitor, enforce, last *time.Time
	err := row.Scan(&p.RowID, &cluster, &p.WorkloadID, &p.Namespace, &p.Name, &p.Mode, &p.OwnerCount, &p.OwnerAmbiguous, &p.PlatformRole, &p.Configured, &p.LearnedProcessesCount, &p.MonitoredAlerts24h, &p.EnforcedBlocks24h, &p.RuleCount, &learn, &monitor, &enforce, &last, &p.TopProcesses)
	p.ClusterID = cluster.String()
	if learn != nil {
		p.LearnStartedAt = learn.UTC().Format(time.RFC3339Nano)
	}
	if monitor != nil {
		p.MonitorStartedAt = monitor.UTC().Format(time.RFC3339Nano)
	}
	if enforce != nil {
		p.EnforceStartedAt = enforce.UTC().Format(time.RFC3339Nano)
	}
	if last != nil {
		p.LastNewProcessAt = last.UTC().Format(time.RFC3339Nano)
	}
	return p, err
}
func (h *Baselines) Inventory(w http.ResponseWriter, r *http.Request) {
	h.baselineInventory(w, r, false)
}
func (h *Baselines) InventoryCSV(w http.ResponseWriter, r *http.Request) {
	h.baselineInventory(w, r, true)
}
func (h *Baselines) baselineInventory(w http.ResponseWriter, r *http.Request, export bool) {
	subject, ok := authctx.SubjectFrom(r.Context())
	if !ok || subject.OrgID == uuid.Nil {
		jsonError(w, 401, "subject required")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		jsonError(w, 400, "invalid query")
		return
	}
	o, err := parseBaselineInventory(values)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	var owned bool
	if err = h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, o.ClusterID, subject.OrgID).Scan(&owned); err != nil {
		jsonError(w, 500, "process profile inventory unavailable")
		return
	}
	if !owned {
		jsonError(w, 404, "cluster not found")
		return
	}
	items, meta, namespaces, err := h.readBaselineInventory(r.Context(), subject.OrgID, o, export)
	if err != nil {
		jsonError(w, 500, "process profile inventory unavailable")
		return
	}
	if export {
		body, err := baselineInventoryCSV(items)
		if err != nil {
			jsonError(w, 500, "process profile export unavailable")
			return
		}
		inventorylist.WriteCSV(w, "process-baselines.csv", body, meta)
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"profiles": items, "total": meta.Total, "summary": meta.Summary, "has_more": meta.HasMore, "limit": o.Limit, "offset": o.Offset, "sort": o.Sort, "order": o.Order, "cluster_id": o.ClusterID, "filters": o.baselineInventoryFilters, "namespaces": namespaces, "source_complete": true, "summary_scope": "matching_retained_process_events"})
}
func (h *Baselines) readBaselineInventory(ctx context.Context, org uuid.UUID, o baselineInventoryOptions, export bool) ([]baselineInventoryRow, inventorylist.Metadata, []string, error) {
	items := []baselineInventoryRow{}
	meta := inventorylist.Metadata{}
	namespaces := []string{}
	tx, err := h.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return items, meta, namespaces, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	args := []any{org, o.ClusterID, o.Search, o.Namespace, o.Mode, o.HidePlatform}
	sql := baselineInventorySQL()
	var summary []byte
	if err = tx.QueryRow(ctx, sql+`SELECT count(*),`+baselineInventorySummary+` FROM inventory WHERE `+baselineInventoryWhere, args...).Scan(&meta.Total, &summary); err != nil {
		return items, meta, namespaces, err
	}
	if err = json.Unmarshal(summary, &meta.Summary); err != nil {
		return items, meta, namespaces, err
	}
	rows, err := tx.Query(ctx, baselineKeysSQL+` SELECT DISTINCT namespace FROM profiles ORDER BY namespace`, org, o.ClusterID)
	if err != nil {
		return items, meta, namespaces, err
	}
	for rows.Next() {
		var ns string
		if err = rows.Scan(&ns); err != nil {
			rows.Close()
			return items, meta, namespaces, err
		}
		namespaces = append(namespaces, ns)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return items, meta, namespaces, err
	}
	if export {
		o.Limit = inventorylist.ExportLimit
		o.Offset = 0
	}
	rows, err = tx.Query(ctx, sql+`SELECT * FROM inventory WHERE `+baselineInventoryWhere+` ORDER BY `+o.OrderSQL+` LIMIT $7 OFFSET $8`, append(args, o.Limit, o.Offset)...)
	if err != nil {
		return items, meta, namespaces, err
	}
	for rows.Next() {
		var item baselineInventoryRow
		item, err = scanBaselineInventory(rows)
		if err != nil {
			rows.Close()
			return items, meta, namespaces, err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return items, meta, namespaces, err
	}
	if err = tx.Commit(ctx); err != nil {
		return items, meta, namespaces, err
	}
	meta.HasMore = int64(o.Offset)+int64(len(items)) < meta.Total
	return items, meta, namespaces, nil
}
