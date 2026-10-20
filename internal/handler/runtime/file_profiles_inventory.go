package runtime

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
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

type fileProfileInventoryRow struct {
	fileProfileSummaryDTO
	RowID          string `json:"row_id"`
	OwnerCount     int    `json:"owner_count"`
	OwnerAmbiguous bool   `json:"owner_ambiguous"`
	PlatformRole   string `json:"platform_role"`
	RetainedEvents int    `json:"retained_events"`
	LastObservedAt string `json:"last_observed_at"`
}

// Shared profiles are keyed by namespace/name, not Kubernetes kind. Only a
// single exact owner can contribute pod-linked evidence; ambiguous owners
// retain canonical-name events without borrowing one kind's pods or labels.
func fileInventorySQL() string {
	return `WITH deployment_profiles AS (
 SELECT d.cluster_id,d.namespace,d.name,d.namespace||'/'||d.name workload_id,count(*)::int owner_count
 FROM deployments d JOIN clusters c ON c.id=d.cluster_id AND c.org_id=d.org_id
 WHERE d.org_id=$1 AND d.cluster_id=$2 GROUP BY d.cluster_id,d.namespace,d.name
), profile_keys AS (
 SELECT cluster_id,workload_id,namespace,name,owner_count FROM deployment_profiles
 UNION ALL SELECT s.cluster_id,s.workload_id,s.namespace,s.name,0 FROM file_profile_states s JOIN clusters c ON c.id=s.cluster_id AND c.org_id=s.org_id WHERE s.org_id=$1 AND s.cluster_id=$2
 UNION ALL SELECT r.cluster_id,r.workload_id,split_part(r.workload_id,'/',1),substr(r.workload_id,strpos(r.workload_id,'/')+1),0 FROM file_profile_rules r JOIN clusters c ON c.id=r.cluster_id AND c.org_id=r.org_id WHERE r.org_id=$1 AND r.cluster_id=$2
), profiles AS (
 SELECT k.cluster_id,k.workload_id,coalesce(max(dp.namespace),split_part(k.workload_id,'/',1)) namespace,coalesce(max(dp.name),substr(k.workload_id,strpos(k.workload_id,'/')+1)) name,max(k.owner_count) owner_count FROM profile_keys k LEFT JOIN deployment_profiles dp ON dp.cluster_id=k.cluster_id AND dp.workload_id=k.workload_id GROUP BY k.cluster_id,k.workload_id
), refs AS (
 SELECT cluster_id,workload_id,workload_id ref FROM profiles
 UNION SELECT p.cluster_id,p.workload_id,l.pod_workload_id FROM profiles p
 JOIN pod_workload_links l ON l.org_id=$1 AND l.cluster_id=p.cluster_id AND l.owner_workload_id=p.workload_id AND l.namespace=p.namespace AND l.pod_workload_id<>''
 JOIN deployments d ON d.id=l.deployment_id AND d.org_id=l.org_id AND d.cluster_id=l.cluster_id AND d.namespace=p.namespace AND d.name=p.name
 WHERE p.owner_count=1
), evidence AS (
 SELECT r.cluster_id,r.workload_id,e.at,e.severity,e.verdict,
 CASE WHEN jsonb_typeof(e.payload->'path')='string' THEN btrim(e.payload->>'path') ELSE '' END path,
 CASE WHEN jsonb_typeof(e.payload->'comm')='string' THEN btrim(e.payload->>'comm') ELSE '' END comm
 FROM refs r JOIN events e ON e.org_id=$1 AND e.cluster_id=r.cluster_id AND e.workload_id=r.ref AND e.kind='file_open'
), activity AS (
 SELECT cluster_id,workload_id,count(*)::int retained_events,max(at) last_observed,
 count(*) FILTER(WHERE at>transaction_timestamp()-interval '24 hours' AND (severity IN('high','critical') OR verdict='alert'))::int alerts,
 count(*) FILTER(WHERE at>transaction_timestamp()-interval '24 hours' AND verdict IN('block','deny'))::int blocks
 FROM evidence GROUP BY cluster_id,workload_id
), paths AS (
 SELECT cluster_id,workload_id,path,comm,min(at) first_seen FROM evidence WHERE path<>'' GROUP BY cluster_id,workload_id,path,comm
), path_summary AS (
 SELECT cluster_id,workload_id,count(*)::int paths,count(*) FILTER(WHERE path LIKE ANY(ARRAY['/etc/shadow%','/etc/passwd%','/etc/sudoers%','/etc/kubernetes%','/root/.ssh%','/home%','/run/secrets%','/var/lib/kubelet/pki%','/var/run/secrets/kubernetes.io%','/var/run/secrets/eks.amazonaws.com%']))::int sensitive,max(first_seen) last_new
 FROM paths GROUP BY cluster_id,workload_id
), rules AS (SELECT cluster_id,workload_id,count(*)::int n FROM file_profile_rules WHERE org_id=$1 AND cluster_id=$2 GROUP BY cluster_id,workload_id),
 watches AS (SELECT cluster_id,workload_id,count(*)::int n FROM file_profile_watch_inventory WHERE org_id=$1 AND cluster_id=$2 GROUP BY cluster_id,workload_id)
 SELECT jsonb_build_array(p.cluster_id,p.workload_id)::text,p.cluster_id::text,p.workload_id,p.namespace,p.name,coalesce(s.mode,'learn'),p.owner_count,p.owner_count>1,
 ` + handler.EvidencePlatformRoleSQL("$1::uuid", "p.cluster_id", "p.workload_id", "p.namespace") + `,
 coalesce(ps.paths,0),coalesce(ps.sensitive,0),coalesce(r.n,0),coalesce(w.n,0),coalesce(a.alerts,0),coalesce(a.blocks,0),coalesce(a.retained_events,0),
 s.learn_started_at,s.monitor_started_at,s.enforce_started_at,ps.last_new,a.last_observed
 FROM profiles p LEFT JOIN file_profile_states s ON s.org_id=$1 AND s.cluster_id=p.cluster_id AND s.workload_id=p.workload_id
 LEFT JOIN activity a ON a.cluster_id=p.cluster_id AND a.workload_id=p.workload_id
 LEFT JOIN path_summary ps ON ps.cluster_id=p.cluster_id AND ps.workload_id=p.workload_id
 LEFT JOIN rules r ON r.cluster_id=p.cluster_id AND r.workload_id=p.workload_id
 LEFT JOIN watches w ON w.cluster_id=p.cluster_id AND w.workload_id=p.workload_id`
}

const fileInventoryColumns = "id,cluster_id,workload_id,namespace,name,mode,owner_count,owner_ambiguous,platform_role,learned_paths_count,sensitive_path_count,rule_count,watched_file_count,monitored_alerts_24h,enforced_blocks_24h,retained_events,learn_started_at,monitor_started_at,enforce_started_at,last_new_path_at,last_observed_at"

func scanFileInventory(row inventorylist.Row) (fileProfileInventoryRow, error) {
	var p fileProfileInventoryRow
	var learn, monitor, enforce, lastNew, last *time.Time
	err := row.Scan(&p.RowID, &p.ClusterID, &p.WorkloadID, &p.Namespace, &p.Name, &p.Mode, &p.OwnerCount, &p.OwnerAmbiguous, &p.PlatformRole, &p.LearnedPathsCount, &p.SensitivePathCount, &p.RuleCount, &p.WatchedFileCount, &p.MonitoredAlerts24h, &p.EnforcedBlocks24h, &p.RetainedEvents, &learn, &monitor, &enforce, &lastNew, &last)
	format := func(v *time.Time) string {
		if v == nil {
			return ""
		}
		return v.UTC().Format(time.RFC3339Nano)
	}
	p.LearnStartedAt = format(learn)
	p.MonitorStartedAt = format(monitor)
	p.EnforceStartedAt = format(enforce)
	p.LastNewPathAt = format(lastNew)
	p.LastObservedAt = format(last)
	p.TopPaths = []string{}
	return p, err
}
func (h *FileProfiles) Inventory(w http.ResponseWriter, r *http.Request) {
	h.writeFileInventory(w, r, false)
}
func (h *FileProfiles) InventoryCSV(w http.ResponseWriter, r *http.Request) {
	h.writeFileInventory(w, r, true)
}
func (h *FileProfiles) writeFileInventory(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "subject required")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		jsonError(w, 400, "invalid query")
		return
	}
	for key, items := range values {
		if len(items) != 1 {
			jsonError(w, 400, "duplicate "+key)
			return
		}
	}
	cluster, err := uuid.Parse(values.Get("cluster_id"))
	if err != nil {
		jsonError(w, 400, "cluster_id required")
		return
	}
	options, err := inventorylist.Parse(values, map[string]string{"workload": "workload_id", "namespace": "(namespace,workload_id)", "mode": "mode", "rules": "rule_count", "paths": "learned_paths_count", "alerts": "monitored_alerts_24h", "blocks": "enforced_blocks_24h", "last_observed": "last_observed_at"}, "workload")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	for _, key := range []string{"limit", "offset"} {
		if raw, present := values[key]; present {
			value := raw[0]
			n, e := strconv.Atoi(value)
			if e != nil || n < 0 || key == "limit" && (n < 1 || n > 2000) || key == "offset" && n > inventorylist.MaxOffset {
				jsonError(w, 400, "invalid "+key)
				return
			}
			if key == "limit" {
				options.Limit = n
			} else {
				options.Offset = n
			}
		}
	}
	mode, err := inventorylist.Filter(values, "mode", "learn", "monitor", "enforce")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	role, err := inventorylist.Filter(values, "platform_role", "core", "unknown")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	hide := false
	switch values.Get("hide_platform") {
	case "", "false", "0":
	case "true", "1":
		hide = true
	default:
		jsonError(w, 400, "invalid hide_platform")
		return
	}
	q, namespace := strings.TrimSpace(values.Get("q")), strings.TrimSpace(values.Get("namespace"))
	filters := map[string]any{"q": q, "namespace": namespace, "mode": mode, "platform_role": role, "hide_platform": hide}
	tx, err := h.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		jsonError(w, 500, "inventory unavailable")
		return
	}
	defer tx.Rollback(context.WithoutCancel(r.Context()))
	var owned bool
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, subj.OrgID, cluster).Scan(&owned); err != nil {
		jsonError(w, 500, "cluster scope unavailable")
		return
	}
	if !owned {
		jsonError(w, 404, "cluster not found")
		return
	}
	prefix := "WITH inventory(" + fileInventoryColumns + ") AS (" + fileInventorySQL() + ") "
	where := `($3='' OR strpos(lower(workload_id),lower($3))>0) AND ($4='' OR namespace=$4) AND ($5='' OR mode=$5) AND (NOT $6 OR platform_role<>'core') AND ($7='' OR ($7='unknown' AND platform_role='') OR platform_role=$7)`
	args := []any{subj.OrgID, cluster, q, namespace, mode, hide, role}
	meta := inventorylist.Metadata{}
	var summary []byte
	if err = tx.QueryRow(r.Context(), prefix+`SELECT count(*),json_build_object('total',count(*),'learn',count(*) FILTER(WHERE mode='learn'),'monitor',count(*) FILTER(WHERE mode='monitor'),'enforce',count(*) FILTER(WHERE mode='enforce'),'rules',coalesce(sum(rule_count),0),'alerts',coalesce(sum(monitored_alerts_24h),0),'blocks',coalesce(sum(enforced_blocks_24h),0),'retained_events',coalesce(sum(retained_events),0),'ambiguous',count(*) FILTER(WHERE owner_ambiguous)) FROM inventory WHERE `+where, args...).Scan(&meta.Total, &summary); err != nil {
		jsonError(w, 500, "file profile inventory unavailable")
		return
	}
	if err = json.Unmarshal(summary, &meta.Summary); err != nil {
		jsonError(w, 500, "inventory totals unavailable")
		return
	}
	namespaces := []string{}
	facets, err := tx.Query(r.Context(), fileInventorySQL()[:strings.Index(fileInventorySQL(), "), refs AS (")]+") SELECT DISTINCT namespace FROM profiles ORDER BY namespace", args[:2]...)
	if err != nil {
		jsonError(w, 500, "namespace scope unavailable")
		return
	}
	for facets.Next() {
		var ns string
		if err = facets.Scan(&ns); err != nil {
			facets.Close()
			jsonError(w, 500, "namespace scope unavailable")
			return
		}
		namespaces = append(namespaces, ns)
	}
	err = facets.Err()
	facets.Close()
	if err != nil {
		jsonError(w, 500, "namespace scope unavailable")
		return
	}
	limit, offset := options.Limit, options.Offset
	if export {
		limit = inventorylist.ExportLimit
		offset = 0
	}
	queryArgs := append(append([]any{}, args...), limit, offset)
	rows, err := tx.Query(r.Context(), prefix+`SELECT * FROM inventory WHERE `+where+` ORDER BY `+options.OrderSQL+` LIMIT $8 OFFSET $9`, queryArgs...)
	if err != nil {
		jsonError(w, 500, "inventory rows unavailable")
		return
	}
	profiles := []fileProfileInventoryRow{}
	for rows.Next() {
		p, e := scanFileInventory(rows)
		if e != nil {
			rows.Close()
			jsonError(w, 500, "inventory rows unavailable")
			return
		}
		profiles = append(profiles, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		jsonError(w, 500, "inventory rows unavailable")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		jsonError(w, 500, "inventory snapshot unavailable")
		return
	}
	meta.HasMore = int64(offset+len(profiles)) < meta.Total
	if export {
		var buf bytes.Buffer
		writer := csv.NewWriter(&buf)
		headers := strings.Split(fileInventoryColumns, ",")
		headers[0] = "row_id"
		_ = writer.Write(headers)
		for _, p := range profiles {
			_ = writer.Write([]string{p.RowID, p.ClusterID, p.WorkloadID, p.Namespace, p.Name, p.Mode, strconv.Itoa(p.OwnerCount), strconv.FormatBool(p.OwnerAmbiguous), p.PlatformRole, strconv.Itoa(p.LearnedPathsCount), strconv.Itoa(p.SensitivePathCount), strconv.Itoa(p.RuleCount), strconv.Itoa(p.WatchedFileCount), strconv.Itoa(p.MonitoredAlerts24h), strconv.Itoa(p.EnforcedBlocks24h), strconv.Itoa(p.RetainedEvents), p.LearnStartedAt, p.MonitorStartedAt, p.EnforceStartedAt, p.LastNewPathAt, p.LastObservedAt})
		}
		writer.Flush()
		if writer.Error() != nil {
			jsonError(w, 500, "inventory export unavailable")
			return
		}
		inventorylist.WriteCSV(w, "file-monitor-profiles.csv", buf.Bytes(), meta)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"profiles": profiles, "total": meta.Total, "limit": options.Limit, "offset": options.Offset, "has_more": meta.HasMore, "summary": meta.Summary, "sort": options.Sort, "order": options.Order, "org_id": subj.OrgID, "cluster_id": cluster, "filters": filters, "namespaces": namespaces, "source": "retained_file_events", "source_complete": true, "summary_scope": "matching_shared_profiles"})
}
