package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/google/uuid"
)

// Only running entries from the latest per-node snapshots are inventory rows.
// Pod-prefix risk attribution is advisory. Platform labels require one exact pod owner.
// Fact flags report key presence, not values.
const containerInventorySQL = `
WITH conts AS (
 SELECT hc.node,COALESCE(item->>'id','') AS id,COALESCE(item->>'name','') AS name,
 COALESCE(item->>'pod_namespace','') AS namespace,COALESCE(item->>'pod_name','') AS pod_name,
 COALESCE(NULLIF(item->>'image_ref',''),item->>'image','') AS image,COALESCE(item->>'state','') AS state,hc.observed_at,
 jsonb_build_array(hc.cluster_id::text,hc.node,COALESCE(item->>'id',''),ordinal)::text AS row_id
 FROM host_containers hc
 CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(hc.payload->'items')='array' THEN hc.payload->'items' ELSE '[]'::jsonb END) WITH ORDINALITY entry(item,ordinal)
 WHERE hc.org_id=$1 AND hc.cluster_id=$2 AND COALESCE(item->>'state','') IN('CONTAINER_RUNNING','running')
)
SELECT c.row_id,c.node,c.id,c.name,c.namespace,c.pod_name,COALESCE(named.image_ref,c.image) AS image,c.state,
 COALESCE(d.name,'') AS workload,COALESCE(d.risk_factors ? 'privileged',false) AS privileged,
 COALESCE(d.risk_factors ? 'run_as_root',false) AS run_as_root,COALESCE(d.risk_score,0) AS risk_score,
 COALESCE(d.critical_count,0) AS critical,COALESCE(d.high_count,0) AS high,
 CASE WHEN strpos(c.pod_name,':')>0 OR c.pod_name ~ '^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$' THEN '' ELSE {{platform}} END AS platform_role,c.observed_at
 FROM conts c
 LEFT JOIN LATERAL (
 SELECT dd.name,dd.risk_factors,dd.risk_score,dd.critical_count,dd.high_count
 FROM deployments dd WHERE dd.org_id=$1 AND dd.cluster_id=$2 AND dd.namespace=c.namespace AND c.pod_name LIKE dd.name||'-%'
 ORDER BY length(dd.name) DESC,dd.id ASC LIMIT 1
 ) d ON true
 LEFT JOIN LATERAL (
 SELECT labels FROM (
 SELECT owners.*,count(*) OVER () AS matches FROM (
 SELECT DISTINCT role_d.id,role_d.labels
 FROM pod_workload_links p
 JOIN deployments role_d ON role_d.id=p.deployment_id AND role_d.org_id=$1 AND role_d.cluster_id=$2 AND role_d.namespace=c.namespace
 WHERE p.org_id=$1 AND p.cluster_id=$2 AND p.namespace=c.namespace
 AND p.pod_workload_id=c.namespace||'/pod/'||c.pod_name
 ) owners
 ) resolved WHERE matches=1
 ) exact_owner ON true
 LEFT JOIN LATERAL (
 SELECT iwl.image_ref FROM image_workload_links iwl
 WHERE iwl.org_id=$1 AND iwl.cluster_id=$2 AND iwl.namespace=c.namespace AND iwl.image_ref !~ '^sha256:' AND iwl.image_digest=c.image
 ORDER BY iwl.last_seen_at DESC,length(iwl.image_ref),iwl.image_ref,iwl.id ASC LIMIT 1
 ) named ON true`

func containerInventoryDefinition(r *http.Request, org, cluster uuid.UUID) (inventorylist.Definition, inventorylist.Options, error) {
	values, err := inventorylist.Query(r)
	if err != nil {
		return inventorylist.Definition{}, inventorylist.Options{}, err
	}
	o, err := inventorylist.Parse(values, map[string]string{"name": "lower(name)", "pod": "lower(namespace||'/'||pod_name)", "image": "lower(image)", "node": "lower(node)", "risk": "ROW(critical,high,risk_score)", "state": "lower(replace(state,'CONTAINER_',''))", "observed": "observed_at"}, "risk")
	if err != nil {
		return inventorylist.Definition{}, o, err
	}
	o.OrderSQL += ", row_id ASC"
	role, err := inventorylist.Filter(values, "platform_role", "core", "none")
	if err != nil {
		return inventorylist.Definition{}, o, err
	}
	hide := false
	if raw := values.Get("hide_platform"); raw != "" {
		hide, err = strconv.ParseBool(raw)
		if err != nil {
			return inventorylist.Definition{}, o, fmt.Errorf("invalid hide_platform")
		}
	}
	args := []any{org, cluster}
	parts := []string{"true"}
	bind := func(value any) string { args = append(args, value); return "$" + strconv.Itoa(len(args)) }
	if q := strings.TrimSpace(values.Get("q")); q != "" {
		parts = append(parts, "strpos(lower(concat_ws(' ',id,name,namespace,pod_name,image,node,workload)),lower("+bind(q)+"::text))>0")
	}
	for _, key := range []string{"namespace", "node"} {
		if value := strings.TrimSpace(values.Get(key)); value != "" {
			parts = append(parts, key+"="+bind(value))
		}
	}
	if role == "core" {
		parts = append(parts, "platform_role='core'")
	} else if role == "none" {
		parts = append(parts, "platform_role=''")
	}
	sql := "WITH enriched AS (" + strings.ReplaceAll(containerInventorySQL, "{{platform}}", platformRoleSQL("c.namespace", "COALESCE(exact_owner.labels,'{}'::jsonb)")) + ") SELECT * FROM enriched WHERE " + strings.Join(parts, " AND ")
	where := "true"
	if hide {
		where = "platform_role=''"
	}
	return inventorylist.Definition{SQL: sql, Columns: "row_id,node,id,name,namespace,pod_name,image,state,workload,privileged,run_as_root,risk_score,critical,high,platform_role,observed_at", Args: args, Where: where, Summary: `jsonb_build_object('total',count(*),'running',count(*),'privileged',count(*) FILTER(WHERE privileged),'run_as_root',count(*) FILTER(WHERE run_as_root),'platform_count',(SELECT count(*) FROM inventory WHERE platform_role='core'))`}, o, nil
}

func scanContainerInventory(row inventorylist.Row) (containerRow, error) {
	var c containerRow
	err := row.Scan(&c.RowID, &c.Node, &c.ID, &c.Name, &c.Namespace, &c.PodName, &c.Image, &c.State, &c.Workload, &c.Privileged, &c.RunAsRoot, &c.RiskScore, &c.Critical, &c.High, &c.PlatformRole, &c.ObservedAt)
	return c, err
}
func (h *Nodes) Containers(w http.ResponseWriter, r *http.Request) {
	h.readContainerInventory(w, r, false)
}
func (h *Nodes) ContainersCSV(w http.ResponseWriter, r *http.Request) {
	h.readContainerInventory(w, r, true)
}
func (h *Nodes) readContainerInventory(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "subject required")
		return
	}
	cluster, ok := h.clusterIDFromRoute(w, r, subj.OrgID)
	if !ok {
		return
	}
	d, o, err := containerInventoryDefinition(r, subj.OrgID, cluster)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if export {
		body, meta, err := inventorylist.CSV(r.Context(), h.db.Pool(), d, o, scanContainerInventory, []string{"Row identity", "Cluster ID", "Container ID", "Container", "Namespace", "Platform role", "Pod", "Image", "Node", "State", "Advisory workload", "Privileged fact recorded", "Root fact recorded", "Workload risk", "Workload critical findings", "Workload high findings", "Observed at"}, func(c containerRow) []string {
			return []string{c.RowID, cluster.String(), c.ID, c.Name, c.Namespace, c.PlatformRole, c.PodName, c.Image, c.Node, c.State, c.Workload, strconv.FormatBool(c.Privileged), strconv.FormatBool(c.RunAsRoot), strconv.Itoa(c.RiskScore), strconv.Itoa(c.Critical), strconv.Itoa(c.High), c.ObservedAt.UTC().Format(time.RFC3339Nano)}
		})
		if err != nil {
			jsonError(w, 500, err.Error())
			return
		}
		inventorylist.WriteCSV(w, "constellation-running-containers.csv", body, meta)
		return
	}
	items, meta, err := inventorylist.Read(r.Context(), h.db.Pool(), d, o, scanContainerInventory)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"cluster_id": cluster.String(), "items": items, "summary": meta.Summary, "total": meta.Total, "limit": o.Limit, "offset": o.Offset, "sort": o.Sort, "order": o.Order, "has_more": meta.HasMore})
}
