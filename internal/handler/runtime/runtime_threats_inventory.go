package runtime

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/google/uuid"
)

func (h *RuntimeThreats) ListCSV(w http.ResponseWriter, r *http.Request) {
	h.threatInventory(w, r, true)
}
func (h *RuntimeThreats) threatInventory(w http.ResponseWriter, r *http.Request, csv bool) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "auth required")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		jsonError(w, 400, "invalid query")
		return
	}
	ints := map[string]int{"hours": 24, "severity_min": 0, "limit": 500, "offset": 0, "port": 0, "application": 0}
	bounds := map[string][2]int{"hours": {1, 720}, "severity_min": {0, 9}, "limit": {1, 2000}, "offset": {0, inventorylist.MaxOffset}, "port": {1, 65535}}
	for key, limits := range bounds {
		if raw := values.Get(key); raw != "" {
			n, e := strconv.Atoi(raw)
			if e != nil || n < limits[0] || n > limits[1] {
				jsonError(w, 400, "invalid "+key)
				return
			}
			ints[key] = n
		}
	}
	for key, entries := range values {
		if len(entries) != 1 {
			jsonError(w, 400, "duplicate "+key)
			return
		}
	}
	applicationFilter := strings.ToLower(strings.TrimSpace(values.Get("application")))
	applicationPorts := []int{}
	if applicationFilter != "" {
		if ports := handler.ApplicationFilterPorts(applicationFilter); len(ports) > 0 {
			applicationPorts = ports
		} else {
			n, e := strconv.Atoi(applicationFilter)
			if e != nil || n < 1 || n > 2147483647 {
				jsonError(w, 400, "invalid application")
				return
			}
			ints["application"] = n
		}
	}
	options, err := inventorylist.Parse(values, map[string]string{"at": "at", "reported": "reported_at", "severity": "severity", "action": "action", "workload": "lower(workload_id)", "category": "category", "node": "lower(node)", "signature": "threat_id"}, "at")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	options.Limit = ints["limit"]
	options.Offset = ints["offset"]
	clusterRaw := strings.TrimSpace(values.Get("cluster_id"))
	var cluster *uuid.UUID
	if clusterRaw != "" {
		id, e := uuid.Parse(clusterRaw)
		if e != nil {
			jsonError(w, 400, "invalid cluster_id")
			return
		}
		cluster = &id
		var owned bool
		if e = h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, sub.OrgID, id).Scan(&owned); e != nil {
			jsonError(w, 500, "threat scope unavailable")
			return
		}
		if !owned {
			jsonError(w, 404, "cluster not found")
			return
		}
	}
	category, err := inventorylist.Filter(values, "category", "ips", "dlp", "waf")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	hide := false
	if raw := values.Get("hide_platform"); raw != "" {
		if raw != "true" && raw != "false" {
			jsonError(w, 400, "invalid hide_platform")
			return
		}
		hide = raw == "true"
	}
	members, groupName, groupActive, err := handler.ResolveGroupFilterMembers(r.Context(), h.db.Pool(), sub.OrgID, cluster, values.Get("group"))
	if err != nil {
		jsonError(w, 400, "invalid group filter")
		return
	}
	workload, namespace, node := strings.TrimSpace(values.Get("workload_id")), strings.TrimSpace(values.Get("namespace")), strings.TrimSpace(values.Get("node"))
	peer, search := strings.ToLower(strings.TrimSpace(values.Get("peer"))), strings.ToLower(strings.TrimSpace(values.Get("q")))
	d := inventorylist.Definition{
		SQL: `SELECT t.id,t.org_id,t.cluster_id,COALESCE(t.node,''),COALESCE(t.ep_mac,''),COALESCE(t.workload_id,''),COALESCE(t.namespace,''),COALESCE(t.pod_name,''),t.threat_id,t.severity,t.action,COALESCE(t.application,0),COALESCE(t.msg,''),COALESCE(t.ip_proto,0::smallint),COALESCE(t.src_ip,''),COALESCE(t.src_port,0),COALESCE(t.dst_ip,''),COALESCE(t.dst_port,0),COALESCE(t.pkt_len,0),COALESCE(t.cap_len,0),t.pkt_ingress,t.sess_ingress,t.reported_at,t.at,
 CASE WHEN t.threat_id>=40000 AND t.threat_id<50000 THEN 'waf' WHEN t.threat_id>=20000 AND t.threat_id<40000 THEN 'dlp' ELSE 'ips' END,
 ` + handler.EvidencePlatformRoleSQL("t.org_id", "t.cluster_id", "t.workload_id", "t.namespace") + `
 FROM runtime_threats t JOIN clusters owned ON owned.id=t.cluster_id AND owned.org_id=t.org_id
 WHERE t.org_id=$1 AND t.at>=NOW()-($2::int*INTERVAL '1 hour') AND ($3::uuid IS NULL OR t.cluster_id=$3)`,
		Columns: "id,org_id,cluster_id,node,ep_mac,workload_id,namespace,pod_name,threat_id,severity,action,application,msg,ip_proto,src_ip,src_port,dst_ip,dst_port,pkt_len,cap_len,pkt_ingress,sess_ingress,reported_at,at,category,platform_role",
		Where:   `severity >= $4 AND ($5::text='' OR workload_id=$5) AND ($6::text='' OR category=$6) AND (NOT $7::boolean OR workload_id=ANY($8::text[])) AND ($9::int=0 OR src_port=$9 OR dst_port=$9) AND ($10::text='' OR strpos(lower(src_ip),$10)>0 OR strpos(lower(dst_ip),$10)>0) AND (($11::int=0 AND cardinality($16::int[])=0) OR ($11::int>0 AND application=$11) OR src_port=ANY($16::int[]) OR dst_port=ANY($16::int[])) AND ($12::text='' OR namespace=$12) AND ($13::text='' OR node=$13) AND (NOT $14::boolean OR platform_role<>'core') AND ($15::text='' OR strpos(lower(concat_ws(' ',id::text,threat_id::text,msg,node,workload_id,namespace,src_ip,dst_ip)),$15)>0)`,
		Args:    []any{sub.OrgID, ints["hours"], cluster, ints["severity_min"], workload, category, groupActive, members, ints["port"], peer, ints["application"], namespace, node, hide, search, applicationPorts},
		Summary: `json_build_object('total',count(*),'critical',count(*) FILTER(WHERE severity>=8),'blocked',count(*) FILTER(WHERE action IN (2,3,4)),'ips',count(*) FILTER(WHERE category='ips'),'dlp',count(*) FILTER(WHERE category='dlp'),'waf',count(*) FILTER(WHERE category='waf'),'workloads',count(DISTINCT (cluster_id,workload_id)) FILTER(WHERE workload_id<>''))`,
	}
	scan := func(row inventorylist.Row) (RuntimeThreatRow, error) {
		var t RuntimeThreatRow
		err := row.Scan(&t.ID, &t.OrgID, &t.ClusterID, &t.Node, &t.EPMAC, &t.WorkloadID, &t.Namespace, &t.PodName, &t.ThreatID, &t.Severity, &t.Action, &t.Application, &t.Msg, &t.IPProto, &t.SrcIP, &t.SrcPort, &t.DstIP, &t.DstPort, &t.PktLen, &t.CapLen, &t.PktIngress, &t.SessIngress, &t.ReportedAt, &t.At, &t.Category, &t.PlatformRole)
		t.ThreatName = resolveThreatName(uint32(t.ThreatID))
		return t, err
	}
	if csv {
		headers := []string{"id", "cluster_id", "node", "workload_id", "namespace", "pod_name", "platform_role", "threat_id", "threat_name", "category", "severity", "action", "application", "message", "protocol", "source_ip", "source_port", "destination_ip", "destination_port", "reported_at", "at"}
		body, meta, e := inventorylist.CSV(r.Context(), h.db.Pool(), d, options, scan, headers, func(t RuntimeThreatRow) []string {
			return []string{t.ID, t.ClusterID, t.Node, t.WorkloadID, t.Namespace, t.PodName, t.PlatformRole, fmt.Sprint(t.ThreatID), t.ThreatName, t.Category, fmt.Sprint(t.Severity), fmt.Sprint(t.Action), fmt.Sprint(t.Application), t.Msg, fmt.Sprint(t.IPProto), t.SrcIP, fmt.Sprint(t.SrcPort), t.DstIP, fmt.Sprint(t.DstPort), t.ReportedAt.Format(time.RFC3339Nano), t.At.Format(time.RFC3339Nano)}
		})
		if e != nil {
			jsonError(w, 500, "threat inventory unavailable")
			return
		}
		inventorylist.WriteCSV(w, "runtime-threats.csv", body, meta)
		return
	}
	items, meta, err := inventorylist.Read(r.Context(), h.db.Pool(), d, options, scan)
	if err != nil {
		jsonError(w, 500, "threat inventory unavailable")
		return
	}
	response := map[string]any{"threats": items, "total": meta.Total, "summary": meta.Summary, "limit": options.Limit, "offset": options.Offset, "sort": options.Sort, "order": options.Order, "has_more": meta.HasMore, "cluster_id": cluster, "window_hours": ints["hours"], "filters": map[string]any{"severity_min": ints["severity_min"], "workload_id": workload, "category": category, "group": values.Get("group"), "port": ints["port"], "peer": peer, "application": applicationFilter, "namespace": namespace, "node": node, "hide_platform": hide, "q": search}}
	if groupActive {
		response["selected_group"] = groupName
		response["selected_group_members"] = len(members)
	}
	httpx.WriteJSON(w, 200, response)
}
