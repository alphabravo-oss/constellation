package network

import (
	"bytes"
	"encoding/csv"
	"errors"
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
	"github.com/jackc/pgx/v5"
)

const sessionInventoryColumns = `id,session_id,cluster_id,node,workload_id,application,ip_proto,client_ip,client_port,server_ip,server_port,client_state,server_state,client_bytes,server_bytes,client_pkts,server_pkts,age,idle,ingress,severity,threat_id,updated_at,platform_role,application_label,protocol_label,client_state_label,server_state_label,bytes,packets`
const sessionProtocolLabelSQL = `CASE s.ip_proto WHEN 6 THEN 'TCP' WHEN 17 THEN 'UDP' WHEN 1 THEN 'ICMP' WHEN 58 THEN 'ICMPv6' WHEN 0 THEN '' ELSE 'proto-'||s.ip_proto END`
const sessionApplicationLabelSQL = `CASE s.server_port WHEN 80 THEN 'HTTP' WHEN 8080 THEN 'HTTP' WHEN 8000 THEN 'HTTP' WHEN 443 THEN 'HTTPS' WHEN 8443 THEN 'HTTPS' WHEN 53 THEN 'DNS' WHEN 22 THEN 'SSH' WHEN 3306 THEN 'MySQL' WHEN 5432 THEN 'PostgreSQL' WHEN 6379 THEN 'Redis' WHEN 27017 THEN 'MongoDB' ELSE ` + sessionProtocolLabelSQL + ` END`

func sessionStateLabelSQL(column string) string {
	return `CASE ` + column + ` WHEN 0 THEN '' WHEN 1 THEN 'ESTABLISHED' WHEN 2 THEN 'SYN_SENT' WHEN 3 THEN 'SYN_RECV' WHEN 4 THEN 'FIN_WAIT1' WHEN 5 THEN 'FIN_WAIT2' WHEN 6 THEN 'TIME_WAIT' WHEN 7 THEN 'CLOSE' WHEN 8 THEN 'CLOSE_WAIT' WHEN 9 THEN 'LAST_ACK' WHEN 10 THEN 'LISTEN' WHEN 11 THEN 'CLOSING' ELSE 'state-'||` + column + ` END`
}
func sessionInventorySQL() string {
	return `SELECT jsonb_build_array(s.cluster_id,s.node,s.id)::text,s.id,s.cluster_id,s.node,s.workload_id,s.application,s.ip_proto,s.client_ip,s.client_port,s.server_ip,s.server_port,s.client_state,s.server_state,s.client_bytes,s.server_bytes,s.client_pkts,s.server_pkts,s.age,s.idle,s.ingress,s.severity,s.threat_id,s.updated_at,` +
		handler.EvidencePlatformRoleSQL("s.org_id", "s.cluster_id", "s.workload_id", "''") + `,` + sessionApplicationLabelSQL + `,` + sessionProtocolLabelSQL + `,` + sessionStateLabelSQL("s.client_state") + `,` + sessionStateLabelSQL("s.server_state") + `,s.client_bytes::numeric+s.server_bytes::numeric,s.client_pkts::numeric+s.server_pkts::numeric
 FROM network_sessions s WHERE s.org_id=$1 AND ($2::uuid IS NULL OR s.cluster_id=$2) AND s.updated_at>NOW()-INTERVAL '5 minutes'
 AND EXISTS(SELECT 1 FROM clusters c WHERE c.org_id=s.org_id AND c.id=s.cluster_id)`
}

const sessionInventorySummary = `jsonb_build_object('total',count(*),'tcp',count(*) FILTER(WHERE ip_proto=6),'udp',count(*) FILTER(WHERE ip_proto=17),'icmp',count(*) FILTER(WHERE ip_proto IN (1,58)),'other',count(*) FILTER(WHERE ip_proto NOT IN (6,17,1,58)),'client_bytes',COALESCE(sum(client_bytes),0),'server_bytes',COALESCE(sum(server_bytes),0),'bytes',COALESCE(sum(bytes),0),'packets',COALESCE(sum(packets),0),'threats',count(*) FILTER(WHERE threat_id<>0))`

// Keep the legacy preferred-cluster fallback, but propagate lookup failures
// rather than broadening a failed cluster read to an organization-wide success.
func (h *Network) sessionInventoryCluster(r *http.Request, org uuid.UUID) (*uuid.UUID, error) {
	if strings.TrimSpace(r.URL.Query().Get("cluster_id")) != "" {
		return h.resolveNetworkCluster(r, org)
	}
	var cluster uuid.UUID
	err := h.db.Pool().QueryRow(r.Context(), `SELECT id FROM clusters WHERE org_id=$1 ORDER BY CASE WHEN state='connected' THEN 0 ELSE 1 END,last_heartbeat_at DESC NULLS LAST,created_at ASC,id ASC LIMIT 1`, org).Scan(&cluster)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cluster, nil
}
func scanSessionInventory(row inventorylist.Row) (sessionDTO, error) {
	var item sessionDTO
	var application, proto, clientState, serverState int
	var totalBytes, totalPackets string
	err := row.Scan(&item.RowID, &item.ID, &item.ClusterID, &item.Node, &item.WorkloadID, &application, &proto, &item.ClientIP, &item.ClientPort, &item.ServerIP, &item.ServerPort, &clientState, &serverState, &item.ClientBytes, &item.ServerBytes, &item.ClientPkts, &item.ServerPkts, &item.Age, &item.Idle, &item.Ingress, &item.Severity, &item.ThreatID, &item.UpdatedAt, &item.PlatformRole, &item.Application, &item.IPProto, &item.ClientState, &item.ServerState, &totalBytes, &totalPackets)
	return item, err
}
func (h *Network) writeSessionInventory(w http.ResponseWriter, r *http.Request, export, summaryOnly bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, 401, map[string]string{"error": "subject required"})
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		httpx.WriteJSON(w, 400, map[string]string{"error": "invalid query encoding"})
		return
	}
	cluster, err := h.sessionInventoryCluster(r, subj.OrgID)
	if err != nil {
		status := 500
		message := "session cluster scope could not be verified"
		if err.Error() == "invalid cluster_id" || err.Error() == "cluster not found" {
			status = 400
			message = err.Error()
		}
		httpx.WriteJSON(w, status, map[string]string{"error": message})
		return
	}
	sorts := map[string]string{"workload": "lower(workload_id)", "node": "lower(node)", "application": "lower(application_label)", "protocol": "lower(protocol_label)", "client": "ROW(lower(client_ip),client_port)", "server": "ROW(lower(server_ip),server_port)", "bytes": "bytes", "packets": "packets", "client_bytes": "client_bytes", "server_bytes": "server_bytes", "age": "age", "idle": "idle", "severity": "severity", "observed": "updated_at", "state": "ROW(lower(client_state_label),lower(server_state_label))"}
	opts, err := inventorylist.Parse(values, sorts, "bytes")
	if err != nil {
		httpx.WriteJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	opts.Limit = 500
	if values.Has("limit") {
		n, e := strconv.Atoi(values.Get("limit"))
		if e != nil || n < 1 || n > 2000 {
			httpx.WriteJSON(w, 400, map[string]string{"error": "limit must be between 1 and 2000"})
			return
		}
		opts.Limit = n
	}
	if values.Has("offset") {
		n, e := strconv.Atoi(values.Get("offset"))
		if e != nil || n < 0 || n > inventorylist.MaxOffset {
			httpx.WriteJSON(w, 400, map[string]string{"error": "invalid offset"})
			return
		}
		opts.Offset = n
	}
	// Raw IDs are only node-local; every order ends with the complete instance key.
	opts.OrderSQL = sorts[opts.Sort] + " " + strings.ToUpper(opts.Order) + " NULLS LAST"
	if values.Get("sort") == "" {
		opts.OrderSQL += ", age DESC"
	}
	opts.OrderSQL += ", cluster_id ASC,node ASC,session_id ASC"
	filters, err := parseSessionFilters(r)
	if err != nil {
		httpx.WriteJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	members, name, active, err := handler.ResolveGroupFilterMembers(r.Context(), h.db.Pool(), subj.OrgID, cluster, filters.Group)
	if err != nil {
		httpx.WriteJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	filters.GroupMembers, filters.GroupName, filters.GroupActive = members, name, active
	hidePlatform := false
	switch values.Get("hide_platform") {
	case "", "false", "0":
	case "true", "1":
		hidePlatform = true
	default:
		httpx.WriteJSON(w, 400, map[string]string{"error": "invalid hide_platform"})
		return
	}
	where, args := filters.applySessionWhere([]string{"true"}, []any{subj.OrgID, cluster})
	if hidePlatform {
		where = append(where, "platform_role<>'core'")
	}
	search := strings.TrimSpace(values.Get("q"))
	if search != "" {
		args = append(args, search)
		where = append(where, fmt.Sprintf(`strpos(lower(concat_ws(' ',id,node,workload_id,application_label,protocol_label,client_ip,client_port,server_ip,server_port,client_state_label,server_state_label)),lower($%d))>0`, len(args)))
	}
	definition := inventorylist.Definition{SQL: sessionInventorySQL(), Columns: sessionInventoryColumns, Where: strings.Join(where, " AND "), Args: args, Summary: sessionInventorySummary}
	if export {
		opts.Limit = inventorylist.ExportLimit
		opts.Offset = 0
	}
	if summaryOnly {
		opts.Limit = 0
		opts.Offset = 0
	}
	items, meta, err := inventorylist.Read(r.Context(), h.db.Pool(), definition, opts, scanSessionInventory)
	if err != nil {
		httpx.WriteJSON(w, 500, map[string]string{"error": "live sessions could not be read"})
		return
	}
	if summaryOnly {
		httpx.WriteJSON(w, 200, meta.Summary)
		return
	}
	if export {
		var body bytes.Buffer
		writer := csv.NewWriter(&body)
		if err := writer.Write([]string{"row_id", "cluster_id", "session_id", "node", "workload_id", "platform_role", "application", "ip_proto", "client_ip", "client_port", "server_ip", "server_port", "client_state", "server_state", "client_bytes", "server_bytes", "client_pkts", "server_pkts", "age", "idle", "ingress", "severity", "threat_id", "updated_at"}); err != nil {
			httpx.WriteJSON(w, 500, map[string]string{"error": "session export failed"})
			return
		}
		for _, item := range items {
			if err := writer.Write([]string{item.RowID, item.ClusterID.String(), strconv.FormatInt(item.ID, 10), item.Node, item.WorkloadID, item.PlatformRole, item.Application, item.IPProto, item.ClientIP, strconv.Itoa(item.ClientPort), item.ServerIP, strconv.Itoa(item.ServerPort), item.ClientState, item.ServerState, strconv.FormatInt(item.ClientBytes, 10), strconv.FormatInt(item.ServerBytes, 10), strconv.FormatInt(item.ClientPkts, 10), strconv.FormatInt(item.ServerPkts, 10), strconv.Itoa(item.Age), strconv.Itoa(item.Idle), strconv.FormatBool(item.Ingress), strconv.Itoa(item.Severity), strconv.FormatInt(item.ThreatID, 10), item.UpdatedAt.UTC().Format(time.RFC3339Nano)}); err != nil {
				httpx.WriteJSON(w, 500, map[string]string{"error": "session export failed"})
				return
			}
		}
		writer.Flush()
		if writer.Error() != nil {
			httpx.WriteJSON(w, 500, map[string]string{"error": "session export failed"})
			return
		}
		inventorylist.WriteCSV(w, "constellation-network-sessions.csv", body.Bytes(), meta)
		return
	}
	response := map[string]any{"sessions": items, "total": meta.Total, "limit": opts.Limit, "offset": opts.Offset, "has_more": meta.HasMore, "summary": meta.Summary, "sort": opts.Sort, "order": opts.Order, "q": search, "application": filters.Application, "peer": filters.Peer, "workload": filters.Workload, "node": filters.Node, "group": filters.Group, "hours": filters.Hours, "hide_platform": hidePlatform, "stale_after_seconds": 300}
	response["filters"] = map[string]any{"cluster_id": cluster, "protocol": filters.Protocol, "port": filters.Port, "application": filters.Application, "peer": filters.Peer, "workload": filters.Workload, "node": filters.Node, "group": filters.Group, "hours": filters.Hours, "q": search, "hide_platform": hidePlatform}

	if cluster != nil {
		response["cluster_id"] = cluster.String()
	}
	if filters.Protocol != nil {
		response["protocol"] = *filters.Protocol
	} else {
		response["protocol"] = nil
	}
	if filters.Port != nil {
		response["port"] = *filters.Port
	} else {
		response["port"] = nil
	}
	if filters.GroupActive {
		response["selected_group"] = filters.GroupName
		response["selected_group_members"] = len(filters.GroupMembers)
	}
	httpx.WriteJSON(w, 200, response)
}
