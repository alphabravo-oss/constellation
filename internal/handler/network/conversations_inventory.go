package network

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/alphabravocompany/constellation/pkg/graph"
)

type conversationFilters struct {
	HidePlatform bool   `json:"hide_platform"`
	Hours        int    `json:"hours"`
	Namespace    string `json:"namespace"`
	Verdict      string `json:"verdict"`
	Group        string `json:"group"`
	Port         int    `json:"port"`
	Peer         string `json:"peer"`
	Application  string `json:"application"`
	From         string `json:"from"`
	To           string `json:"to"`
	VerdictGroup string `json:"verdict_group"`
}
type conversationOptions struct {
	inventorylist.Options
	conversationFilters
	ClusterID    *uuid.UUID
	GroupMembers []string
	GroupName    string
	GroupActive  bool
}

var conversationSorts = map[string]string{
	"from": "src_workload", "to": "dst_workload", "bytes": "bytes", "packets": "packets", "edges": "edges", "severity": "severity", "verdict": "verdict", "last_seen": "last_seen", "apps": "apps",
}

func parseConversationOptions(values url.Values) (conversationOptions, error) {
	o := conversationOptions{Options: inventorylist.Options{Limit: 5000, Sort: "bytes", Order: "desc"}}
	// Hours retain the existing default/normalization contract.
	o.Hours, _ = strconv.Atoi(values.Get("hours"))
	if o.Hours <= 0 || o.Hours > 720 {
		o.Hours = 24
	}
	for key, target := range map[string]*int{"limit": &o.Limit, "offset": &o.Offset, "port": &o.Port} {
		if raw, present := values[key]; present {
			if len(raw) != 1 {
				return o, fmt.Errorf("invalid %s", key)
			}
			value, err := strconv.Atoi(strings.TrimSpace(raw[0]))
			if err != nil || value < 0 || key == "limit" && (value < 1 || value > 5000) || key == "offset" && value > inventorylist.MaxOffset || key == "port" && (value < 1 || value > 65535) {
				return o, fmt.Errorf("invalid %s", key)
			}
			*target = value
		}
	}
	if raw, present := values["hide_platform"]; present {
		if len(raw) != 1 || (raw[0] != "true" && raw[0] != "false") {
			return o, fmt.Errorf("invalid hide_platform")
		}
		o.HidePlatform = raw[0] == "true"
	}

	for key, values := range values {
		if len(values) != 1 {
			return o, fmt.Errorf("duplicate %s", key)
		}
	}
	if raw := strings.TrimSpace(values.Get("cluster_id")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return o, fmt.Errorf("invalid cluster_id")
		}
		o.ClusterID = &id
	}
	o.Namespace = strings.TrimSpace(values.Get("namespace"))
	o.Verdict = strings.ToLower(strings.TrimSpace(values.Get("verdict")))
	o.Group = strings.TrimSpace(values.Get("group"))
	o.Peer = strings.ToLower(strings.TrimSpace(values.Get("peer")))
	o.Application = strings.ToLower(strings.TrimSpace(values.Get("application")))
	o.From = strings.TrimSpace(values.Get("from"))
	o.To = strings.TrimSpace(values.Get("to"))
	o.VerdictGroup = strings.TrimSpace(values.Get("verdict_group"))
	if o.VerdictGroup != "" && o.VerdictGroup != "blocked" {
		return o, fmt.Errorf("invalid verdict_group")
	}
	if key := values.Get("sort"); key != "" {
		o.Sort = key
	}
	expression, ok := conversationSorts[o.Sort]
	if !ok {
		return o, fmt.Errorf("unsupported sort")
	}
	if order := values.Get("order"); order != "" {
		o.Order = strings.ToLower(order)
	}
	if o.Order != "asc" && o.Order != "desc" {
		return o, fmt.Errorf("order must be asc or desc")
	}
	o.OrderSQL = expression + " " + strings.ToUpper(o.Order) + " NULLS LAST, src_workload ASC, dst_workload ASC"
	return o, nil
}

// Fold every matching rollup before pagination. A stream is the same protocol/port
// edge used by pkg/graph; its latest nonempty app and worst verdict are deterministic.
const conversationInventorySQL = `WITH scoped AS (
 SELECT r.* FROM network_flow_rollups r
 WHERE r.org_id=$1 AND ($2::uuid IS NULL OR r.cluster_id=$2)
 AND (r.cluster_id IS NULL OR EXISTS (SELECT 1 FROM clusters c WHERE c.id=r.cluster_id AND c.org_id=$1))
 AND bucket >= date_trunc('hour', NOW()-($3::int * INTERVAL '1 hour'))
 AND ($4::text='' OR verdict=$4)
 AND ($5::text='' OR split_part(src_workload,'/',1)=$5 AND strpos(src_workload,'/')>0 OR split_part(dst_workload,'/',1)=$5 AND strpos(dst_workload,'/')>0)
 AND (NOT $6::boolean OR src_workload=ANY($7::text[]) OR dst_workload=ANY($7::text[]))
 AND ($8::int=0 OR dst_port=$8 OR min_src_port=$8)
 AND ($9::text='' OR strpos(lower(src_workload),$9)>0 OR strpos(lower(dst_workload),$9)>0 OR strpos(lower(min_src_addr),$9)>0 OR strpos(lower(min_dst_addr),$9)>0)
 AND ($10::text='' OR lower(l7_protocol)=$10 OR max_application::text=$10)
 AND ($11::text='' OR src_workload=$11) AND ($12::text='' OR dst_workload=$12)
 AND ($13::text='' OR lower(verdict) IN ('deny','denied','block','blocked'))
), streams AS (
 SELECT src_workload,dst_workload,protocol,dst_port,
 SUM(sum_bytes)::bigint AS bytes,SUM(sum_packets)::bigint AS packets,MAX(max_at) AS last_seen,COALESCE(MAX(max_severity),0)::int AS severity,
 COALESCE((array_agg(lower(l7_protocol) ORDER BY max_at DESC,lower(l7_protocol)) FILTER (WHERE l7_protocol<>''))[1],'') AS app,
 (array_agg(lower(verdict) ORDER BY CASE lower(verdict) WHEN 'deny' THEN 3 WHEN 'denied' THEN 3 WHEN 'block' THEN 3 WHEN 'blocked' THEN 3 WHEN 'violate' THEN 2 WHEN 'alert' THEN 2 WHEN 'allow' THEN 1 ELSE 0 END DESC,lower(verdict)))[1] AS verdict
 FROM scoped GROUP BY src_workload,dst_workload,protocol,dst_port
), inventory AS (
 SELECT src_workload,dst_workload,SUM(bytes)::bigint AS bytes,SUM(packets)::bigint AS packets,COUNT(*)::int AS edges,MAX(last_seen) AS last_seen,MAX(severity)::int AS severity,
 (array_agg(verdict ORDER BY CASE verdict WHEN 'deny' THEN 3 WHEN 'denied' THEN 3 WHEN 'block' THEN 3 WHEN 'blocked' THEN 3 WHEN 'violate' THEN 2 WHEN 'alert' THEN 2 WHEN 'allow' THEN 1 ELSE 0 END DESC,verdict))[1] AS verdict,
 COALESCE(array_agg(DISTINCT app ORDER BY app) FILTER (WHERE app<>''),'{}') AS apps,
 jsonb_agg(jsonb_build_object('from',src_workload,'to',dst_workload,'attrs',jsonb_build_object('bytes',bytes,'packets',packets,'protocol',protocol,'port',dst_port,'last_seen',last_seen,'l7',app,'verdict',verdict,'severity',severity)) ORDER BY protocol,dst_port) AS streams
 FROM streams GROUP BY src_workload,dst_workload
) `

// Platform filtering resolves each actual source-cluster endpoint once, before
// folding org-wide names together. Display classification retains the existing
// conservative org-wide rule when several clusters can share an endpoint name.
func conversationSQL(hidePlatform bool) string {
	if !hidePlatform {
		return conversationInventorySQL
	}
	namespace := "CASE WHEN strpos(e.workload,'/')>0 THEN split_part(e.workload,'/',1) ELSE '' END"
	role := handler.EvidencePlatformRoleSQL("$1", "e.cluster_id", "e.workload", namespace)
	sql := strings.Replace(conversationInventorySQL, "WITH scoped AS (", "WITH raw_scoped AS (", 1)
	return strings.Replace(sql, "), streams AS (", `), endpoint_roles AS MATERIALIZED (
 SELECT e.cluster_id,e.workload,`+role+` AS role FROM (
 SELECT cluster_id,src_workload AS workload FROM raw_scoped
 UNION SELECT cluster_id,dst_workload FROM raw_scoped
 ) e
 ), scoped AS (
 SELECT r.* FROM raw_scoped r
 JOIN endpoint_roles f ON f.cluster_id IS NOT DISTINCT FROM r.cluster_id AND f.workload=r.src_workload
 JOIN endpoint_roles t ON t.cluster_id IS NOT DISTINCT FROM r.cluster_id AND t.workload=r.dst_workload
 WHERE f.role<>'core' AND t.role<>'core'
 ), streams AS (`, 1)
}

func conversationRowID(from, to string) string {
	encoded, _ := json.Marshal([]string{from, to})
	return string(encoded)
}

func (h *NetworkConversations) listConversations(w http.ResponseWriter, r *http.Request, export bool) {
	started := time.Now()
	subject, ok := authctx.SubjectFrom(r.Context())
	if !ok || subject.OrgID == uuid.Nil {
		apiutil.WriteStatus(r.Context(), w, 401, "authentication required")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 400, "invalid query")
		return
	}
	o, err := parseConversationOptions(values)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 400, err.Error())
		return
	}
	if o.ClusterID != nil {
		var exists bool
		if err := h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, subject.OrgID, *o.ClusterID).Scan(&exists); err != nil {
			conversationReadError(w)
			return
		} else if !exists {
			apiutil.WriteStatus(r.Context(), w, 404, "cluster not found")
			return
		}
	}
	o.GroupMembers, o.GroupName, o.GroupActive, err = handler.ResolveGroupFilterMembers(r.Context(), h.db.Pool(), subject.OrgID, o.ClusterID, o.Group)
	if err != nil {
		if err.Error() == "group not found" {
			apiutil.WriteStatus(r.Context(), w, 400, "group not found")
		} else {
			conversationReadError(w)
		}
		return
	}
	// Preserve the legacy hot graph, but never claim its TTL/edge-limited snapshot
	// is the complete requested window. Any inventory control forces durable SQL.
	if !export && h.live != nil && !o.HidePlatform && o.Namespace == "" && o.Verdict == "" && !o.GroupActive && o.Port == 0 && o.Peer == "" && o.Application == "" && o.From == "" && o.To == "" && o.VerdictGroup == "" && !values.Has("limit") && !values.Has("offset") && !values.Has("sort") && !values.Has("order") {
		g := h.live.Snapshot(subject.OrgID, o.ClusterID)
		if n, _ := g.Len(); n > 0 {
			conversations, err := h.platformConversations(r.Context(), subject.OrgID, o.ClusterID, g.Conversations())
			if err != nil {
				conversationReadError(w)
				return
			}
			response := conversationResponse(o, conversations, g, liveConversationSummary(g))
			response["source"] = "live"
			response["source_complete"] = false
			response["summary_scope"] = "live_snapshot"
			response["sort"] = "from"
			response["order"] = "asc"
			httpx.WriteJSON(w, 200, response)
			return
		}
	}
	if export {
		o.Limit = inventorylist.ExportLimit
		o.Offset = 0
	}
	conversations, g, meta, err := h.readConversationInventory(r.Context(), subject.OrgID, o, !export)
	if err != nil {
		conversationReadError(w)
		return
	}
	if !historyAvailable(w, r, h.db.Pool(), started.Add(-time.Duration(o.Hours)*time.Hour)) {
		return
	}
	if export {
		var body bytes.Buffer
		writer := csv.NewWriter(&body)
		if err = writer.Write([]string{"Conversation ID", "From", "To", "Bytes", "Packets", "Streams", "Last seen", "Max severity", "Verdict", "Applications (JSON)", "From platform role", "To platform role"}); err == nil {
			for _, item := range conversations {
				apps, _ := json.Marshal(item.Apps)
				if err = writer.Write([]string{item.RowID, item.From, item.To, strconv.FormatInt(item.Bytes, 10), strconv.FormatInt(item.Packets, 10), strconv.Itoa(item.Edges), item.LastSeen.UTC().Format(time.RFC3339Nano), strconv.Itoa(item.Severity), item.Verdict, string(apps), item.FromPlatformRole, item.ToPlatformRole}); err != nil {
					break
				}
			}
		}
		writer.Flush()
		if err != nil || writer.Error() != nil {
			conversationReadError(w)
			return
		}
		w.Header().Set("X-Conversation-Source", "rollups")
		w.Header().Set("X-Conversation-Window-Hours", strconv.Itoa(o.Hours))
		cluster := "organization"
		if o.ClusterID != nil {
			cluster = o.ClusterID.String()
		}
		w.Header().Set("X-Conversation-Cluster", cluster)
		inventorylist.WriteCSV(w, "network-conversations.csv", body.Bytes(), meta)
		return
	}
	response := conversationResponse(o, conversations, g, meta)
	response["source"] = "rollups"
	response["source_complete"] = true
	response["summary_scope"] = "matching_rollups"
	httpx.WriteJSON(w, 200, response)
}
func conversationReadError(w http.ResponseWriter) {
	apiutil.WriteStatus(context.Background(), w, 500, "could not read conversations")
}

func (h *NetworkConversations) readConversationInventory(ctx context.Context, org uuid.UUID, o conversationOptions, includeGraph bool) ([]platformConversation, *graph.Graph, inventorylist.Metadata, error) {
	meta := inventorylist.Metadata{}
	tx, err := h.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, nil, meta, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	args := []any{org, o.ClusterID, o.Hours, o.Verdict, o.Namespace, o.GroupActive, o.GroupMembers, o.Port, o.Peer, o.Application, o.From, o.To, o.VerdictGroup}
	var summary []byte
	err = tx.QueryRow(ctx, conversationSQL(o.HidePlatform)+`SELECT COUNT(*),jsonb_build_object('total',COUNT(*),'bytes',COALESCE(SUM(bytes),0),'packets',COALESCE(SUM(packets),0),'edges',COALESCE(SUM(edges),0),'blocked',COUNT(*) FILTER(WHERE verdict IN ('deny','denied','block','blocked')),'violating',COUNT(*) FILTER(WHERE verdict IN ('violate','alert')),'max_severity',COALESCE(MAX(severity),0),'source_clusters',(SELECT COUNT(DISTINCT cluster_id) FROM scoped),'nodes',(SELECT COUNT(DISTINCT endpoint) FROM (SELECT src_workload AS endpoint FROM inventory UNION SELECT dst_workload FROM inventory) n)) FROM inventory`, args...).Scan(&meta.Total, &summary)
	if err != nil {
		return nil, nil, meta, err
	}
	if err = json.Unmarshal(summary, &meta.Summary); err != nil {
		return nil, nil, meta, err
	}
	streamColumn := "streams"
	if !includeGraph {
		streamColumn = "'[]'::jsonb"
	}
	rows, err := tx.Query(ctx, conversationSQL(o.HidePlatform)+`SELECT src_workload,dst_workload,bytes,packets,edges,last_seen,severity,verdict,apps,`+streamColumn+` FROM inventory ORDER BY `+o.OrderSQL+` LIMIT $14 OFFSET $15`, append(args, o.Limit, o.Offset)...)
	if err != nil {
		return nil, nil, meta, err
	}
	g := graph.New()
	items := []graph.Conversation{}
	for rows.Next() {
		var item graph.Conversation
		var streams []byte
		if err = rows.Scan(&item.From, &item.To, &item.Bytes, &item.Packets, &item.Edges, &item.LastSeen, &item.Severity, &item.Verdict, &item.Apps, &streams); err != nil {
			rows.Close()
			return nil, nil, meta, err
		}
		var edges []graph.Edge
		if err = json.Unmarshal(streams, &edges); err != nil {
			rows.Close()
			return nil, nil, meta, err
		}
		for _, edge := range edges {
			g.AddEdge(edge.From, edge.To, edge.Attrs)
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, meta, err
	}
	conversations, err := h.platformConversationsWithQuerier(ctx, tx, org, o.ClusterID, items)
	if err != nil {
		return nil, nil, meta, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, nil, meta, err
	}
	meta.HasMore = int64(o.Offset)+int64(len(items)) < meta.Total
	return conversations, g, meta, nil
}
func conversationResponse(o conversationOptions, items []platformConversation, g *graph.Graph, meta inventorylist.Metadata) map[string]any {
	nodes := g.Nodes()
	response := map[string]any{"conversations": items, "nodes": nodes, "node_kinds": nodeKinds(nodes), "edges": g.Edges(), "window_hours": o.Hours, "cluster_id": o.ClusterID, "filters": o.conversationFilters, "total": meta.Total, "summary": meta.Summary, "limit": o.Limit, "offset": o.Offset, "has_more": meta.HasMore, "sort": o.Sort, "order": o.Order}
	if o.GroupActive {
		response["selected_group"] = o.GroupName
		response["selected_group_members"] = len(o.GroupMembers)
	}
	return response
}
func liveConversationSummary(g *graph.Graph) inventorylist.Metadata {
	items := g.Conversations()
	nodes, _ := g.Len()
	summary := map[string]int64{"total": int64(len(items)), "nodes": int64(nodes), "bytes": 0, "packets": 0, "edges": 0, "blocked": 0, "violating": 0, "max_severity": 0}
	for _, item := range items {
		summary["bytes"] += item.Bytes
		summary["packets"] += item.Packets
		summary["edges"] += int64(item.Edges)
		if int64(item.Severity) > summary["max_severity"] {
			summary["max_severity"] = int64(item.Severity)
		}
		switch item.Verdict {
		case "deny", "denied", "block", "blocked":
			summary["blocked"]++
		case "violate", "alert":
			summary["violating"]++
		}
	}
	return inventorylist.Metadata{Total: int64(len(items)), Summary: summary}
}
