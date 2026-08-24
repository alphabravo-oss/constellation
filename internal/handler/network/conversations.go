package network

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/graph"
	"github.com/alphabravocompany/constellation/pkg/livegraph"
)

// endpointKind classifies a conversation-graph node, mirroring NeuVector's node
// kinds (workload | host | unmanaged | external). Node ids are "scope/name"
// ("ns/deploy", "cluster/<ip>") or bare values. Managed workloads are
// namespace/name; a private/cluster IP not mapped to a workload is unmanaged; a
// public IP is external; host/node scopes are host.
func endpointKind(id string) string {
	scope, name, found := strings.Cut(strings.TrimSpace(id), "/")
	if !found {
		if ip := net.ParseIP(scope); ip != nil {
			return ipEndpointKind(ip)
		}
		return "external"
	}
	switch strings.ToLower(scope) {
	case "host", "node":
		return "host"
	case "external":
		return "external"
	case "cluster":
		if ip := net.ParseIP(name); ip != nil {
			return ipEndpointKind(ip)
		}
		return "unmanaged"
	}
	if ip := net.ParseIP(name); ip != nil {
		return ipEndpointKind(ip)
	}
	return "workload"
}

func ipEndpointKind(ip net.IP) string {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		// ponytail: heuristic — the CNI pod-network gateway is conventionally the
		// .1 of the subnet (flannel cni0, calico, etc.) and appears as very
		// high-volume infra traffic (kube-proxy / node-local DNS / probes).
		// Classify it as host so it renders as node infrastructure instead of
		// cluttering the graph as an "unmanaged" workload. Upgrade path: match
		// against the cluster's real node InternalIPs / pod CIDR from inventory
		// rather than guessing on the last octet.
		if v4 := ip.To4(); v4 != nil && v4[3] == 1 {
			return "host"
		}
		return "unmanaged"
	}
	return "external"
}

// nodeKinds maps each node id to its endpoint kind for the response.
func nodeKinds(nodes []string) map[string]string {
	out := make(map[string]string, len(nodes))
	for _, n := range nodes {
		out[n] = endpointKind(n)
	}
	return out
}

// NetworkConversations is a slim wrapper that builds a pkg/graph.Graph from the
// flows table and returns the folded service-conversation view. Distinct from the
// existing /network/map endpoint which returns the raw flow rows.
type NetworkConversations struct {
	db   *db.DB
	live *livegraph.Store // optional hot cache (plan B5); nil when disabled
}

func NewNetworkConversations(d *db.DB) *NetworkConversations { return &NetworkConversations{db: d} }

// WithLiveGraph wires the in-memory hot graph. When set, List serves the
// conversation graph from the cache for low latency, falling back to the
// Postgres query only when the cache is empty for the org.
func (h *NetworkConversations) WithLiveGraph(s *livegraph.Store) *NetworkConversations {
	h.live = s
	return h
}

func (h *NetworkConversations) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*30 {
		hours = 24
	}
	// Wave D2: optional cluster_id scoping. Without it the conversation
	// graph aggregates across every cluster the user can see — that's
	// useful for the org-level overview but a UI passing cluster_id
	// gets a per-cluster view. Same shape as /network/map.
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	// Namespace + verdict filters (previously accepted by the UI but silently ignored).
	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
	verdict := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("verdict")))
	var clusterUUID *uuid.UUID
	if clusterID != "" {
		if u, err := uuid.Parse(clusterID); err == nil {
			clusterUUID = &u
		}
	}
	groupMembers, groupName, groupActive, err := handler.ResolveGroupFilterMembers(r.Context(), h.db.Pool(), subj.OrgID, clusterUUID, r.URL.Query().Get("group"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Plan B5: serve from the hot in-memory graph when enabled. The cache only
	// holds the recent TTL window, so it's used as a low-latency accelerator;
	// when it has nothing for this org we fall through to the durable SQL path.
	// The in-memory graph can't apply namespace/verdict filters, so skip it when
	// either is set and serve the filterable SQL path instead.
	if h.live != nil && namespace == "" && verdict == "" && !groupActive {
		g := h.live.Snapshot(subj.OrgID, clusterUUID)
		if n, _ := g.Len(); n > 0 {
			nodes := g.Nodes()
			httpx.WriteJSON(w, http.StatusOK, map[string]any{
				"conversations": g.Conversations(),
				"nodes":         nodes,
				"node_kinds":    nodeKinds(nodes),
				"edges":         g.Edges(),
				"window_hours":  hours,
				"source":        "live",
			})
			return
		}
	}
	// Fold conversations in SQL so the 5000 cap bounds distinct edges, not raw
	// observations — otherwise busy clusters truncate before aggregation and the
	// byte/packet SUMs undercount. Mirrors Network.Map's GROUP BY.
	// NET perf: fold from the network_flow_rollups pre-aggregate (migration 115)
	// rather than the raw network_flows day-window GROUP BY. Same shape; the
	// 5000 cap still bounds distinct edges.
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT src_workload, dst_workload, protocol, dst_port,
       l7_protocol, verdict, COALESCE(MAX(max_severity),0)::int,
       SUM(sum_bytes)::bigint, SUM(sum_packets)::bigint, MAX(max_at)
  FROM network_flow_rollups
 WHERE org_id = $1
   AND ($2::text = '' OR cluster_id::text = $2)
   AND bucket >= date_trunc('hour', NOW() - ($3::int * INTERVAL '1 hour'))
   AND ($4::text = '' OR verdict = $4)
   AND ($5::text = '' OR src_workload LIKE $5 || '/%' OR dst_workload LIKE $5 || '/%')
   AND (NOT $6::boolean OR src_workload = ANY($7::text[]) OR dst_workload = ANY($7::text[]))
 GROUP BY src_workload, dst_workload, protocol, dst_port, l7_protocol, verdict
 ORDER BY SUM(sum_bytes) DESC
 LIMIT 5000`, subj.OrgID, clusterID, hours, verdict, namespace, groupActive, groupMembers)
	if err != nil {
		// network_flows table may be absent in non-runtime envs; degrade to empty graph.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"conversations": []graph.Conversation{},
			"nodes":         []string{},
			"node_kinds":    map[string]string{},
			"edges":         []graph.Edge{},
			"window_hours":  hours,
		})
		return
	}
	defer rows.Close()
	g := graph.New()
	for rows.Next() {
		var src, dst, proto, l7, verdict string
		var port, severity int
		var bytes, pkts int64
		var lastSeen time.Time
		if err := rows.Scan(&src, &dst, &proto, &port, &l7, &verdict, &severity, &bytes, &pkts, &lastSeen); err != nil {
			continue
		}
		g.AddEdge(src, dst, graph.Attrs{
			Bytes: bytes, Packets: pkts, Protocol: proto, Port: port, LastSeen: lastSeen,
			L7: strings.ToLower(l7), Verdict: strings.ToLower(verdict), Severity: severity,
		})
	}
	nodes := g.Nodes()
	response := map[string]any{
		"conversations": g.Conversations(),
		"nodes":         nodes,
		"node_kinds":    nodeKinds(nodes),
		"edges":         g.Edges(),
		"window_hours":  hours,
	}
	if groupActive {
		response["selected_group"] = groupName
		response["selected_group_members"] = len(groupMembers)
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}

// conversationEntryDTO is one protocol/port/app stream between a from→to pair — NV's
// RESTConversationEntry. client_bytes is from→to payload (the initiator's traffic),
// server_bytes is to→from (responses); so an operator sees in/out per stream. mapped_port,
// xff, and per-session rows are omitted: the rollups don't carry them (no fabrication).
type conversationEntryDTO struct {
	Protocol    string `json:"protocol"`
	Application string `json:"application"`
	Port        int    `json:"port"`
	Verdict     string `json:"verdict"`
	Bytes       int64  `json:"bytes"`
	ClientBytes int64  `json:"client_bytes"`
	ServerBytes int64  `json:"server_bytes"`
	Packets     int64  `json:"packets"`
	Sessions    int64  `json:"sessions"`
	Severity    int    `json:"severity"`
	ThreatID    int    `json:"threat_id"`
	LastSeenAt  string `json:"last_seen_at"`
}

// Detail returns the full per-stream breakdown of one from→to conversation — every
// protocol/port/application seen between the pair, with directional (in/out) bytes and
// session counts. NV's GET /v1/conversation/:from/:to. GET /network/conversations/entries?from=&to=
func (h *NetworkConversations) Detail(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	from := strings.TrimSpace(r.URL.Query().Get("from"))
	to := strings.TrimSpace(r.URL.Query().Get("to"))
	if from == "" || to == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "from and to are required"})
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*30 {
		hours = 24
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT protocol, COALESCE(l7_protocol,''), COALESCE(dst_port,0), verdict,
       SUM(sum_bytes)::bigint, SUM(sum_packets)::bigint,
       COALESCE(SUM(sum_client_bytes),0)::bigint, COALESCE(SUM(sum_server_bytes),0)::bigint,
       COALESCE(SUM(sum_sessions),0)::bigint,
       COALESCE(MAX(max_severity),0)::int, COALESCE(MAX(max_threat_id),0)::int, MAX(max_at)
  FROM network_flow_rollups
 WHERE org_id = $1
   AND ($2::text = '' OR cluster_id::text = $2)
   AND src_workload = $3 AND dst_workload = $4
   AND bucket >= date_trunc('hour', NOW() - ($5::int * INTERVAL '1 hour'))
 GROUP BY protocol, l7_protocol, dst_port, verdict
 ORDER BY SUM(sum_bytes) DESC
 LIMIT 200`, subj.OrgID, clusterID, from, to, hours)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	entries := []conversationEntryDTO{}
	var tBytes, tClient, tServer, tPkts, tSess int64
	for rows.Next() {
		var e conversationEntryDTO
		var l7 string
		var last time.Time
		if err := rows.Scan(&e.Protocol, &l7, &e.Port, &e.Verdict, &e.Bytes, &e.Packets,
			&e.ClientBytes, &e.ServerBytes, &e.Sessions, &e.Severity, &e.ThreatID, &last); err != nil {
			continue
		}
		e.Protocol = strings.ToUpper(e.Protocol)
		e.Application = strings.ToUpper(l7)
		e.Verdict = strings.ToLower(e.Verdict)
		e.LastSeenAt = last.UTC().Format(time.RFC3339)
		entries = append(entries, e)
		tBytes += e.Bytes
		tClient += e.ClientBytes
		tServer += e.ServerBytes
		tPkts += e.Packets
		tSess += e.Sessions
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to, "window_hours": hours,
		"entries": entries,
		"totals": map[string]int64{
			"bytes": tBytes, "client_bytes": tClient, "server_bytes": tServer,
			"packets": tPkts, "sessions": tSess,
		},
	})
}
