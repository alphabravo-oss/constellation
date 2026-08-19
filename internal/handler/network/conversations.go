package network

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
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

	// Plan B5: serve from the hot in-memory graph when enabled. The cache only
	// holds the recent TTL window, so it's used as a low-latency accelerator;
	// when it has nothing for this org we fall through to the durable SQL path.
	if h.live != nil {
		var cid *uuid.UUID
		if clusterID != "" {
			if u, err := uuid.Parse(clusterID); err == nil {
				cid = &u
			}
		}
		g := h.live.Snapshot(subj.OrgID, cid)
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
 GROUP BY src_workload, dst_workload, protocol, dst_port, l7_protocol, verdict
 ORDER BY SUM(sum_bytes) DESC
 LIMIT 5000`, subj.OrgID, clusterID, hours)
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
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"conversations": g.Conversations(),
		"nodes":         nodes,
		"node_kinds":    nodeKinds(nodes),
		"edges":         g.Edges(),
		"window_hours":  hours,
	})
}
