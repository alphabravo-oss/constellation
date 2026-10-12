package network

import (
	"context"
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

type platformConversation struct {
	graph.Conversation
	RowID            string `json:"row_id"`
	FromPlatformRole string `json:"from_platform_role,omitempty"`
	ToPlatformRole   string `json:"to_platform_role,omitempty"`
}

func (h *NetworkConversations) platformConversations(ctx context.Context, orgID uuid.UUID, clusterID *uuid.UUID, conversations []graph.Conversation) ([]platformConversation, error) {
	return h.platformConversationsWithQuerier(ctx, h.db.Pool(), orgID, clusterID, conversations)
}

func (h *NetworkConversations) platformConversationsWithQuerier(ctx context.Context, q handler.PlatformRoleQuerier, orgID uuid.UUID, clusterID *uuid.UUID, conversations []graph.Conversation) ([]platformConversation, error) {
	workloads := make([]string, 0, len(conversations)*2)
	for _, conversation := range conversations {
		workloads = append(workloads, conversation.From, conversation.To)
	}
	roles, err := h.conversationPlatformRolesWithQuerier(ctx, q, orgID, clusterID, workloads...)
	if err != nil {
		return nil, err
	}
	out := make([]platformConversation, 0, len(conversations))
	for _, conversation := range conversations {
		out = append(out, platformConversation{
			Conversation:     conversation,
			RowID:            conversationRowID(conversation.From, conversation.To),
			FromPlatformRole: roles[conversation.From],
			ToPlatformRole:   roles[conversation.To],
		})
	}
	return out, nil
}

// Org-wide conversation folding intentionally does not infer an installation
// when several clusters can contribute the same endpoint name.
func (h *NetworkConversations) conversationPlatformRoles(ctx context.Context, orgID uuid.UUID, clusterID *uuid.UUID, workloads ...string) (map[string]string, error) {
	return h.conversationPlatformRolesWithQuerier(ctx, h.db.Pool(), orgID, clusterID, workloads...)
}

func (h *NetworkConversations) conversationPlatformRolesWithQuerier(ctx context.Context, q handler.PlatformRoleQuerier, orgID uuid.UUID, clusterID *uuid.UUID, workloads ...string) (map[string]string, error) {
	if clusterID == nil {
		rows, err := q.Query(ctx, `SELECT id FROM clusters WHERE org_id = $1 LIMIT 2`, orgID)
		if err != nil {
			return nil, err
		}
		var onlyCluster uuid.UUID
		count := 0
		for rows.Next() {
			if err := rows.Scan(&onlyCluster); err != nil {
				rows.Close()
				return nil, err
			}
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if count == 1 {
			clusterID = &onlyCluster
		}
	}
	identities := make([]handler.PlatformWorkloadIdentity, len(workloads))
	for i, workload := range workloads {
		if endpointKind(workload) != "workload" {
			continue
		}
		identities[i].Workload = workload
		if clusterID != nil {
			identities[i].ClusterID = *clusterID
		}
	}
	resolved, err := handler.EvidencePlatformRoles(ctx, q, orgID, identities)
	if err != nil {
		return nil, err
	}
	roles := make(map[string]string, len(workloads))
	for i, workload := range workloads {
		roles[workload] = resolved[i]
	}
	return roles, nil
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
// bounded graph snapshot for legacy requests. Sorted/paged inventory and CSV
// always use the durable rollups for complete matching summaries.
func (h *NetworkConversations) WithLiveGraph(s *livegraph.Store) *NetworkConversations {
	h.live = s
	return h
}

func (h *NetworkConversations) List(w http.ResponseWriter, r *http.Request) {
	h.listConversations(w, r, false)
}

// ListCSV exports the same complete matching rollup cohort, up to 100,000 pairs.
func (h *NetworkConversations) ListCSV(w http.ResponseWriter, r *http.Request) {
	h.listConversations(w, r, true)
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
	var clusterUUID *uuid.UUID
	if clusterID != "" {
		u, err := uuid.Parse(clusterID)
		if err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster_id"})
			return
		}
		clusterUUID = &u
	}
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
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read conversation entries"})
			return
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
	if err := rows.Err(); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read conversation entries"})
		return
	}
	rows.Close()
	response := map[string]any{
		"from": from, "to": to, "window_hours": hours,
		"entries": entries,
		"totals": map[string]int64{
			"bytes": tBytes, "client_bytes": tClient, "server_bytes": tServer,
			"packets": tPkts, "sessions": tSess,
		},
	}
	if len(entries) > 0 {
		roles, err := h.conversationPlatformRoles(r.Context(), subj.OrgID, clusterUUID, from, to)
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not classify conversation entries"})
			return
		}
		if role := roles[from]; role != "" {
			response["from_platform_role"] = role
		}
		if role := roles[to]; role != "" {
			response["to_platform_role"] = role
		}
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}
