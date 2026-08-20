package network

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// sessionIngestRow is the wire shape the runtime-agent POSTs to /network-sessions:bulk.
// One row per live dp session (NV RESTSession). Field tags match the agent's dp_session.go.
type sessionIngestRow struct {
	ID           int64  `json:"id"`
	Node         string `json:"node,omitempty"`
	EPMAC        string `json:"ep_mac,omitempty"`
	WorkloadID   string `json:"workload_id,omitempty"`
	EtherType    int    `json:"ether_type,omitempty"`
	IPProto      int    `json:"ip_proto,omitempty"`
	Application  int    `json:"application,omitempty"`
	ClientMAC    string `json:"client_mac,omitempty"`
	ServerMAC    string `json:"server_mac,omitempty"`
	ClientIP     string `json:"client_ip,omitempty"`
	ServerIP     string `json:"server_ip,omitempty"`
	ClientPort   int    `json:"client_port,omitempty"`
	ServerPort   int    `json:"server_port,omitempty"`
	ICMPCode     int    `json:"icmp_code,omitempty"`
	ICMPType     int    `json:"icmp_type,omitempty"`
	ClientPkts   int64  `json:"client_pkts,omitempty"`
	ServerPkts   int64  `json:"server_pkts,omitempty"`
	ClientBytes  int64  `json:"client_bytes,omitempty"`
	ServerBytes  int64  `json:"server_bytes,omitempty"`
	ClientAsmPkts  int64 `json:"client_asm_pkts,omitempty"`
	ServerAsmPkts  int64 `json:"server_asm_pkts,omitempty"`
	ClientAsmBytes int64 `json:"client_asm_bytes,omitempty"`
	ServerAsmBytes int64 `json:"server_asm_bytes,omitempty"`
	ClientState  int    `json:"client_state,omitempty"`
	ServerState  int    `json:"server_state,omitempty"`
	Idle         int    `json:"idle,omitempty"`
	Age          int    `json:"age,omitempty"`
	Life         int    `json:"life,omitempty"`
	ThreatID     int64  `json:"threat_id,omitempty"`
	PolicyID     int64  `json:"policy_id,omitempty"`
	PolicyAction int    `json:"policy_action,omitempty"`
	Severity     int    `json:"severity,omitempty"`
	Ingress      bool   `json:"ingress,omitempty"`
	Tap          bool   `json:"tap,omitempty"`
	MidStream    bool   `json:"mid_stream,omitempty"`
	XffIP        string `json:"xff_ip,omitempty"`
	XffApp       int    `json:"xff_app,omitempty"`
	XffPort      int    `json:"xff_port,omitempty"`
}

const maxSessionBatchSize = 5000

// IngestSessions replaces the live-session snapshot for the reporting node. Auth is the
// runtime-agent token; the snapshot fully replaces the node's rows (dp already sends a
// complete ctrl_list_session dump), so the table always reflects current connections.
// POST /network-sessions:bulk
func (h *Network) IngestSessions(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "runtime-agent token required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var rows []sessionIngestRow
	if err := json.NewDecoder(r.Body).Decode(&rows); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body: " + err.Error()})
		return
	}
	if len(rows) > maxSessionBatchSize {
		httpx.WriteJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("batch > %d", maxSessionBatchSize)})
		return
	}
	// Resolve the agent's cluster (org primary connected cluster), same fallback as
	// runtime-threats ingest.
	var clusterID uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT id FROM clusters WHERE org_id = $1
		 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END,
		          last_heartbeat_at DESC NULLS LAST, created_at ASC
		 LIMIT 1`, tok.OrgID).Scan(&clusterID); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"accepted": 0, "note": "no cluster"})
		return
	}
	// The reporting node — all rows in a snapshot share it (the agent sets it per row).
	node := ""
	if len(rows) > 0 {
		node = rows[0].Node
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Replace this node's snapshot atomically.
	if _, err := tx.Exec(r.Context(),
		`DELETE FROM network_sessions WHERE org_id = $1 AND cluster_id = $2 AND node = $3`,
		tok.OrgID, clusterID, node); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	const insertSQL = `
INSERT INTO network_sessions
  (org_id, cluster_id, node, id, ep_mac, workload_id, ether_type, ip_proto, application,
   client_mac, server_mac, client_ip, server_ip, client_port, server_port, icmp_code, icmp_type,
   client_pkts, server_pkts, client_bytes, server_bytes,
   client_asm_pkts, server_asm_pkts, client_asm_bytes, server_asm_bytes,
   client_state, server_state, idle, age, life, threat_id, policy_id, policy_action, severity,
   ingress, tap, mid_stream, xff_ip, xff_app, xff_port, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,NOW())
ON CONFLICT (org_id, cluster_id, node, id) DO UPDATE SET
  client_bytes = EXCLUDED.client_bytes, server_bytes = EXCLUDED.server_bytes,
  client_pkts = EXCLUDED.client_pkts, server_pkts = EXCLUDED.server_pkts,
  client_state = EXCLUDED.client_state, server_state = EXCLUDED.server_state,
  idle = EXCLUDED.idle, age = EXCLUDED.age, updated_at = NOW()`
	accepted := 0
	for _, s := range rows {
		if _, err := tx.Exec(r.Context(), insertSQL,
			tok.OrgID, clusterID, s.Node, s.ID, strings.ToLower(s.EPMAC), s.WorkloadID, s.EtherType, s.IPProto, s.Application,
			strings.ToLower(s.ClientMAC), strings.ToLower(s.ServerMAC), s.ClientIP, s.ServerIP, s.ClientPort, s.ServerPort, s.ICMPCode, s.ICMPType,
			s.ClientPkts, s.ServerPkts, s.ClientBytes, s.ServerBytes,
			s.ClientAsmPkts, s.ServerAsmPkts, s.ClientAsmBytes, s.ServerAsmBytes,
			s.ClientState, s.ServerState, s.Idle, s.Age, s.Life, s.ThreatID, s.PolicyID, s.PolicyAction, s.Severity,
			s.Ingress, s.Tap, s.MidStream, s.XffIP, s.XffApp, s.XffPort); err != nil {
			continue
		}
		accepted++
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"accepted": accepted})
}

// sessionDTO is one live connection returned to the UI (NV RESTSession).
type sessionDTO struct {
	ID          int64  `json:"id"`
	Node        string `json:"node"`
	WorkloadID  string `json:"workload_id,omitempty"`
	Application string `json:"application"`
	IPProto     string `json:"ip_proto"`
	ClientIP    string `json:"client_ip"`
	ClientPort  int    `json:"client_port"`
	ServerIP    string `json:"server_ip"`
	ServerPort  int    `json:"server_port"`
	ClientState string `json:"client_state"`
	ServerState string `json:"server_state"`
	ClientBytes int64  `json:"client_bytes"`
	ServerBytes int64  `json:"server_bytes"`
	ClientPkts  int64  `json:"client_pkts"`
	ServerPkts  int64  `json:"server_pkts"`
	Age         int    `json:"age"`
	Idle        int    `json:"idle"`
	Ingress     bool   `json:"ingress"`
	Severity    int    `json:"severity"`
	ThreatID    int64  `json:"threat_id,omitempty"`
}

// Sessions returns the current live connection table (NV's Network > Sessions). Cluster-scoped;
// stale rows (node stopped reporting > 5 min) are excluded so the view stays "live".
// GET /network/sessions
func (h *Network) Sessions(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterID, err := h.resolveNetworkCluster(r, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, node, workload_id, application, ip_proto,
       client_ip, client_port, server_ip, server_port, client_state, server_state,
       client_bytes, server_bytes, client_pkts, server_pkts, age, idle, ingress, severity, threat_id
  FROM network_sessions
 WHERE org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2)
   AND updated_at > NOW() - INTERVAL '5 minutes'
 ORDER BY (client_bytes + server_bytes) DESC, age DESC
 LIMIT $3`, subj.OrgID, clusterID, limit)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"sessions": []sessionDTO{}})
		return
	}
	defer rows.Close()
	out := []sessionDTO{}
	for rows.Next() {
		var s sessionDTO
		var proto, cstate, sstate int
		if err := rows.Scan(&s.ID, &s.Node, &s.WorkloadID, new(int), &proto,
			&s.ClientIP, &s.ClientPort, &s.ServerIP, &s.ServerPort, &cstate, &sstate,
			&s.ClientBytes, &s.ServerBytes, &s.ClientPkts, &s.ServerPkts, &s.Age, &s.Idle, &s.Ingress, &s.Severity, &s.ThreatID); err != nil {
			continue
		}
		s.IPProto = ipProtoName(proto)
		s.Application = appLabel(proto, s.ServerPort)
		s.ClientState = tcpStateName(cstate)
		s.ServerState = tcpStateName(sstate)
		out = append(out, s)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// SessionsSummary returns live-session counts (NV RESTSessionSummary): total + by IP proto.
// GET /network/sessions/summary
func (h *Network) SessionsSummary(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterID, err := h.resolveNetworkCluster(r, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var total, tcp, udp, icmp, other int
	_ = h.db.Pool().QueryRow(r.Context(), `
SELECT COUNT(*)::int,
       COUNT(*) FILTER (WHERE ip_proto = 6)::int,
       COUNT(*) FILTER (WHERE ip_proto = 17)::int,
       COUNT(*) FILTER (WHERE ip_proto IN (1,58))::int,
       COUNT(*) FILTER (WHERE ip_proto NOT IN (6,17,1,58))::int
  FROM network_sessions
 WHERE org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2)
   AND updated_at > NOW() - INTERVAL '5 minutes'`, subj.OrgID, clusterID).
		Scan(&total, &tcp, &udp, &icmp, &other)
	httpx.WriteJSON(w, http.StatusOK, map[string]int{
		"total": total, "tcp": tcp, "udp": udp, "icmp": icmp, "other": other,
	})
}

// ipProtoName maps an IP protocol number to a short name.
func ipProtoName(p int) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	case 0:
		return ""
	default:
		return fmt.Sprintf("proto-%d", p)
	}
}

// appLabel is a best-effort L7 label from the well-known server port. dp carries an
// application id too but we don't ship its name table yet; the port is the honest signal.
func appLabel(proto, port int) string {
	switch port {
	case 80, 8080, 8000:
		return "HTTP"
	case 443, 8443:
		return "HTTPS"
	case 53:
		return "DNS"
	case 22:
		return "SSH"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 27017:
		return "MongoDB"
	}
	return ipProtoName(proto)
}

// tcpStateName maps dp's TCP state enum (matching NeuVector's dpi/dpi_session.h ordering)
// to a readable label. Non-TCP sessions report 0 → "".
func tcpStateName(s int) string {
	names := []string{"", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSED"}
	if s >= 0 && s < len(names) {
		return names[s]
	}
	return fmt.Sprintf("state-%d", s)
}
