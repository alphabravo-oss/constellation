package network

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// peerDTO is one individual peer (a single IP) that a workload talked to or was reached by —
// NV's per-conversation peer list. Direction is relative to the workload: ingress = the peer
// initiated to us, egress = we initiated to the peer.
type peerDTO struct {
	PeerIP     string  `json:"peer_ip"`
	Peer       string  `json:"peer"`        // resolved workload id when the peer is in-cluster, else ""
	FQDN       string  `json:"fqdn,omitempty"`
	Direction  string  `json:"direction"`   // ingress | egress
	External   bool    `json:"external"`
	Bytes      int64   `json:"bytes"`
	Sessions   int64   `json:"sessions"`
	Packets    int64   `json:"packets"`
	Ports      []int32 `json:"ports"`
	Protocols  []string `json:"protocols"`
	Verdict    string  `json:"verdict"`
	LastSeenAt string  `json:"last_seen_at"`
}

// Peers lists every individual peer IP for a workload (both directions), with bytes / sessions /
// ports / last-seen — NV's "who is connected to this" drill-down, including external IPs.
// GET /network/peers?workload=ns/name&cluster_id=&hours=
func (h *Network) Peers(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	workload := strings.TrimSpace(r.URL.Query().Get("workload"))
	if workload == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "workload required"})
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*30 {
		hours = 24 * 7
	}
	clusterID, err := h.resolveNetworkCluster(r, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// One row per (direction, peer IP). For ingress the workload is the dst and the peer is the
	// src address; for egress it's mirrored. dp-source rows carry sessions; sum where present.
	// The peer's workload id (when it's an in-cluster address) is the opposite workload column.
	rows, err := h.db.Pool().Query(r.Context(), `
WITH ing AS (
  SELECT 'ingress'::text AS direction, nf.src_addr AS peer_ip, COALESCE(MIN(nf.src_workload),'') AS peer,
         COALESCE(SUM(nf.bytes),0)::bigint AS bytes, COALESCE(SUM(nf.packets),0)::bigint AS packets,
         COALESCE(SUM(nf.sessions),0)::bigint AS sessions,
         (COALESCE(array_agg(DISTINCT nf.dst_port) FILTER (WHERE nf.dst_port > 0), '{}'))[1:12] AS ports,
         COALESCE(array_agg(DISTINCT nf.protocol) FILTER (WHERE COALESCE(nf.protocol,'') <> ''), '{}') AS protos,
         COALESCE(MIN(nf.verdict),'allow') AS verdict, COALESCE(MAX(nf.fqdn),'') AS fqdn, MAX(nf.at) AS last_at
    FROM network_flows nf
   WHERE nf.org_id = $1 AND ($2::uuid IS NULL OR nf.cluster_id = $2)
     AND nf.dst_workload = $3 AND COALESCE(nf.src_addr,'') <> ''
     AND nf.at > now() - ($4 || ' hours')::interval
   GROUP BY nf.src_addr
),
egr AS (
  SELECT 'egress'::text AS direction, nf.dst_addr AS peer_ip, COALESCE(MIN(nf.dst_workload),'') AS peer,
         COALESCE(SUM(nf.bytes),0)::bigint AS bytes, COALESCE(SUM(nf.packets),0)::bigint AS packets,
         COALESCE(SUM(nf.sessions),0)::bigint AS sessions,
         (COALESCE(array_agg(DISTINCT nf.dst_port) FILTER (WHERE nf.dst_port > 0), '{}'))[1:12] AS ports,
         COALESCE(array_agg(DISTINCT nf.protocol) FILTER (WHERE COALESCE(nf.protocol,'') <> ''), '{}') AS protos,
         COALESCE(MIN(nf.verdict),'allow') AS verdict, COALESCE(MAX(nf.fqdn),'') AS fqdn, MAX(nf.at) AS last_at
    FROM network_flows nf
   WHERE nf.org_id = $1 AND ($2::uuid IS NULL OR nf.cluster_id = $2)
     AND nf.src_workload = $3 AND COALESCE(nf.dst_addr,'') <> ''
     AND nf.at > now() - ($4 || ' hours')::interval
   GROUP BY nf.dst_addr
)
SELECT * FROM ing UNION ALL SELECT * FROM egr
 ORDER BY bytes DESC
 LIMIT 500`, subj.OrgID, clusterID, workload, strconv.Itoa(hours))
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []peerDTO{}
	for rows.Next() {
		var p peerDTO
		var lastT time.Time
		if err := rows.Scan(&p.Direction, &p.PeerIP, &p.Peer, &p.Bytes, &p.Packets, &p.Sessions,
			&p.Ports, &p.Protocols, &p.Verdict, &p.FQDN, &lastT); err != nil {
			continue
		}
		p.LastSeenAt = lastT.UTC().Format(time.RFC3339)
		p.Verdict = strings.ToLower(p.Verdict)
		for i, pr := range p.Protocols {
			p.Protocols[i] = strings.ToUpper(pr)
		}
		// External when the peer's resolved workload id is 'external', or its IP classifies as
		// external (public / not an in-cluster workload). Blank the placeholder workload id.
		p.External = p.Peer == "external" || endpointKind(p.PeerIP) == "external"
		if p.Peer == "external" {
			p.Peer = ""
		}
		out = append(out, p)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"workload": workload, "peers": out})
}
