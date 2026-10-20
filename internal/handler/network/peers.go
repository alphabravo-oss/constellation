package network

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// peerDTO is one individual peer (a single IP) that a workload talked to or was reached by —
// NV's per-conversation peer list. Direction is relative to the workload: ingress = the peer
// initiated to us, egress = we initiated to the peer.
type peerDTO struct {
	PeerPlatformRole string     `json:"peer_platform_role"`
	PeerClusterID    *uuid.UUID `json:"peer_cluster_id"`
	PeerIP           string     `json:"peer_ip"`
	Peer             string     `json:"peer"` // resolved workload id when the peer is in-cluster, else ""
	FQDN             string     `json:"fqdn,omitempty"`
	Direction        string     `json:"direction"` // ingress | egress
	External         bool       `json:"external"`
	Bytes            int64      `json:"bytes"`
	Sessions         int64      `json:"sessions"`
	Packets          int64      `json:"packets"`
	Ports            []int32    `json:"ports"`
	Protocols        []string   `json:"protocols"`
	Verdict          string     `json:"verdict"`
	LastSeenAt       string     `json:"last_seen_at"`
}

// Peers lists every individual peer IP for a workload (both directions), with bytes / sessions /
// ports / last-seen — NV's "who is connected to this" drill-down, including external IPs.
// GET /network/peers?workload=ns/name&cluster_id=&hours=
func (h *Network) Peers(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 400, "invalid query")
		return
	}
	for _, values := range query {
		if len(values) != 1 {
			apiutil.WriteStatus(r.Context(), w, 400, "duplicate query parameter")
			return
		}
	}
	workload := strings.TrimSpace(query.Get("workload"))
	if workload == "" {
		apiutil.WriteStatus(r.Context(), w, 400, "workload required")
		return
	}
	hide := false
	if raw := query.Get("hide_platform"); raw != "" {
		if raw != "true" && raw != "false" {
			apiutil.WriteStatus(r.Context(), w, 400, "hide_platform must be true or false")
			return
		}
		hide = raw == "true"
	}
	hours, _ := strconv.Atoi(query.Get("hours"))
	if hours <= 0 || hours > 24*30 {
		hours = 24 * 7
	}
	tx, err := h.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 500, err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	// Preserve the legacy selected-cluster default, but never suppress a lookup failure
	// or classify records through a cluster owned by another organization.
	var clusterID *uuid.UUID
	if raw := strings.TrimSpace(query.Get("cluster_id")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			apiutil.WriteStatus(r.Context(), w, 400, "invalid cluster_id")
			return
		}
		var exists bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, subj.OrgID, parsed).Scan(&exists); err != nil {
			apiutil.WriteStatus(r.Context(), w, 500, err.Error())
			return
		}
		if !exists {
			apiutil.WriteStatus(r.Context(), w, 400, "cluster not found")
			return
		}
		clusterID = &parsed
	} else {
		var selected uuid.UUID
		err := tx.QueryRow(r.Context(), `SELECT id FROM clusters WHERE org_id=$1 ORDER BY CASE WHEN state='connected' THEN 0 ELSE 1 END,last_heartbeat_at DESC NULLS LAST,created_at ASC,id ASC LIMIT 1`, subj.OrgID).Scan(&selected)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			apiutil.WriteStatus(r.Context(), w, 500, err.Error())
			return
		}
		if err == nil {
			clusterID = &selected
		}
	}
	roleSQL := handler.EvidencePlatformRoleSQL("$1::uuid", "$2::uuid", "$3::text", "''")
	workloadRole := ""
	if clusterID != nil {
		if err := tx.QueryRow(r.Context(), `SELECT `+roleSQL, subj.OrgID, clusterID, workload).Scan(&workloadRole); err != nil {
			apiutil.WriteStatus(r.Context(), w, 500, err.Error())
			return
		}
	}
	// Classify distinct actual source identities before folding by IP. A shared IP
	// cannot borrow one arbitrarily selected workload's role or cluster.
	sql := fmt.Sprintf(`WITH endpoints AS MATERIALIZED (
 SELECT nf.org_id,nf.cluster_id,'ingress'::text AS direction,nf.src_addr AS peer_ip,nf.src_workload AS peer,
 nf.bytes,nf.packets,nf.sessions,nf.dst_port,nf.protocol,nf.verdict,nf.fqdn,nf.at
 FROM network_flows nf JOIN clusters c ON c.id=nf.cluster_id AND c.org_id=nf.org_id
 WHERE nf.org_id=$1 AND nf.cluster_id=$2 AND nf.dst_workload=$3 AND COALESCE(nf.src_addr,'')<>'' AND nf.at>now()-($4||' hours')::interval
 UNION ALL
 SELECT nf.org_id,nf.cluster_id,'egress',nf.dst_addr,nf.dst_workload,nf.bytes,nf.packets,nf.sessions,nf.dst_port,nf.protocol,nf.verdict,nf.fqdn,nf.at
 FROM network_flows nf JOIN clusters c ON c.id=nf.cluster_id AND c.org_id=nf.org_id
 WHERE nf.org_id=$1 AND nf.cluster_id=$2 AND nf.src_workload=$3 AND COALESCE(nf.dst_addr,'')<>'' AND nf.at>now()-($4||' hours')::interval
 ), identities AS MATERIALIZED (
 SELECT DISTINCT org_id,cluster_id,peer FROM endpoints
 ), roles AS MATERIALIZED (SELECT i.*, %s AS peer_role FROM identities i),
 matching AS (
 SELECT e.*,r.peer_role FROM endpoints e JOIN roles r USING(org_id,cluster_id,peer)
 WHERE NOT $5::boolean OR ($6::text='' AND r.peer_role='')
 ), folded AS (
 SELECT direction,peer_ip,
 CASE WHEN count(DISTINCT (cluster_id,peer))=1 THEN min(peer) ELSE '' END AS peer,
 CASE WHEN count(DISTINCT (cluster_id,peer))=1 THEN min(peer_role) ELSE '' END AS peer_role,
 CASE WHEN count(DISTINCT (cluster_id,peer))=1 AND min(peer) NOT IN ('','external') THEN min(cluster_id::text)::uuid ELSE NULL END AS peer_cluster_id,
 COALESCE(sum(bytes),0)::bigint AS bytes,COALESCE(sum(packets),0)::bigint AS packets,COALESCE(sum(sessions),0)::bigint AS sessions,
 (COALESCE(array_agg(DISTINCT dst_port ORDER BY dst_port) FILTER(WHERE dst_port>0),'{}'))[1:12] AS ports,
 COALESCE(array_agg(DISTINCT protocol ORDER BY protocol) FILTER(WHERE COALESCE(protocol,'')<>''),'{}') AS protos,
 COALESCE(min(verdict),'allow') AS verdict,COALESCE(max(fqdn),'') AS fqdn,max(at) AS last_at
 FROM matching GROUP BY direction,peer_ip
 ) SELECT *,count(*) OVER() FROM folded ORDER BY bytes DESC,direction ASC,peer_ip ASC LIMIT 500`, handler.EvidencePlatformRoleSQL("i.org_id", "i.cluster_id", "i.peer", "''"))
	rows, err := tx.Query(r.Context(), sql, subj.OrgID, clusterID, workload, strconv.Itoa(hours), hide, workloadRole)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 500, err.Error())
		return
	}
	out := []peerDTO{}
	var total int64
	for rows.Next() {
		var p peerDTO
		var lastT time.Time
		if err := rows.Scan(&p.Direction, &p.PeerIP, &p.Peer, &p.PeerPlatformRole, &p.PeerClusterID, &p.Bytes, &p.Packets, &p.Sessions, &p.Ports, &p.Protocols, &p.Verdict, &p.FQDN, &lastT, &total); err != nil {
			rows.Close()
			apiutil.WriteStatus(r.Context(), w, 500, err.Error())
			return
		}
		p.LastSeenAt = lastT.UTC().Format(time.RFC3339)
		p.Verdict = strings.ToLower(p.Verdict)
		for i, pr := range p.Protocols {
			p.Protocols[i] = strings.ToUpper(pr)
		}
		p.External = p.Peer == "external" || endpointKind(p.PeerIP) == "external"
		if p.Peer == "external" {
			p.Peer = ""
		}
		if p.Peer == "" || net.ParseIP(p.Peer) != nil {
			p.PeerClusterID = nil
		}
		// Literal IP and unresolved external identities carry no workload role.
		out = append(out, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 500, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		apiutil.WriteStatus(r.Context(), w, 500, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"workload": workload, "cluster_id": clusterID, "workload_platform_role": workloadRole, "hide_platform": hide, "source_limit": 500, "total": total, "has_more": total > int64(len(out)), "peers": out})
}
