package network

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// exposedServiceDTO is one externally-facing service: a workload that talks to (egress)
// or is reached by (ingress) an endpoint outside the cluster, joined to its vulnerability
// rollup. Mirrors NeuVector's dashboard ingress/egress exposed-conversation lists, whose
// signature move is correlating EXPOSURE with VULNERABILITY (a reachable service with
// critical CVEs is the top remediation target).
type exposedServiceDTO struct {
	Workload      string   `json:"workload"` // "namespace/name"
	Namespace     string   `json:"namespace"`
	PlatformRole  string   `json:"platform_role"`
	Name          string   `json:"name"`
	ExternalPeers int      `json:"external_peers"` // distinct external IPs
	Protocols     []string `json:"protocols"`
	Ports         []int32  `json:"ports"`
	Sessions      int64    `json:"sessions"`
	Critical      int      `json:"critical"`
	High          int      `json:"high"`
	RiskScore     int      `json:"risk_score"`
	PolicyMode    string   `json:"policy_mode"` // strongest group mode covering the workload (NV per-endpoint policy_mode): discover=unprotected
}

// Exposure returns the cluster's externally-reachable services split into ingress
// (external → workload) and egress (workload → external), each with its vuln counts.
//
//	GET /api/v1/network/exposure?cluster_id=&hours=
func (h *Network) Exposure(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*30 {
		// Exposure is a posture signal, not a live metric — a service reachable from the
		// internet yesterday is still a finding today. Default to a 7-day window so an
		// intermittent flow-collection gap doesn't blank the panel.
		hours = 24 * 7
	}
	clusterID, err := h.resolveNetworkCluster(r, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// One query, parameterized by direction: 'ingress' groups the internal peer of flows
	// FROM external; 'egress' groups the internal peer of flows TO external. The internal
	// workload is the dst for ingress and the src for egress; the external counterpart is
	// the opposite endpoint. Restrict to real workloads ("namespace/name"), excluding the
	// literal 'external' and host-scoped ids.
	query := func(direction string) ([]exposedServiceDTO, error) {
		internalCol, externalWL, externalAddr := "nf.dst_workload", "nf.src_workload", "nf.src_addr"
		if direction == "egress" {
			internalCol, externalWL, externalAddr = "nf.src_workload", "nf.dst_workload", "nf.dst_addr"
		}
		// wl_mode: strongest group policy_mode covering each workload (NV per-endpoint
		// policy_mode). An exposed service still in discover is unprotected attack surface.
		// Aggregate source observations before joining deployment rollups. An
		// endpoint shared by several workload kinds must not multiply sessions.
		sql := `
WITH wl_mode AS (
  SELECT jsonb_array_elements_text(g.members) AS wl,
         MAX(CASE g.policy_mode WHEN 'protect' THEN 3 WHEN 'monitor' THEN 2 ELSE 1 END) AS r
    FROM groups g
   WHERE g.org_id = $1 AND ($2::uuid IS NULL OR g.cluster_id = $2)
   GROUP BY 1
), scoped AS (
 SELECT ` + internalCol + ` AS workload, ` + externalAddr + ` AS external_addr,
        nf.cluster_id, nf.protocol, nf.dst_port, nf.sessions
   FROM network_flows nf
  WHERE nf.org_id = $1
    AND ($2::uuid IS NULL OR nf.cluster_id = $2)
    AND ` + externalWL + ` = 'external'
    AND COALESCE(` + internalCol + `, '') NOT IN ('external', '')
    AND ` + internalCol + ` NOT LIKE 'host/%'
    AND nf.at > now() - ($3 || ' hours')::interval
), observed AS (
 SELECT workload, count(DISTINCT external_addr)::int AS external_peers,
        COALESCE(array_agg(DISTINCT protocol) FILTER (WHERE COALESCE(protocol,'') <> ''), '{}') AS protocols,
        (COALESCE(array_agg(DISTINCT dst_port) FILTER (WHERE dst_port > 0), '{}'))[1:12] AS ports,
        COALESCE(sum(sessions), 0)::bigint AS sessions,
        array_agg(DISTINCT cluster_id) AS cluster_ids,
        CASE WHEN COUNT(DISTINCT cluster_id) = 1 AND bool_and(cluster_id IS NOT NULL)
             THEN (array_agg(cluster_id))[1] ELSE NULL END AS role_cluster_id
   FROM scoped GROUP BY workload
)
SELECT observed.workload, observed.external_peers, observed.protocols,
       observed.ports, observed.sessions,
       COALESCE(d.critical, 0)::int AS critical,
       COALESCE(d.high, 0)::int AS high,
       COALESCE(d.risk_score, 0)::int AS risk_score,
       CASE m.r WHEN 3 THEN 'protect' WHEN 2 THEN 'monitor' WHEN 1 THEN 'discover' ELSE '' END AS policy_mode,
       observed.role_cluster_id
  FROM observed
  LEFT JOIN LATERAL (
    SELECT max(critical_count) AS critical, max(high_count) AS high, max(risk_score) AS risk_score
      FROM deployments d
     WHERE d.org_id = $1 AND d.cluster_id = ANY(observed.cluster_ids)
       AND (d.namespace || '/' || d.name) = observed.workload
  ) d ON true
  LEFT JOIN wl_mode m ON m.wl = observed.workload
 ORDER BY critical DESC, high DESC, sessions DESC, observed.workload ASC
 LIMIT 50`
		rows, err := h.db.Pool().Query(r.Context(), sql, subj.OrgID, clusterID, strconv.Itoa(hours))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []exposedServiceDTO{}
		identities := []handler.PlatformWorkloadIdentity{}
		for rows.Next() {
			var s exposedServiceDTO
			var sourceCluster *uuid.UUID
			if err := rows.Scan(&s.Workload, &s.ExternalPeers, &s.Protocols, &s.Ports,
				&s.Sessions, &s.Critical, &s.High, &s.RiskScore, &s.PolicyMode, &sourceCluster); err != nil {
				return nil, err
			}
			s.Namespace, s.Name = splitWorkload(s.Workload)
			identity := handler.PlatformWorkloadIdentity{Workload: s.Workload}
			if sourceCluster != nil {
				identity.ClusterID = *sourceCluster
			}
			identities = append(identities, identity)
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		rows.Close()
		roles, err := handler.EvidencePlatformRoles(r.Context(), h.db.Pool(), subj.OrgID, identities)
		if err != nil {
			return nil, err
		}
		for i := range out {
			out[i].PlatformRole = roles[i]
		}
		return out, nil
	}

	ingress, err := query("ingress")
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	egress, err := query("egress")
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ingress": ingress, "egress": egress})
}

func splitWorkload(wl string) (namespace, name string) {
	for i := 0; i < len(wl); i++ {
		if wl[i] == '/' {
			return wl[:i], wl[i+1:]
		}
	}
	return "", wl
}
