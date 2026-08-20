package network

import (
	"net/http"
	"strconv"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// exposedServiceDTO is one externally-facing service: a workload that talks to (egress)
// or is reached by (ingress) an endpoint outside the cluster, joined to its vulnerability
// rollup. Mirrors NeuVector's dashboard ingress/egress exposed-conversation lists, whose
// signature move is correlating EXPOSURE with VULNERABILITY (a reachable service with
// critical CVEs is the top remediation target).
type exposedServiceDTO struct {
	Workload      string   `json:"workload"`   // "namespace/name"
	Namespace     string   `json:"namespace"`
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
		sql := `
WITH wl_mode AS (
  SELECT jsonb_array_elements_text(g.members) AS wl,
         MAX(CASE g.policy_mode WHEN 'protect' THEN 3 WHEN 'monitor' THEN 2 ELSE 1 END) AS r
    FROM groups g
   WHERE g.org_id = $1 AND ($2::uuid IS NULL OR g.cluster_id = $2)
   GROUP BY 1)
SELECT ` + internalCol + ` AS workload,
       count(DISTINCT ` + externalAddr + `)::int                                   AS external_peers,
       COALESCE(array_agg(DISTINCT nf.protocol) FILTER (WHERE COALESCE(nf.protocol,'') <> ''), '{}') AS protocols,
       (COALESCE(array_agg(DISTINCT nf.dst_port) FILTER (WHERE nf.dst_port > 0), '{}'))[1:12]         AS ports,
       COALESCE(sum(nf.sessions), 0)::bigint                                        AS sessions,
       COALESCE(max(d.critical_count), 0)::int                                      AS critical,
       COALESCE(max(d.high_count), 0)::int                                          AS high,
       COALESCE(max(d.risk_score), 0)::int                                          AS risk_score,
       CASE max(m.r) WHEN 3 THEN 'protect' WHEN 2 THEN 'monitor' WHEN 1 THEN 'discover' ELSE '' END AS policy_mode
  FROM network_flows nf
  LEFT JOIN deployments d
    ON d.org_id = nf.org_id AND d.cluster_id = nf.cluster_id
   AND (d.namespace || '/' || d.name) = ` + internalCol + `
  LEFT JOIN wl_mode m ON m.wl = ` + internalCol + `
 WHERE nf.org_id = $1
   AND ($2::uuid IS NULL OR nf.cluster_id = $2)
   AND ` + externalWL + ` = 'external'
   AND COALESCE(` + internalCol + `, '') NOT IN ('external', '')
   AND ` + internalCol + ` NOT LIKE 'host/%'
   AND nf.at > now() - ($3 || ' hours')::interval
 GROUP BY ` + internalCol + `
 ORDER BY critical DESC, high DESC, sessions DESC
 LIMIT 50`
		rows, err := h.db.Pool().Query(r.Context(), sql, subj.OrgID, clusterID, strconv.Itoa(hours))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []exposedServiceDTO{}
		for rows.Next() {
			var s exposedServiceDTO
			if err := rows.Scan(&s.Workload, &s.ExternalPeers, &s.Protocols, &s.Ports,
				&s.Sessions, &s.Critical, &s.High, &s.RiskScore, &s.PolicyMode); err != nil {
				return nil, err
			}
			s.Namespace, s.Name = splitWorkload(s.Workload)
			out = append(out, s)
		}
		return out, rows.Err()
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
