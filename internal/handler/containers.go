package handler

import (
	"net/http"
)

// containerRow is one running container in the cluster, aggregated across every node's
// runtime-agent container inventory and enriched with its workload's security posture.
// This is the per-running-container view NeuVector's Assets → Containers page shows;
// Constellation previously only aggregated to the deployment level.
type containerRow struct {
	Node       string `json:"node"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	PodName    string `json:"pod_name"`
	Image      string `json:"image"`
	State      string `json:"state"`
	Workload   string `json:"workload,omitempty"`
	Privileged bool   `json:"privileged"`
	RunAsRoot  bool   `json:"run_as_root"`
	RiskScore  int    `json:"risk_score"`
	Critical   int    `json:"critical"`
	High       int    `json:"high"`
}

// Containers returns the cluster's running containers by unnesting each node's
// host_containers inventory, best-effort mapped to their owning deployment (pod name
// starts with the deployment name) for privileged/root/risk enrichment.
//
//	GET /api/v1/clusters/{id}/containers
func (h *Nodes) Containers(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterID, ok := h.clusterIDFromRoute(w, r, subj.OrgID)
	if !ok {
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
WITH conts AS (
    SELECT hc.node,
           COALESCE(item->>'id', '')                                   AS id,
           COALESCE(item->>'name', '')                                 AS name,
           COALESCE(item->>'pod_namespace', '')                        AS namespace,
           COALESCE(item->>'pod_name', '')                             AS pod_name,
           COALESCE(NULLIF(item->>'image_ref',''), item->>'image', '') AS image,
           COALESCE(item->>'state', '')                                AS state
      FROM host_containers hc,
           jsonb_array_elements(hc.payload->'items') AS item
     WHERE hc.org_id = $1 AND hc.cluster_id = $2
)
SELECT c.node, c.id, c.name, c.namespace, c.pod_name, c.image, c.state,
       COALESCE(d.name, '')                                  AS workload,
       COALESCE(d.risk_factors ? 'privileged', false)        AS privileged,
       COALESCE(d.risk_factors ? 'run_as_root', false)       AS run_as_root,
       COALESCE(d.risk_score, 0)                             AS risk_score,
       COALESCE(d.critical_count, 0)                         AS critical,
       COALESCE(d.high_count, 0)                             AS high
  FROM conts c
  LEFT JOIN LATERAL (
      SELECT dd.name, dd.risk_factors, dd.risk_score, dd.critical_count, dd.high_count
        FROM deployments dd
       WHERE dd.org_id = $1 AND dd.cluster_id = $2
         AND dd.namespace = c.namespace
         AND c.pod_name LIKE dd.name || '-%'
       ORDER BY length(dd.name) DESC
       LIMIT 1
  ) d ON true
 ORDER BY c.namespace, c.pod_name, c.name
 LIMIT 3000`, subj.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query containers: "+err.Error())
		return
	}
	defer rows.Close()

	out := []containerRow{}
	running := 0
	for rows.Next() {
		var c containerRow
		if err := rows.Scan(&c.Node, &c.ID, &c.Name, &c.Namespace, &c.PodName, &c.Image, &c.State,
			&c.Workload, &c.Privileged, &c.RunAsRoot, &c.RiskScore, &c.Critical, &c.High); err != nil {
			jsonError(w, http.StatusInternalServerError, "scan container: "+err.Error())
			return
		}
		if c.State == "CONTAINER_RUNNING" || c.State == "running" {
			running++
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	priv, root := 0, 0
	for i := range out {
		if out[i].Privileged {
			priv++
		}
		if out[i].RunAsRoot {
			root++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id": clusterID.String(),
		"items":      out,
		"summary": map[string]int{
			"total": len(out), "running": running, "privileged": priv, "run_as_root": root,
		},
	})
}
