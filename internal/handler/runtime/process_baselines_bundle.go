package runtime

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/google/uuid"
)

// process baseline bundle — the agent-side process enforcer pulls this to learn,
// per workload, the current mode and the allowed-process basename set. Mirrors
// FileProfiles.AgentRulesBundle exactly, but the allowed set is DB-derived (from
// process_baseline_states + the events-table observations), NOT from in-memory
// state, so a fresh agent or a restarted api still gets a correct bundle.

type processBaselineBundleRow struct {
	WorkloadID     string   `json:"workload_id"`
	PodWorkloadIDs []string `json:"pod_workload_ids,omitempty"`
	Namespace      string   `json:"namespace,omitempty"`
	Name           string   `json:"name,omitempty"`
	Mode           string   `json:"mode"`      // learn|monitor|enforce
	Processes      []string `json:"processes"` // allowed basenames, deduped+sorted
	UpdatedAt      string   `json:"updated_at"`
}

type processBaselineBundleDTO struct {
	ClusterID   string                     `json:"cluster_id"`
	GeneratedAt string                     `json:"generated_at"`
	Rows        []processBaselineBundleRow `json:"rows"`
}

// AgentBaselineBundle serves the per-workload process baselines for a cluster to
// the runtime-agent process enforcer. Auth is the runtime-agent token.
func (h *Baselines) AgentBaselineBundle(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	clusterIDRaw := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterIDRaw == "" {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	clusterID, err := uuid.Parse(clusterIDRaw)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid cluster_id")
		return
	}
	var exists bool
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT EXISTS (SELECT 1 FROM clusters WHERE org_id = $1 AND id = $2)`,
		tok.OrgID, clusterID).Scan(&exists); err != nil {
		jsonError(w, http.StatusInternalServerError, "cluster lookup: "+err.Error())
		return
	}
	if !exists {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT s.workload_id,
       COALESCE((
           SELECT array_agg(DISTINCT l.pod_workload_id ORDER BY l.pod_workload_id)
             FROM pod_workload_links l
            WHERE l.org_id = s.org_id
              AND l.cluster_id = s.cluster_id
              AND l.owner_workload_id = s.workload_id
              AND l.pod_workload_id <> ''
       ), '{}'),
       COALESCE(s.namespace, ''),
       COALESCE(s.name, ''),
       COALESCE(s.mode, 'learn'),
       s.updated_at
  FROM process_baseline_states s
 WHERE s.org_id = $1
   AND s.cluster_id = $2
 ORDER BY s.workload_id`, tok.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "process baseline states: "+err.Error())
		return
	}
	defer rows.Close()

	bundle := processBaselineBundleDTO{
		ClusterID:   clusterID.String(),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Rows:        []processBaselineBundleRow{},
	}
	type pending struct {
		row processBaselineBundleRow
	}
	var pendings []pending
	for rows.Next() {
		var row processBaselineBundleRow
		var updatedAt time.Time
		if err := rows.Scan(&row.WorkloadID, &row.PodWorkloadIDs, &row.Namespace,
			&row.Name, &row.Mode, &updatedAt); err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		row.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		pendings = append(pendings, pending{row: row})
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, "rows: "+err.Error())
		return
	}

	// Resolve the allowed-process set per workload from observations. Done after
	// the cursor is drained so we don't hold the row cursor open across queries.
	for _, p := range pendings {
		obs, _, _, _, err := h.processObservations(r.Context(), tok.OrgID, clusterID, p.row.WorkloadID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "observations: "+err.Error())
			return
		}
		p.row.Processes = allowedBasenames(obs)
		bundle.Rows = append(bundle.Rows, p.row)
	}

	// P2-3: merge master-authored (federated) baselines read-only. Populated only
	// on a joint (replicated into fed_runtime_profiles from its master); empty on a
	// master/standalone controller.
	fedPayloads, err := fetchFedRuntimeProfilePayloads(r.Context(), h.db.Pool(), tok.OrgID, handler.FedKindHostProcessProfile)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "fed baselines: "+err.Error())
		return
	}
	bundle.Rows = appendFedProcessBaselineRows(bundle.Rows, fedPayloads)

	httpx.WriteJSON(w, http.StatusOK, bundle)
}

// allowedBasenames collapses observed processes to a deduped, sorted basename set
// (process name + path basename) — the form the enforcer matches an exec against.
func allowedBasenames(obs []processObservation) []string {
	set := map[string]struct{}{}
	for _, p := range obs {
		if name := strings.TrimSpace(p.Name); name != "" {
			set[name] = struct{}{}
		}
		if base := pathBasename(p.Path); base != "" {
			set[base] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
