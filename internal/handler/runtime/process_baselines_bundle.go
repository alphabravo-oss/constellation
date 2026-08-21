package runtime

import (
	"context"
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
	Processes      []string `json:"processes"` // allowed basenames, deduped+sorted (legacy fallback)
	// RT-MATCH-16: rich per-process entries carrying full path + optional sha256 +
	// parent name + action, so the agent enforcer can reject a renamed/relocated
	// binary running under an allowed basename. Additive: an agent that ignores it
	// (or a row with no entries) falls back to the basename Processes set above.
	Entries   []processBundleEntry `json:"entries,omitempty"`
	UpdatedAt string               `json:"updated_at"`
}

// processBundleEntry mirrors the agent's processProfileEntry / NeuVector's
// CLUSProcessProfileEntry: every non-empty key field is an AND constraint the exec
// must satisfy. Action is "allow" (learned/authored-allow) or "deny" (authored-deny).
type processBundleEntry struct {
	Basename   string `json:"basename,omitempty"`
	Path       string `json:"path,omitempty"`
	Sha256     string `json:"sha256,omitempty"`
	ParentName string `json:"parent_name,omitempty"`
	Action     string `json:"action"`
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

	// Authored allow/deny rules (RT-MATCH-16) for the whole cluster in one query,
	// grouped by workload, so the per-workload loop below doesn't N+1.
	ruleEntries, err := h.loadProcessRuleEntries(r.Context(), tok.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "process rules: "+err.Error())
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
		// Rich entries: learned observations (allow) + authored rules (allow/deny).
		p.row.Entries = append(allowedEntries(obs), ruleEntries[p.row.WorkloadID]...)
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

// allowedEntries builds rich allow-entries from learned observations (RT-MATCH-16).
// When a process was seen with a canonical absolute path, the entry pins that full
// path (+ hash/parent when captured) so a binary renamed/relocated to an allowed
// basename no longer matches. When no absolute path is known (older rows / relative
// execve filename), the entry is basename-only — the documented fallback, identical
// to the legacy behavior for that process.
func allowedEntries(obs []processObservation) []processBundleEntry {
	out := make([]processBundleEntry, 0, len(obs))
	seen := map[string]struct{}{}
	for _, p := range obs {
		name := strings.TrimSpace(p.Name)
		path := strings.TrimSpace(p.Path)
		if name == "" && path == "" {
			continue
		}
		e := processBundleEntry{Action: "allow"}
		// Only pin an absolute path; a relative/empty path stays a wildcard so we
		// never false-reject a legitimately-relocated-but-canonical exec.
		if strings.HasPrefix(path, "/") {
			e.Path = path
			e.Basename = pathBasename(path)
			e.Sha256 = strings.TrimSpace(p.Sha256)
			e.ParentName = strings.TrimSpace(p.ParentName)
		} else {
			e.Basename = name
		}
		if e.Basename == "" && e.Path == "" {
			continue
		}
		k := e.Basename + "\x00" + e.Path + "\x00" + e.Sha256 + "\x00" + e.ParentName
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Basename < out[j].Basename
	})
	return out
}

// loadProcessRuleEntries loads the authored allow/deny process rules for a cluster and
// groups them by workload as rich entries (RT-MATCH-16). Degrades to an empty map if
// the table/columns haven't been migrated yet, so the bundle never fails on a stale DB.
func (h *Baselines) loadProcessRuleEntries(ctx context.Context, orgID, clusterID uuid.UUID) (map[string][]processBundleEntry, error) {
	out := map[string][]processBundleEntry{}
	rows, err := h.db.Pool().Query(ctx, `
SELECT workload_id, name, path, COALESCE(sha256,''), COALESCE(parent_name,''), action
  FROM process_profile_rules
 WHERE org_id = $1 AND cluster_id = $2 AND enabled = TRUE`, orgID, clusterID)
	if err != nil {
		// Missing table/column (pre-migration) is non-fatal: no authored entries.
		if strings.Contains(err.Error(), "process_profile_rules") ||
			strings.Contains(err.Error(), "sha256") || strings.Contains(err.Error(), "parent_name") {
			return out, nil
		}
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var workloadID, name, path, sha, parent, action string
		if err := rows.Scan(&workloadID, &name, &path, &sha, &parent, &action); err != nil {
			return nil, err
		}
		if action != "deny" {
			action = "allow"
		}
		out[workloadID] = append(out[workloadID], processBundleEntry{
			Basename:   strings.TrimSpace(name),
			Path:       strings.TrimSpace(path),
			Sha256:     strings.TrimSpace(sha),
			ParentName: strings.TrimSpace(parent),
			Action:     action,
		})
	}
	return out, rows.Err()
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
