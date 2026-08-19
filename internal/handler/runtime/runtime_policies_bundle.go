// H6 server leg: the agent-facing runtime-policy bundle.
//
// The runtime-agent's policy-sync worker (cmd/constellation-runtime-agent/
// runtime_policy_sync.go) GETs
//
//	GET /api/v1/runtime/policies:bundle?cluster_id=<id>   (runtime-agent token)
//
// every interval and programs dp from the result. Before this handler existed
// the route 404'd, so the worker no-op'd and dp matched every connection
// against an empty rule table — operator-authored deny/FQDN policies were
// stored + audited but never reached the datapath.
//
// The JSON shape here MUST match the worker's runtimePolicyBundle /
// runtimePolicyWire structs exactly (field names + types), since the worker
// decodes straight into them. We emit the stored policy rows verbatim (raw
// rules + mode + dp_policy_id); the worker applies the monitor→violate demotion
// and stamps each rule with dp_policy_id itself (see buildMergedWorkloadPolicy).
// Auth + org/cluster scoping mirror file_profiles.go AgentRulesBundle and
// runtime_dlp.go AgentBundle.
package runtime

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// agentRuntimePolicyWire is the per-policy element of the bundle. Field names +
// types must stay byte-for-byte identical to runtimePolicyWire in the agent's
// runtime_policy_sync.go — that struct is the only consumer.
type agentRuntimePolicyWire struct {
	ID         string           `json:"id"`
	DPPolicyID int64            `json:"dp_policy_id"`
	Workload   string           `json:"workload"`
	Mode       string           `json:"mode"` // monitor | enforce | disabled
	DefAction  uint8            `json:"def_action"`
	ApplyDir   int              `json:"apply_dir"`
	Rules      []*dp.PolicyRule `json:"rules"`
	Version    int64            `json:"version"`
}

// agentRuntimePolicyBundle is the top-level envelope; mirrors the agent's
// runtimePolicyBundle.
type agentRuntimePolicyBundle struct {
	Policies []agentRuntimePolicyWire `json:"policies"`
}

// AgentPolicyBundle serves a cluster's non-disabled runtime policies to the
// runtime-agent's policy-sync worker, authenticated by the runtime-agent token.
// The user-facing List is guarded by user RBAC, so a bearer-token agent 401s
// against it; this is the agent's read path. Org-scoped via the token so a
// token for org A can never read org B's policies, even with a guessed
// cluster_id.
func (h *RuntimePoliciesHTTP) AgentPolicyBundle(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	// Confirm the cluster belongs to the token's org. ListForCluster is already
	// org-scoped (WHERE org_id = $1) so this only changes a cross-org / unknown
	// cluster from an empty 200 into a clean 404 — no data ever leaks across orgs.
	var exists bool
	if err := h.store.db.Pool().QueryRow(r.Context(),
		`SELECT EXISTS (SELECT 1 FROM clusters WHERE org_id = $1 AND id = $2)`,
		tok.OrgID, clusterID).Scan(&exists); err != nil {
		jsonError(w, http.StatusInternalServerError, "cluster lookup: "+err.Error())
		return
	}
	if !exists {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return
	}

	policies, err := h.store.ListForCluster(r.Context(), tok.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// P1-2: the cluster-wide master switch WINS over each policy's own mode /
	// def_action. "observe" forces monitor (never block) for staged rollout or
	// an emergency stop; "enforce" flips the whole cluster on; default action
	// unset|allow|deny overrides the matched-no-rule fallback. Passthrough
	// defaults leave the stored values untouched.
	settings, err := h.store.GetSettings(r.Context(), tok.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "settings: "+err.Error())
		return
	}

	bundle := agentRuntimePolicyBundle{Policies: make([]agentRuntimePolicyWire, 0, len(policies))}
	for _, p := range policies {
		// Emit rules exactly as stored. The worker applies the per-policy mode
		// mapping and dp_policy_id stamping; doing it here too would double-apply.
		rules, err := p.DecodeRules()
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "decode rules: "+err.Error())
			return
		}
		if rules == nil {
			rules = []*dp.PolicyRule{}
		}
		bundle.Policies = append(bundle.Policies, agentRuntimePolicyWire{
			ID:         p.ID.String(),
			DPPolicyID: p.DPPolicyID,
			Workload:   p.Workload,
			Mode:       string(settings.EnforcementOverride.ApplyMode(p.Mode)),
			DefAction:  settings.DefaultAction.ApplyDefAction(p.DefAction),
			ApplyDir:   p.ApplyDir,
			Rules:      rules,
			Version:    p.Version,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, bundle)
}
