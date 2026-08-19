// Wave B2 + B3: match-stats and simulate endpoints.
//
//	GET  /api/v1/runtime-policies/{id}/match-stats?hours=24
//	     For an existing policy — runs the evaluator against last N hours
//	     of network_flows for the policy's workload, returns allow / monitor
//	     / deny / default counts + up to 10 samples per bucket.
//
//	POST /api/v1/runtime-policies/{id}/simulate?hours=24
//	     Like /match-stats but the candidate rules come from the POST body —
//	     operators can preview an unsaved edit before clicking Save.
//
// Both endpoints rely on the pure-Go evaluator in runtime_policies_eval.go;
// the only DB query is the windowed flow pull.
package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// MatchStats handles GET /runtime-policies/{id}/match-stats.
func (h *RuntimePoliciesHTTP) MatchStats(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	// URL path: /runtime-policies/{id}/match-stats. The id is parts[len-2].
	id, ok := idFromPathSeg(r.URL.Path, "match-stats")
	if !ok {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	policyID, err := uuid.Parse(id)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	hours := clampInt(parseIntDefault(r.URL.Query().Get("hours"), 24), 1, 168)

	p, err := h.store.Get(r.Context(), sub.OrgID, policyID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rules, err := p.DecodeRules()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "decode rules: "+err.Error())
		return
	}
	out, err := h.evaluateAgainstFlows(r.Context(), sub.OrgID, p.ClusterID, p.Workload, hours,
		rules, p.DefAction, p.Mode == PolicyModeMonitor)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out.WindowHours = hours
	httpx.WriteJSON(w, http.StatusOK, out)
}

// Simulate handles POST /runtime-policies/{id}/simulate. Body shape mirrors
// UpdatePolicyRequest (rules + optional def_action / apply_dir) but the
// candidate is NOT persisted — we just evaluate.
//
// `id` is the policy whose workload + cluster we scope to. The candidate
// can be a from-scratch ruleset for that workload.
func (h *RuntimePoliciesHTTP) Simulate(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id, ok := idFromPathSeg(r.URL.Path, "simulate")
	if !ok {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	policyID, err := uuid.Parse(id)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	hours := clampInt(parseIntDefault(r.URL.Query().Get("hours"), 24), 1, 168)

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Rules     json.RawMessage `json:"rules"`
		DefAction *uint8          `json:"def_action,omitempty"`
		// AsMode lets the caller preview either enforce semantics (deny stays
		// deny) or monitor semantics (deny → monitor). Default: enforce.
		AsMode PolicyMode `json:"as_mode,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	rules, err := ParseRulesJSON(req.Rules)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "rules: "+err.Error())
		return
	}
	// Look up the policy's workload + cluster scope.
	p, err := h.store.Get(r.Context(), sub.OrgID, policyID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	def := p.DefAction
	if req.DefAction != nil {
		def = *req.DefAction
	}
	honorMonitorDemote := req.AsMode == PolicyModeMonitor

	out, err := h.evaluateAgainstFlows(r.Context(), sub.OrgID, p.ClusterID, p.Workload, hours,
		rules, def, honorMonitorDemote)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out.WindowHours = hours
	httpx.WriteJSON(w, http.StatusOK, out)
}

// evaluateAgainstFlows is the shared work both endpoints do: pull the
// workload's flows in the window, run the evaluator, return stats.
//
// We cap at 5000 flows per evaluation — covers the realistic case (a busy
// workload at 100s of flows / hour stays well under) and bounds CPU on a
// "simulate against 168h" request. Larger windows just sample the most
// recent 5000.
func (h *RuntimePoliciesHTTP) evaluateAgainstFlows(
	ctx context.Context,
	orgID, clusterID uuid.UUID,
	workload string,
	hours int,
	rules []*dp.PolicyRule,
	defAction uint8,
	honorMonitorDemote bool,
) (MatchStats, error) {
	const cap = 5000
	// Pull every flow that touches this workload as src OR dst. Selecting
	// the columns the evaluator + sample shape needs in one go.
	rows, err := h.store.db.Pool().Query(ctx, `
SELECT src_workload, dst_workload, COALESCE(src_addr,''), COALESCE(dst_addr,''),
       COALESCE(src_port,0), COALESCE(dst_port,0),
       COALESCE(protocol,''), COALESCE(l7_protocol,''),
       COALESCE(application,0),
       COALESCE(bytes,0), at::text
  FROM network_flows
 WHERE org_id = $1 AND cluster_id = $2
   AND (src_workload = $3 OR dst_workload = $3)
   AND at >= NOW() - ($4 || ' hours')::interval
 ORDER BY at DESC
 LIMIT $5`,
		orgID, clusterID, workload, intToStr(hours), cap)
	if err != nil {
		return MatchStats{}, err
	}
	defer rows.Close()
	var flows []EvaluatedFlow
	var samples []*FlowSampleRow
	for rows.Next() {
		var f EvaluatedFlow
		var s FlowSampleRow
		if err := rows.Scan(
			&f.SrcWorkload, &f.DstWorkload, &f.SrcAddr, &f.DstAddr,
			&f.SrcPort, &f.DstPort, &f.Protocol, &f.L7Protocol,
			&f.Application, &s.Bytes, &s.LastSeenAt,
		); err != nil {
			return MatchStats{}, err
		}
		f.Workload = workload
		flows = append(flows, f)
		s.Src = f.SrcWorkload
		s.Dst = f.DstWorkload
		s.SrcAddr = f.SrcAddr
		s.DstAddr = f.DstAddr
		s.SrcPort = f.SrcPort
		s.DstPort = f.DstPort
		s.Protocol = f.Protocol
		s.L7Protocol = f.L7Protocol
		samples = append(samples, &s)
	}
	stats := EvaluateBatch(rules, defAction, honorMonitorDemote, workload, flows, samples)
	return stats, nil
}

// idFromPathSeg pulls the policy id from URLs of the form
// /runtime-policies/{id}/<suffix>. Returns ("", false) if the suffix
// isn't the final segment.
func idFromPathSeg(path, suffix string) (string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return "", false
	}
	if parts[len(parts)-1] != suffix {
		return "", false
	}
	return parts[len(parts)-2], true
}

func intToStr(n int) string {
	// Tiny helper to avoid pulling strconv just for this two-call site.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
