// Wave B4: threat-aware NetworkPolicy auto-generation.
//
//	POST /api/v1/runtime-policies:generate
//	  body: { cluster_id, workload, namespace, hours, allow_dns?, default_deny? }
//	  returns: { rules (dp), yaml { native, cilium, calico }, sources }
//
//	POST /api/v1/runtime-policies:apply-generated
//	  body: same as :generate plus `name` for the new row
//	  returns: the inserted RuntimePolicy (mode=monitor)
//
// Strategy: query network_flows for the workload in the window, EXCLUDE any
// flow with threat_id > 0 (don't whitelist attack traffic), feed the result
// into pkg/netpolicy.BuildDPRules + GenerateNative/Cilium/Calico. The
// caller decides whether to preview (just :generate) or apply (which
// creates a monitor-mode runtime_policies row).
//
// Audit: :apply-generated writes a runtime.policy.create event via the
// existing store path, plus a metadata-only annotation on the row noting
// it was machine-generated. The annotation lives in the row's name (eg.
// "auto-2025-03-15-discover") so operators recognise auto-gen output at
// a glance in the UI; we don't have a separate `source` column today.
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
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// GenerateRequest is the POST body shared by /generate and /apply-generated.
type GenerateRequest struct {
	ClusterID   uuid.UUID `json:"cluster_id"`
	Workload    string    `json:"workload"`            // "<ns>/<deployment>"
	Namespace   string    `json:"namespace,omitempty"` // for the YAML; defaults to the workload's namespace
	Hours       int       `json:"hours,omitempty"`     // observation window; defaults to 24
	AllowDNS    *bool     `json:"allow_dns,omitempty"`
	DefaultDeny *bool     `json:"default_deny,omitempty"`
	// Used by /apply-generated.
	Name string `json:"name,omitempty"`
}

// GenerateResponse is the /generate result.
type GenerateResponse struct {
	WindowHours     int              `json:"window_hours"`
	Workload        string           `json:"workload"`
	FlowsSeen       int              `json:"flows_seen"`       // before threat filtering
	FlowsKept       int              `json:"flows_kept"`       // after threat filtering
	ThreatsExcluded int              `json:"threats_excluded"` // flows dropped because threat_id > 0
	Rules           []*dp.PolicyRule `json:"rules"`
	DefAction       uint8            `json:"def_action"`
	ApplyDir        int              `json:"apply_dir"`
	YAML            GenerateYAML     `json:"yaml"`
	Summary         []string         `json:"summary"` // human-readable rule list
}

// GenerateYAML carries the three NetworkPolicy flavors we can emit.
type GenerateYAML struct {
	Native string `json:"native"`
	Cilium string `json:"cilium"`
	Calico string `json:"calico"`
}

// Generate handles POST /api/v1/runtime-policies:generate — preview only.
func (h *RuntimePoliciesHTTP) Generate(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req GenerateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	res, err := h.generateInternal(r.Context(), sub.OrgID, req)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ApplyGenerated handles POST /api/v1/runtime-policies:apply-generated.
// Calls generateInternal and then creates a monitor-mode runtime_policies
// row using the synthesized rules. Operator promotes to enforce later
// through the regular /promote endpoint.
func (h *RuntimePoliciesHTTP) ApplyGenerated(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req GenerateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "name is required")
		return
	}
	gen, err := h.generateInternal(r.Context(), sub.OrgID, req)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// P2-2: everything we synthesize from observed flows is provenance=learned.
	// We persist the provenance tag in the rules JSONB (rides an extra `cfg`
	// key that the dp decoder ignores) so a later regeneration can tell learned
	// rules apart from operator-authored ones and merge non-destructively.
	learned := netpolicy.Tag(gen.Rules, netpolicy.CfgTypeLearned)

	// If a policy with this (workload,name) already exists, MERGE instead of
	// 409: replace the learned rules with the fresh set but keep every
	// user/fed-authored rule the operator added by hand.
	existing, err := h.store.GetByName(r.Context(), sub.OrgID, req.ClusterID, req.Workload, req.Name)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing != nil {
		got, err := h.mergeRegenerated(r, sub.OrgID, sub.UserID, existing, learned, gen)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httpx.WriteJSON(w, http.StatusOK, got)
		return
	}

	rulesJSON, err := json.Marshal(learned)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "encode rules: "+err.Error())
		return
	}
	policy := &RuntimePolicy{
		OrgID: sub.OrgID, ClusterID: req.ClusterID,
		Workload: req.Workload, Namespace: namespaceOrDerived(req),
		Name:      req.Name,
		Mode:      PolicyModeMonitor, // always monitor on auto-gen
		DefAction: gen.DefAction,
		ApplyDir:  gen.ApplyDir,
		Rules:     rulesJSON,
		CreatedBy: &sub.UserID,
	}
	id, err := h.store.Insert(r.Context(), policy, requestIDFrom(r))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			// Lost a create race; fall back to the merge path.
			existing, gerr := h.store.GetByName(r.Context(), sub.OrgID, req.ClusterID, req.Workload, req.Name)
			if gerr == nil && existing != nil {
				got, merr := h.mergeRegenerated(r, sub.OrgID, sub.UserID, existing, learned, gen)
				if merr == nil {
					httpx.WriteJSON(w, http.StatusOK, got)
					return
				}
			}
			jsonError(w, http.StatusConflict, "policy with this name already exists")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, _ := h.store.Get(r.Context(), sub.OrgID, id)
	httpx.WriteJSON(w, http.StatusCreated, got)
}

// mergeRegenerated merges freshly-learned rules into an existing policy row,
// preserving user/fed-authored rules, and writes the result back (bumping
// version via the runtime_policies trigger). Mode is intentionally left
// untouched — regeneration must not silently re-arm or disarm enforcement.
func (h *RuntimePoliciesHTTP) mergeRegenerated(r *http.Request, orgID, userID uuid.UUID,
	existing *RuntimePolicy, learned []*netpolicy.SourcedRule, gen *GenerateResponse) (*RuntimePolicy, error) {
	prior, err := netpolicy.DecodeSourced(existing.Rules)
	if err != nil {
		return nil, err
	}
	merged := netpolicy.MergeRules(prior, learned)
	rulesJSON, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	// Preserve any operator-tuned def_action/apply_dir the row already carries;
	// only the rule set is regenerated.
	_, err = h.store.db.Pool().Exec(r.Context(), `
UPDATE runtime_policies SET rules = $1::jsonb, updated_by = $2
 WHERE id = $3 AND org_id = $4`, string(rulesJSON), userID, existing.ID, orgID)
	if err != nil {
		return nil, err
	}
	got, err := h.store.Get(r.Context(), orgID, existing.ID)
	if err != nil {
		return nil, err
	}
	if h.store.auditLog != nil {
		_ = h.store.auditLog.LogPolicyEvent(r.Context(), orgID, &userID,
			audit.ActionPolicyUpdate, ptrSnap(existing), ptrSnap(got), requestIDFrom(r))
	}
	return got, nil
}

// generateInternal is the shared work both endpoints do.
func (h *RuntimePoliciesHTTP) generateInternal(ctx context.Context, orgID uuid.UUID, req GenerateRequest) (*GenerateResponse, error) {
	if req.ClusterID == uuid.Nil || req.Workload == "" {
		return nil, errBadRequest("cluster_id and workload are required")
	}
	// Default an omitted window to 24h BEFORE clamping (matches /simulate); clampInt's
	// min of 1 would otherwise turn 0 into 1h, silently narrowing the flow window.
	if req.Hours == 0 {
		req.Hours = 24
	}
	hours := clampInt(req.Hours, 1, 168)
	flows, flowsSeen, threats, err := h.fetchFlowsForGeneration(ctx, orgID, req.ClusterID, req.Workload, hours)
	if err != nil {
		return nil, err
	}
	opts := netpolicy.DefaultBuildDPRulesOptions()
	if req.AllowDNS != nil {
		opts.AllowDNS = *req.AllowDNS
	}
	if req.DefaultDeny != nil {
		opts.DefaultDeny = *req.DefaultDeny
	}
	rules, defAction, applyDir := netpolicy.BuildDPRules(req.Workload, flows, opts)

	ns := namespaceOrDerived(req)
	yaml := GenerateYAML{
		Native: netpolicy.GenerateNative(req.Workload, ns, nil, flows),
		Cilium: netpolicy.GenerateCilium(req.Workload, ns, nil, flows),
		Calico: netpolicy.GenerateCalico(req.Workload, ns, nil, flows),
	}
	summary := make([]string, 0, len(rules))
	for _, r := range rules {
		summary = append(summary, netpolicy.FormatRuleSummary(r))
	}
	return &GenerateResponse{
		WindowHours:     hours,
		Workload:        req.Workload,
		FlowsSeen:       flowsSeen,
		FlowsKept:       len(flows),
		ThreatsExcluded: threats,
		Rules:           rules,
		DefAction:       defAction,
		ApplyDir:        applyDir,
		YAML:            yaml,
		Summary:         summary,
	}, nil
}

// fetchFlowsForGeneration pulls network_flows for the workload, excluding
// any row with threat_id > 0. Returns the converted netpolicy.Flow slice
// PLUS the seen/excluded counters so callers can show the operator what
// was filtered.
//
// Hard cap of 5000 rows — same as simulate. For a workload with more
// traffic than that in the window, the most recent flows win (ORDER BY
// at DESC).
func (h *RuntimePoliciesHTTP) fetchFlowsForGeneration(ctx context.Context, orgID, clusterID uuid.UUID, workload string, hours int) ([]netpolicy.Flow, int, int, error) {
	rows, err := h.store.db.Pool().Query(ctx, `
SELECT src_workload, dst_workload,
       COALESCE(src_addr,''), COALESCE(dst_addr,''),
       COALESCE(dst_port,0), COALESCE(protocol,''),
       COALESCE(l7_protocol,''), COALESCE(threat_id,0), COALESCE(at, NOW())::text,
       COALESCE(fqdn,'')
  FROM network_flows
 WHERE org_id = $1 AND cluster_id = $2
   AND (src_workload = $3 OR dst_workload = $3)
   AND at >= NOW() - ($4 || ' hours')::interval
 ORDER BY at DESC
 LIMIT 5000`,
		orgID, clusterID, workload, intToStr(hours))
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	var flows []netpolicy.Flow
	seen, threats := 0, 0
	for rows.Next() {
		var src, dst, srcAddr, dstAddr, proto, l7, lastSeen, fqdn string
		var port int
		var threatID int32
		if err := rows.Scan(&src, &dst, &srcAddr, &dstAddr, &port, &proto, &l7, &threatID, &lastSeen, &fqdn); err != nil {
			return nil, 0, 0, err
		}
		seen++
		if threatID > 0 {
			// Threat flow — DON'T add it to the allow list. dp's signature
			// engine already produces alert/deny verdicts on these; the
			// auto-gen output should reinforce that, not regress it.
			threats++
			continue
		}
		flows = append(flows, flowFromRow(src, dst, srcAddr, dstAddr, proto, l7, fqdn, lastSeen, port))
	}
	return flows, seen, threats, rows.Err()
}

// flowFromRow maps one scanned network_flows row to a netpolicy.Flow. It
// applies external-peer detection for the egress peer IP and, for an egress
// edge to an EXTERNAL peer carrying an observed DNS name, anchors the flow to
// that FQDN so GenerateCilium emits a toFQDNs rule.
func flowFromRow(src, dst, srcAddr, dstAddr, proto, l7, fqdn, lastSeen string, port int) netpolicy.Flow {
	// Pick whichever IP is the peer side for the YAML's external-IP rule path.
	// Per the netpolicy.Flow contract, DstIP is the external peer's IP when the
	// peer is "external/..." or "cluster/<ip>".
	// The ingest path collapses most external destinations to the bare "external"
	// bucket (real IP kept in dst_addr), so external detection must accept BOTH the
	// bare and the un-collapsed "external/<ip>" form — matching the FQDN check below
	// and isExternalPeer in internal/handler/netpolicy/network_policies.go.
	dstExternal := dst == "external" || strings.HasPrefix(dst, "external/")
	srcExternal := src == "external" || strings.HasPrefix(src, "external/")
	peerIP := ""
	switch {
	case dstExternal || strings.HasPrefix(dst, "cluster/"):
		peerIP = dstAddr
	case srcExternal || strings.HasPrefix(src, "cluster/"):
		peerIP = srcAddr
	}
	f := netpolicy.Flow{
		SrcWorkload:  src,
		SrcNamespace: namespaceOf(src),
		DstWorkload:  dst,
		DstNamespace: namespaceOf(dst),
		DstIP:        peerIP,
		Protocol:     strings.ToUpper(proto),
		Port:         port,
		LastSeen:     lastSeen,
		Count:        1,
		L7Protocol:   strings.ToLower(l7),
	}
	// External destination: per the netpolicy.Flow contract DstIP/Fqdn are used only
	// when DstWorkload is "" — an "external"/"external/<ip>" bucket is not a selectable
	// workload, so leaving it set makes the generator emit an app=external toEndpoints
	// selector (matches no pod) instead of toCIDR/toFQDNs. Clear it so egress anchors to
	// the observed IP or DNS name (mirrors the H12 fix in network_policies.go).
	if dstExternal {
		f.DstWorkload = ""
		f.DstNamespace = ""
		if fqdn != "" {
			f.Fqdn = fqdn
		}
	}
	return f
}

func namespaceOf(workload string) string {
	idx := strings.IndexByte(workload, '/')
	if idx <= 0 {
		return ""
	}
	return workload[:idx]
}

// namespaceOrDerived prefers the explicit namespace in the request body;
// falls back to the prefix of the workload string ("default/api" → "default").
func namespaceOrDerived(req GenerateRequest) string {
	if req.Namespace != "" {
		return req.Namespace
	}
	return namespaceOf(req.Workload)
}

// errBadRequest is a small typed-error used to ferry 400-shaped errors out
// of generateInternal without doing the response write there (so the
// handler stays the only place that talks HTTP).
type errBadRequest string

func (e errBadRequest) Error() string { return string(e) }
