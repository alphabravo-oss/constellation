// Wave D1: export an existing runtime_policies row to NetworkPolicy YAML.
//
//	GET /api/v1/runtime-policies/{id}/export?flavor=native|cilium|calico
//
// Wave B4's :generate endpoint emits all three flavors from synthesized
// rules; this endpoint does the same translation for an already-saved
// policy. The two coexist because the use-cases differ:
//
//	B4 :generate     — operator wants a draft to author into a new policy
//	D1 export        — operator wants kube-side defense to mirror what
//	                   dp is doing today (especially on Cilium clusters
//	                   where dp's NFQUEUE path is bypassed and we ask
//	                   Cilium to enforce instead via CiliumNetworkPolicy)
//
// The conversion approximates: PolicyRule.SrcIP/DstIP/Port/IPProto become
// ipBlock + ports entries in the YAML. Action stays informational —
// kube-side NetworkPolicy is always allow-list, deny-by-default.
package runtime

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// Export handles GET /api/v1/runtime-policies/{id}/export.
func (h *RuntimePoliciesHTTP) Export(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id, ok := idFromPathSeg(r.URL.Path, "export")
	if !ok {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	policyID, err := uuid.Parse(id)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	flavor := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("flavor")))
	if flavor == "" {
		flavor = "native"
	}
	switch flavor {
	case "native", "cilium", "calico":
		// ok
	default:
		jsonError(w, http.StatusBadRequest, "flavor must be one of native|cilium|calico")
		return
	}

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
	flows := rulesToFlows(rules, p.Workload, p.Namespace)

	var yamlOut string
	switch flavor {
	case "native":
		yamlOut = netpolicy.GenerateNative(p.Workload, p.Namespace, nil, flows)
	case "cilium":
		yamlOut = netpolicy.GenerateCilium(p.Workload, p.Namespace, nil, flows)
	case "calico":
		yamlOut = netpolicy.GenerateCalico(p.Workload, p.Namespace, nil, flows)
	}

	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition",
		`attachment; filename="`+sanitizeFilename(p.Workload)+`-`+flavor+`.yaml"`)
	_, _ = w.Write([]byte(yamlOut))
}

// rulesToFlows is the inverse of B4's BuildDPRules — convert a stored
// PolicyRule set back into the Flow slice that GenerateNative/Cilium/Calico
// consume. We synthesise a single Flow per allow-rule; the YAML generator
// dedups and groups by direction.
//
// Lossy conversions:
//   - PolicyRule.SrcIPR/DstIPR (range) collapses to the SrcIP value.
//     kube NetworkPolicy supports cidr but not arbitrary ranges; bridging
//     ranges to cidr is doable as a follow-up.
//   - Apps[] (L7 app whitelists) is dropped on the native flavor —
//     NetworkPolicy doesn't model L7. Cilium DOES; future enhancement.
//   - deny-action rules don't translate (NetworkPolicy is allow-list);
//     they're skipped with a comment.
func rulesToFlows(rules []*dp.PolicyRule, workload, namespace string) []netpolicy.Flow {
	out := make([]netpolicy.Flow, 0, len(rules))
	for _, r := range rules {
		if r.Action == dp.PolicyActionDeny || r.Action == dp.PolicyActionViolate {
			continue // deny → omit from allow-list YAML
		}
		f := netpolicy.Flow{
			Protocol: protoCodeToStringExport(r.IPProto),
			Port:     int(r.Port),
			Count:    1,
		}
		if r.Ingress {
			// Ingress: target workload is the destination.
			f.DstWorkload = workload
			f.DstNamespace = namespace
			if r.SrcIP != nil && !r.SrcIP.IsUnspecified() {
				f.SrcWorkload = "external/" + r.SrcIP.String()
				f.DstIP = r.SrcIP.String() // generator uses DstIP for the external CIDR
			} else {
				f.SrcWorkload = "external/0.0.0.0"
			}
		} else {
			// Egress: target workload is the source.
			f.SrcWorkload = workload
			f.SrcNamespace = namespace
			// Preserve the FQDN anchor so the Cilium generator can emit a
			// toFQDNs rule rather than collapsing the destination to an IP/CIDR
			// (the resolved IPs rotate; the name does not).
			f.Fqdn = r.Fqdn
			if r.DstIP != nil && !r.DstIP.IsUnspecified() {
				f.DstWorkload = "external/" + r.DstIP.String()
				f.DstIP = r.DstIP.String()
			} else if r.Fqdn != "" {
				// FQDN-anchored rule with no resolved IP: leave Dst empty so the
				// Cilium toFQDNs path (which keys on Fqdn) is the sole selector.
			} else {
				f.DstWorkload = "external/0.0.0.0"
			}
		}
		out = append(out, f)
	}
	return out
}

// protoCodeToStringExport mirrors the dp_rules.go helper but lives here
// to avoid pulling pkg/netpolicy's private helpers into the handler. The
// YAML generator uppercases the protocol; we produce the canonical case.
func protoCodeToStringExport(code uint8) string {
	switch code {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	}
	return "TCP"
}

// sanitizeFilename converts a "ns/name" workload to a kube-friendly
// filename — strip slashes, lowercase.
func sanitizeFilename(s string) string {
	r := strings.NewReplacer("/", "-", " ", "-", ":", "-")
	return strings.ToLower(r.Replace(s))
}
