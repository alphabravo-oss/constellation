// Wave B4: convert observed Flow records into dp.PolicyRule slices.
//
// Companion to the existing GenerateNative / Cilium / Calico functions in
// netpolicy.go — those emit YAML for kube-side enforcement; this emits
// dp's wire shape for in-kernel enforcement via the NFQUEUE path.
//
// Strategy:
//
//   default action = DENY (PolicyActionDeny)
//   for each unique observed (peer_ip, peer_port, protocol, direction):
//     emit one rule with Action = ALLOW
//
// Two-layer defense: a kube NetworkPolicy says "drop everything not on
// this list" at the kube-proxy layer; dp's policy says "drop everything
// not on this list" at the wire layer. The lists are derived from the
// same observed traffic so they agree on the allow set.
package netpolicy

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// BuildDPRulesOptions configures the rule generator. The defaults work for
// most callers; bump DefaultPort if you want every-port-on-this-peer rules
// instead of per-port (eg. "trust the peer entirely").
type BuildDPRulesOptions struct {
	// AllowDNS — when true, prepend an egress rule allowing UDP/53 to any
	// peer. Mirrors the implicit DNS allow in GenerateNative. Default true.
	AllowDNS bool
	// DefaultDeny — when true (the only safe default), the policy's def_action
	// is set to PolicyActionDeny so anything outside the allow-list drops.
	DefaultDeny bool
}

// DefaultBuildDPRulesOptions are what the auto-gen handler uses.
func DefaultBuildDPRulesOptions() BuildDPRulesOptions {
	return BuildDPRulesOptions{AllowDNS: true, DefaultDeny: true}
}

// BuildDPRules synthesizes a dp policy table from observed traffic for one
// workload. Returns:
//   - rules:     []dp.PolicyRule with stable, deterministic ordering
//   - defAction: PolicyActionDeny (with opts.DefaultDeny) or PolicyActionAllow
//   - applyDir:  always ApplyDirBoth (we generate both ingress + egress rules)
//
// `targetWorkload` is the policy-target — flows where DstWorkload matches
// become ingress rules; flows where SrcWorkload matches become egress rules.
// Flows where neither side matches are dropped (shouldn't happen with a
// properly-scoped query).
//
// IDs are NOT stamped here — the handler does that after insert, using the
// dp_policy_id sequence value from runtime_policies. We leave PolicyRule.ID
// = 0 so ToWorkloadPolicy can overwrite cleanly.
func BuildDPRules(targetWorkload string, flows []Flow, opts BuildDPRulesOptions) ([]*dp.PolicyRule, uint8, int) {
	defAction := uint8(dp.PolicyActionDeny)
	if !opts.DefaultDeny {
		defAction = dp.PolicyActionAllow
	}
	rules := make([]*dp.PolicyRule, 0, len(flows)+1)

	if opts.AllowDNS {
		// Implicit egress allow for UDP/53 to any peer. Without this,
		// auto-gen breaks every workload that resolves names.
		rules = append(rules, &dp.PolicyRule{
			Ingress: false,
			IPProto: 17, // UDP
			Port:    53,
			Action:  dp.PolicyActionAllow,
		})
	}

	// Dedup on (direction, peer_ip, port, protocol). Sort for deterministic
	// rule-list order so two runs produce the same output and the audit
	// diff stays readable.
	type edge struct {
		ingress bool
		peerIP  string
		fqdn    string
		port    int
		proto   string
	}
	seen := map[edge]bool{}
	for _, f := range flows {
		var ing bool
		var peerIP string
		switch {
		case f.DstWorkload == targetWorkload && f.DstNamespace == "":
			// Tolerate a target string without explicit namespace match.
			ing = true
		case f.DstWorkload == targetWorkload:
			ing = true
		case f.SrcWorkload == targetWorkload:
			ing = false
		default:
			// Flow doesn't touch the target — skip rather than emit a noise rule.
			continue
		}
		// FQDN anchoring is egress-only (a server has no DNS name for its
		// clients). On an egress flow with Fqdn set, the rule is keyed by the
		// name instead of the destination IP; dp's FQDN resolver supplies the
		// live IPs at match time.
		fqdn := ""
		if !ing {
			fqdn = f.Fqdn
		}
		if ing {
			// Ingress: peer = src side.
			peerIP = peerIPFromFlow(f, true)
		} else if fqdn == "" {
			peerIP = peerIPFromFlow(f, false)
		}
		key := edge{ingress: ing, peerIP: peerIP, fqdn: fqdn, port: f.Port, proto: strings.ToUpper(f.Protocol)}
		if seen[key] {
			continue
		}
		seen[key] = true
		rules = append(rules, buildAllowRule(ing, peerIP, fqdn, f.Port, f.Protocol))
	}

	// Stable sort: ingress first, then by port, then by peer for ties.
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Ingress != b.Ingress {
			return a.Ingress // ingress before egress
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Fqdn != b.Fqdn {
			return a.Fqdn < b.Fqdn
		}
		return ipToString(a.DstIP) < ipToString(b.DstIP)
	})

	return rules, defAction, dp.ApplyDirBoth
}

// peerIPFromFlow returns the IP of the non-target side of the flow, or ""
// if no IP is available (peer was identified by workload name only — eg.
// when the flow row has src_workload="default/api" but no src_addr).
//
// ingress=true means "we want the src side's IP"; ingress=false means
// "we want the dst side's IP".
func peerIPFromFlow(f Flow, ingress bool) string {
	if ingress {
		// SrcLabels not populated? Use DstIP only when it's an external row
		// where the policy-target was the server. The Flow shape doesn't
		// carry SrcIP separately; we rely on DstIP being filled when the
		// peer is "external/..." or "cluster/<ip>".
		if f.DstIP != "" && (strings.HasPrefix(f.SrcWorkload, "external/") || strings.HasPrefix(f.SrcWorkload, "cluster/")) {
			return f.DstIP // Flow.DstIP is the canonical external-IP field
		}
	} else {
		if f.DstIP != "" {
			return f.DstIP
		}
	}
	return ""
}

func buildAllowRule(ingress bool, peerIP, fqdn string, port int, protoStr string) *dp.PolicyRule {
	r := &dp.PolicyRule{
		Ingress: ingress,
		Port:    uint16(port),
		IPProto: protoToCode(protoStr),
		Action:  dp.PolicyActionAllow,
		Fqdn:    fqdn,
	}
	if peerIP != "" {
		ip := net.ParseIP(peerIP)
		if ip != nil {
			if ingress {
				r.SrcIP = ip
			} else {
				r.DstIP = ip
			}
		}
	}
	return r
}

func protoToCode(s string) uint8 {
	switch strings.ToUpper(s) {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	case "ICMPV6":
		return 58
	}
	return 0
}

func ipToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// FormatRuleSummary renders one rule as a single-line preview string, used
// by callers that surface generated rules in plain text (eg. audit log
// entries, CLI flow). Not exposed to dp's wire format.
func FormatRuleSummary(r *dp.PolicyRule) string {
	dir := "egress"
	if r.Ingress {
		dir = "ingress"
	}
	peer := "any"
	if r.Ingress && len(r.SrcIP) > 0 {
		peer = r.SrcIP.String()
	}
	if !r.Ingress && r.Fqdn != "" {
		peer = "fqdn:" + r.Fqdn
	} else if !r.Ingress && len(r.DstIP) > 0 {
		peer = r.DstIP.String()
	}
	act := "allow"
	switch r.Action {
	case dp.PolicyActionDeny:
		act = "deny"
	case dp.PolicyActionViolate:
		act = "monitor"
	}
	return fmt.Sprintf("%s %s %s/%d %s", dir, peer, protoCodeToString(r.IPProto), r.Port, act)
}

func protoCodeToString(code uint8) string {
	switch code {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return "any"
	}
}
