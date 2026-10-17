package main

import (
	"fmt"
	"net"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// nativeTerminalDefaults expresses a reviewed default as ordinary terminal
// rules. Native's implicit deny/violate default has unknown-peer grace that
// temporarily opens traffic. A finite-order rule preserves the reviewed action
// without changing native's global strict-mode or policy-address inventory.
// Call only after scoped ICMP compatibility rules have been materialized.
func nativeTerminalDefaults(source *dp.WorkloadPolicy, includeICMP bool) (*dp.WorkloadPolicy, error) {
	count, err := nativeTerminalRuleCount(source, len(source.Rules), includeICMP)
	if err != nil {
		return nil, err
	}
	if source.DefAction != dp.PolicyActionDeny && source.DefAction != dp.PolicyActionViolate {
		return source, nil
	}
	out := *source
	out.Rules = make([]*dp.PolicyRule, len(source.Rules), count)
	copy(out.Rules, source.Rules)
	protocols := []uint8{dp.IPProtoTCP, dp.IPProtoUDP}
	if includeICMP {
		protocols = append(protocols, dp.IPProtoICMP)
	}
	for _, address := range source.LocalIPs {
		for _, ingress := range []bool{false, true} {
			direction := dp.ApplyDirEgress
			if ingress {
				direction = dp.ApplyDirIngress
			}
			if source.ApplyDir&direction == 0 {
				continue
			}
			for _, protocol := range protocols {
				out.Rules = append(out.Rules, nativeTerminalDefault(address, ingress, protocol, source.DefAction))
			}
		}
	}
	return &out, nil
}

func nativeTerminalDefault(address net.IP, ingress bool, protocol, action uint8) *dp.PolicyRule {
	rule := &dp.PolicyRule{
		SrcIP: net.IPv4zero.To4(), SrcIPR: net.IPv4bcast.To4(),
		DstIP: net.IPv4zero.To4(), DstIPR: net.IPv4bcast.To4(),
		PortR: 65535, IPProto: protocol, Ingress: ingress, Action: action,
		// Native only synthesizes application-any entries automatically when
		// the rule ID is nonzero. Keep default attribution ID0 while matching
		// application re-evaluation, including unknown and unmatched apps.
		Apps: []dp.PolicyApp{{App: 0, RuleID: 0, Action: action}},
	}
	if ingress {
		rule.DstIP, rule.DstIPR = address, address
	} else {
		rule.SrcIP, rule.SrcIPR = address, address
	}
	if protocol == dp.IPProtoICMP {
		rule.PortR = 0
	}
	return rule
}

// Validate count arithmetic before allocating the expanded table. The native
// limit counts authored rules as well as every generated local-IP/direction row.
func nativeTerminalRuleCount(source *dp.WorkloadPolicy, base int, includeICMP bool) (int, error) {
	if err := dp.ValidatePolicyRuleCount(base); err != nil {
		return 0, err
	}
	if source.DefAction != dp.PolicyActionDeny && source.DefAction != dp.PolicyActionViolate {
		return base, nil
	}
	directions := 0
	if source.ApplyDir&dp.ApplyDirIngress != 0 {
		directions++
	}
	if source.ApplyDir&dp.ApplyDirEgress != 0 {
		directions++
	}
	protocols := 2
	if includeICMP {
		protocols++
	}
	perIP := directions * protocols
	if perIP > 0 && len(source.LocalIPs) > (dp.MaxExpandedPolicyRules-base)/perIP {
		return 0, fmt.Errorf("dp policy: terminal defaults exceed expanded table limit %d; reduce rules or endpoint IPv4 addresses", dp.MaxExpandedPolicyRules)
	}
	return base + len(source.LocalIPs)*perIP, nil
}

// Budget both ICMP compatibility expansion and terminal defaults before either
// translation allocates its output. A rejected candidate never reaches IPC.
func scopedNativePolicy(source *dp.WorkloadPolicy, globalICMP bool) (*dp.WorkloadPolicy, error) {
	count := len(source.Rules)
	if err := dp.ValidatePolicyRuleCount(count); err != nil {
		return nil, err
	}
	includeICMP := mergedHasICMP(source)
	if globalICMP && !includeICMP {
		for _, rule := range source.Rules {
			if rule.IPProto == dp.IPProtoAny {
				count++
			}
		}
		if err := dp.ValidatePolicyRuleCount(count); err != nil {
			return nil, err
		}
		if len(source.LocalIPs) > (dp.MaxExpandedPolicyRules-count)/2 {
			return nil, fmt.Errorf("dp policy: ICMP compatibility exceeds expanded table limit %d; reduce rules or endpoint IPv4 addresses", dp.MaxExpandedPolicyRules)
		}
		count += len(source.LocalIPs) * 2
	}
	if _, err := nativeTerminalRuleCount(source, count, includeICMP); err != nil {
		return nil, err
	}
	return nativeTerminalDefaults(scopedICMPPolicy(source, globalICMP), includeICMP)
}

func (w *RuntimePolicySyncWorker) rejectExpandedPolicy(mac, identity string, generation uint64, previous confirmedRuntimePolicy, known bool, err error) {
	previous.Dirty = true
	if !known {
		previous.Identity, previous.Generation = identity, generation
	}
	w.confirmed[mac] = previous
	w.failure("expanded scoped policy", err)
}
