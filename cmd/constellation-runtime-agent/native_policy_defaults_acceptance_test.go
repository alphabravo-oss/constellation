//go:build integration

package main

import (
	"net"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func (s *nativeAcceptanceScenario) packetQuery(name, mac, source, destination string, port uint16, protocol uint8, app uint32, ingress bool, action uint8, id uint32, temporary bool) {
	s.query(name, mac, source, destination, port, protocol, app, ingress, action, id)
	lookup := s.dataplane.steps[len(s.dataplane.steps)-1].Lookup
	lookup["packet"], lookup["tmp_open"] = true, temporary
	if id == 0 && (action == dp.PolicyActionDeny || action == dp.PolicyActionViolate) {
		lookup["finite_order"] = true
	}
}

func (s *nativeAcceptanceScenario) packetDefaultScopes() {
	// Negative control: actual native packet wrapper temporarily opens a
	// legacy implicit default when peer membership is unset.
	legacy := &dp.WorkloadPolicy{MACs: []string{scopedMACA}, DefAction: dp.PolicyActionDeny, ApplyDir: dp.ApplyDirBoth}
	s.dataplane.steps = append(s.dataplane.steps, nativeAcceptanceStep{Policy: legacy, Command: dp.CmdModify})
	s.packetQuery("legacy-implicit-default-demonstrates-unknown-peer-grace", scopedMACA, "10.0.0.1", "203.0.113.8", 1234, dp.IPProtoTCP, 0, false, dp.PolicyActionOpen, 0, true)
	s.a = nativeAcceptancePolicy("a", "a-1", "uid-a", 11, "enforce")
	s.a.DefAction = dp.PolicyActionDeny
	s.b = nativeAcceptancePolicy("b", "b-1", "uid-b", 22, "monitor")
	s.b.DefAction = dp.PolicyActionDeny
	s.dataplane.endpoints[0].IPs = []string{"10.0.0.1", "10.0.0.3"}
	s.publish(s.a, s.b)
	s.packetDefaultProtocols()
	s.packetDefaultDirections()
	s.packetDefaultICMP()
	s.packetDefaultFragments()
	s.packetDefaultLifecycle()
}

func (s *nativeAcceptanceScenario) packetDefaultProtocols() {
	for _, pair := range []struct {
		mac, local string
		action     uint8
	}{{scopedMACA, "10.0.0.1", dp.PolicyActionDeny}, {scopedMACA, "10.0.0.3", dp.PolicyActionDeny}, {scopedMACB, "10.0.0.2", dp.PolicyActionViolate}} {
		for _, protocol := range []uint8{dp.IPProtoTCP, dp.IPProtoUDP} {
			s.packetQuery("full-packet-reviewed-default-actual-local-address", pair.mac, pair.local, "203.0.113.8", 1234, protocol, 0, false, pair.action, 0, false)
			s.packetQuery("full-packet-ingress-reviewed-default", pair.mac, "203.0.113.8", pair.local, 1234, protocol, 1001, true, pair.action, 0, false)
		}
	}
	s.packetQuery("full-packet-nested-app-authored-rule-keeps-priority", scopedMACA, "10.0.0.1", "203.0.113.7", 443, dp.IPProtoTCP, 100, false, dp.PolicyActionDeny, 11, false)
	for _, app := range []uint32{999, 0xffffffff} {
		s.packetQuery("full-packet-unmatched-or-unknown-app-uses-default", scopedMACA, "10.0.0.1", "203.0.113.7", 443, dp.IPProtoTCP, app, false, dp.PolicyActionDeny, 0, false)
		s.packetQuery("full-packet-monitor-unmatched-or-unknown-app-uses-default", scopedMACB, "10.0.0.2", "203.0.113.7", 443, dp.IPProtoTCP, app, false, dp.PolicyActionViolate, 0, false)
	}
	s.packetQuery("full-packet-authored-allow-precedes-default", scopedMACA, "10.0.0.1", "203.0.113.7", 8080, dp.IPProtoTCP, 1001, false, dp.PolicyActionAllow, 11, false)
}

func (s *nativeAcceptanceScenario) packetDefaultDirections() {
	s.a.ApplyDir = dp.ApplyDirIngress
	s.b.ApplyDir = dp.ApplyDirEgress
	s.publish(s.a, s.b)
	s.packetQuery("ingress-only-protect-preserves-unconfigured-egress", scopedMACA, "10.0.0.1", "203.0.113.8", 1234, dp.IPProtoTCP, 1001, false, dp.PolicyActionOpen, 0, false)
	s.packetQuery("egress-only-monitor-preserves-unconfigured-ingress", scopedMACB, "203.0.113.8", "10.0.0.2", 1234, dp.IPProtoTCP, 1001, true, dp.PolicyActionOpen, 0, false)
	s.packetQuery("ingress-only-protect-applies-ingress-default", scopedMACA, "203.0.113.8", "10.0.0.1", 1234, dp.IPProtoTCP, 1001, true, dp.PolicyActionDeny, 0, false)
	s.packetQuery("egress-only-monitor-applies-egress-default", scopedMACB, "10.0.0.2", "203.0.113.8", 1234, dp.IPProtoTCP, 1001, false, dp.PolicyActionViolate, 0, false)
	s.a.ApplyDir, s.b.ApplyDir = dp.ApplyDirBoth, dp.ApplyDirBoth
	s.a.Rules, s.b.Rules = []*dp.PolicyRule{}, []*dp.PolicyRule{}
	s.publish(s.a, s.b)
	s.packetQuery("empty-authored-table-protect-default", scopedMACA, "10.0.0.1", "203.0.113.8", 1234, dp.IPProtoTCP, 1001, false, dp.PolicyActionDeny, 0, false)
	s.packetQuery("empty-authored-table-monitor-default", scopedMACB, "10.0.0.2", "203.0.113.8", 1234, dp.IPProtoUDP, 1001, false, dp.PolicyActionViolate, 0, false)
}

func (s *nativeAcceptanceScenario) packetDefaultICMP() {
	s.a.Rules = []*dp.PolicyRule{{SrcIP: net.IPv4zero, DstIP: net.ParseIP("203.0.113.7"), IPProto: dp.IPProtoICMP, Action: dp.PolicyActionDeny}}
	s.publish(s.a, s.b)
	s.packetQuery("opted-in-ICMP-keeps-authored-rule", scopedMACA, "10.0.0.1", "203.0.113.7", 0, dp.IPProtoICMP, 0, false, dp.PolicyActionDeny, 11, false)
	s.packetQuery("opted-in-ICMP-unmatched-peer-uses-default", scopedMACA, "10.0.0.1", "203.0.113.8", 0, dp.IPProtoICMP, 0, false, dp.PolicyActionDeny, 0, false)
	s.packetQuery("other-workload-ICMP-not-enforced-by-global-gate", scopedMACB, "10.0.0.2", "203.0.113.8", 0, dp.IPProtoICMP, 0, false, dp.PolicyActionAllow, 0, false)
	s.a.Rules = []*dp.PolicyRule{}
	s.publish(s.a, s.b)
	s.packetQuery("ICMP-opt-out-restores-native-allow", scopedMACA, "10.0.0.1", "203.0.113.8", 0, dp.IPProtoICMP, 0, false, dp.PolicyActionAllow, 0, false)
}

func (s *nativeAcceptanceScenario) packetDefaultLifecycle() {
	s.publish(s.b)
	s.packetQuery("retired-workload-has-no-terminal-rule", scopedMACA, "10.0.0.1", "203.0.113.8", 1234, dp.IPProtoTCP, 0, false, dp.PolicyActionOpen, 0, true)
	s.packetQuery("retirement-preserves-other-MAC-default", scopedMACB, "10.0.0.2", "203.0.113.8", 1234, dp.IPProtoTCP, 0, false, dp.PolicyActionViolate, 0, false)
	s.dataplane.generation++
	s.publish(s.a, s.b)
	s.packetQuery("new-epoch-reapplies-protect-default", scopedMACA, "10.0.0.1", "203.0.113.8", 1234, dp.IPProtoTCP, 0, false, dp.PolicyActionDeny, 0, false)
}

func (s *nativeAcceptanceScenario) packetDefaultFragments() {
	s.a.Mode = "monitor"
	s.a.Rules = []*dp.PolicyRule{{Port: 8443, IPProto: dp.IPProtoTCP, Action: dp.PolicyActionAllow}}
	for index := 0; index < 200; index++ {
		s.a.Rules = append(s.a.Rules, &dp.PolicyRule{Port: uint16(11000 + index), IPProto: dp.IPProtoTCP, Action: dp.PolicyActionDeny})
	}
	s.publish(s.a, s.b)
	candidate := s.dataplane.steps[len(s.dataplane.steps)-1]
	s.dataplane.steps = s.dataplane.steps[:len(s.dataplane.steps)-1]
	prefix := candidate
	prefix.Prefix = true
	s.dataplane.steps = append(s.dataplane.steps, prefix)
	s.packetQuery("incomplete-fragment-keeps-prior-protect-default", scopedMACA, "10.0.0.1", "203.0.113.8", 1234, dp.IPProtoTCP, 1001, false, dp.PolicyActionDeny, 0, false)
	s.packetQuery("incomplete-fragment-does-not-touch-other-MAC", scopedMACB, "10.0.0.2", "203.0.113.8", 1234, dp.IPProtoTCP, 1001, false, dp.PolicyActionViolate, 0, false)
	s.dataplane.steps = append(s.dataplane.steps, candidate)
	s.packetQuery("complete-retry-installs-new-monitor-default", scopedMACA, "10.0.0.1", "203.0.113.8", 1234, dp.IPProtoTCP, 1001, false, dp.PolicyActionViolate, 0, false)
	s.packetQuery("complete-retry-keeps-authored-allow", scopedMACA, "10.0.0.1", "203.0.113.8", 8443, dp.IPProtoTCP, 1001, false, dp.PolicyActionAllow, 11, false)
	s.a.Mode = "enforce"
	s.a.Rules = []*dp.PolicyRule{}
	s.publish(s.a, s.b)
}
