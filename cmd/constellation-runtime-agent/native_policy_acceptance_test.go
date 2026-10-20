//go:build integration

package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// The second phase, in dp/native_policy_acceptance_test.go, sends these
// translated policies through the actual Go IPC encoder into native C objects.
type nativeAcceptanceStep struct {
	Name    string             `json:"name"`
	Policy  *dp.WorkloadPolicy `json:"policy,omitempty"`
	Command uint               `json:"command,omitempty"`
	ICMP    *bool              `json:"icmp,omitempty"`
	Lookup  map[string]any     `json:"lookup,omitempty"`
	Prefix  bool               `json:"prefix,omitempty"`
}

type nativeAcceptanceDP struct {
	*scopedPolicyDP
	steps []nativeAcceptanceStep
}

func (d *nativeAcceptanceDP) SetICMPPolicy(value bool) error {
	d.steps = append(d.steps, nativeAcceptanceStep{ICMP: &value})
	return d.scopedPolicyDP.SetICMPPolicy(value)
}

func (d *nativeAcceptanceDP) PushEndpointPolicy(policy *dp.WorkloadPolicy, command uint, endpoint *dp.PolicyEndpoint, generation uint64) error {
	if err := d.scopedPolicyDP.PushEndpointPolicy(policy, command, endpoint, generation); err != nil {
		return err
	}
	d.steps = append(d.steps, nativeAcceptanceStep{Policy: policy, Command: command})
	return nil
}

type nativeAcceptanceScenario struct {
	t         *testing.T
	worker    *RuntimePolicySyncWorker
	dataplane *nativeAcceptanceDP
	publish   func(...runtimePolicyWire)
	a, b      runtimePolicyWire
}

func TestGenerateNativeRuntimePolicyFixture(t *testing.T) {
	t.Parallel()
	directory := os.Getenv("CONSTELLATION_NATIVE_POLICY_DIR")
	if directory == "" {
		t.Skip("opt in with scripts/test-native-policy.sh; requires native C harness")
	}
	a := nativeAcceptancePolicy("a", "a-1", "uid-a", 11, "enforce")
	a.DefAction = dp.PolicyActionDeny
	b := nativeAcceptancePolicy("b", "b-1", "uid-b", 22, "monitor")
	worker, base, payload := scopedPolicyHarness(t, a, b)
	dataplane := &nativeAcceptanceDP{scopedPolicyDP: base}
	worker.cfg.DPSup = dataplane
	scenario := &nativeAcceptanceScenario{t: t, worker: worker, dataplane: dataplane, a: a, b: b, publish: func(policies ...runtimePolicyWire) {
		storeScopedPolicyPayload(t, payload, scopedPolicyEnvelope(policies...))
		worker.SyncOnce(t.Context())
	}}
	scenario.initialScopes()
	scenario.directionAndDefaultOnly()
	scenario.icmpTransitions()
	scenario.partialTransfer()
	scenario.scopedLifecycle()
	scenario.packetDefaultScopes()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	file, err := root.OpenFile("policies.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(errors.Join(err, root.Close()))
	}
	encodeErr := json.NewEncoder(file).Encode(dataplane.steps)
	if err := errors.Join(encodeErr, file.Close(), root.Close()); err != nil {
		t.Fatal(err)
	}
	t.Logf("generated %d actual-worker native acceptance steps", len(dataplane.steps))
}

func nativeAcceptancePolicy(workload, pod, uid string, id int64, mode string) runtimePolicyWire {
	policy := scopedPolicyFixture(workload, pod, uid, id, mode)
	policy.Rules = []*dp.PolicyRule{
		{DstIP: net.ParseIP("203.0.113.7"), Port: 443, IPProto: dp.IPProtoTCP, Action: dp.PolicyActionCheckApp, Apps: []dp.PolicyApp{{App: 100, Action: dp.PolicyActionDeny, RuleID: 999}}},
		{DstIP: net.ParseIP("203.0.113.7"), Port: 8443, IPProto: dp.IPProtoTCP, Action: dp.PolicyActionDeny},
		{Port: 8080, IPProto: dp.IPProtoTCP, Action: dp.PolicyActionAllow},
		{Port: 9090, Ingress: true, IPProto: dp.IPProtoTCP, Action: dp.PolicyActionDeny},
	}
	return policy
}

func (s *nativeAcceptanceScenario) query(name, mac, source, destination string, port uint16, protocol uint8, app uint32, ingress bool, action uint8, id uint32) {
	s.dataplane.steps = append(s.dataplane.steps, nativeAcceptanceStep{Name: name, Lookup: map[string]any{"mac": mac, "sip": source, "dip": destination, "port": port, "proto": protocol, "app": app, "ingress": ingress, "action": action, "id": id}})
}

func (s *nativeAcceptanceScenario) egress(name, mac, local string, port uint16, app uint32, action uint8, id uint32) {
	s.query(name, mac, local, "203.0.113.7", port, dp.IPProtoTCP, app, false, action, id)
}

func (s *nativeAcceptanceScenario) initialScopes() {
	s.publish(s.a, s.b)
	s.egress("protect-nested-app-deny-and-RID", scopedMACA, "10.0.0.1", 443, 100, dp.PolicyActionDeny, 11)
	s.egress("monitor-nested-app-violate-and-RID", scopedMACB, "10.0.0.2", 443, 100, dp.PolicyActionViolate, 22)
	s.egress("protect-unmatched-app-does-not-borrow-nested-rule", scopedMACA, "10.0.0.1", 443, 999, dp.PolicyActionDeny, 0)
	s.egress("monitor-unmatched-app-does-not-borrow-nested-rule", scopedMACB, "10.0.0.2", 443, 999, dp.PolicyActionAllow, 0)
	s.query("protect-wrong-remote-IP-does-not-match", scopedMACA, "10.0.0.1", "198.51.100.2", 8443, dp.IPProtoTCP, 0, false, dp.PolicyActionDeny, 0)
	s.query("monitor-wrong-remote-IP-does-not-match-App", scopedMACB, "10.0.0.2", "198.51.100.2", 443, dp.IPProtoTCP, 100, false, dp.PolicyActionAllow, 0)
	s.egress("protect-main-deny", scopedMACA, "10.0.0.1", 8443, 0, dp.PolicyActionDeny, 11)
	s.egress("monitor-main-violate", scopedMACB, "10.0.0.2", 8443, 0, dp.PolicyActionViolate, 22)
	s.egress("protect-unmatched-default-deny", scopedMACA, "10.0.0.1", 22, 0, dp.PolicyActionDeny, 0)
	s.egress("monitor-unmatched-default-allow", scopedMACB, "10.0.0.2", 22, 0, dp.PolicyActionAllow, 0)
	s.egress("protect-other-local-IP-does-not-borrow-rule", scopedMACA, "10.0.0.2", 8443, 0, dp.PolicyActionDeny, 0)
	s.egress("monitor-other-local-IP-does-not-borrow-rule", scopedMACB, "10.0.0.1", 8443, 0, dp.PolicyActionAllow, 0)
	s.query("protect-remote-any-allow", scopedMACA, "10.0.0.1", "198.51.100.2", 8080, dp.IPProtoTCP, 0, false, dp.PolicyActionAllow, 11)
	s.query("protect-ingress-deny", scopedMACA, "198.51.100.2", "10.0.0.1", 9090, dp.IPProtoTCP, 0, true, dp.PolicyActionDeny, 11)
	s.query("monitor-ingress-violate", scopedMACB, "198.51.100.2", "10.0.0.2", 9090, dp.IPProtoTCP, 0, true, dp.PolicyActionViolate, 22)
	s.query("implicit-ICMP-before-opt-in", scopedMACA, "10.0.0.1", "203.0.113.7", 0, dp.IPProtoICMP, 0, false, dp.PolicyActionAllow, 0)
}

func (s *nativeAcceptanceScenario) directionAndDefaultOnly() {
	s.a.ApplyDir = dp.ApplyDirEgress
	s.publish(s.a, s.b)
	s.query("direction-change-does-not-enforce-disabled-ingress", scopedMACA, "198.51.100.2", "10.0.0.1", 9090, dp.IPProtoTCP, 0, true, dp.PolicyActionOpen, 0)
	s.query("direction-change-does-not-affect-other-MAC", scopedMACB, "198.51.100.2", "10.0.0.2", 9090, dp.IPProtoTCP, 0, true, dp.PolicyActionViolate, 22)
	s.a.ApplyDir = dp.ApplyDirBoth
	s.b.DefAction = dp.PolicyActionDeny
	s.b.Rules = []*dp.PolicyRule{}
	s.publish(s.a, s.b)
	s.egress("zero-rule-monitor-default-is-installed", scopedMACB, "10.0.0.2", 22, 0, dp.PolicyActionViolate, 0)
	s.egress("zero-rule-other-workload-preserved", scopedMACA, "10.0.0.1", 443, 100, dp.PolicyActionDeny, 11)
}

func (s *nativeAcceptanceScenario) icmpTransitions() {
	s.a.Rules = append(s.a.Rules, &dp.PolicyRule{IPProto: dp.IPProtoICMP, Action: dp.PolicyActionDeny})
	s.b.Rules = []*dp.PolicyRule{{IPProto: dp.IPProtoAny, Action: dp.PolicyActionDeny}}
	s.publish(s.a, s.b)
	s.query("explicit-ICMP-protect-deny", scopedMACA, "10.0.0.1", "203.0.113.7", 0, dp.IPProtoICMP, 0, false, dp.PolicyActionDeny, 11)
	s.query("other-scope-ICMP-egress-remains-allowed", scopedMACB, "10.0.0.2", "203.0.113.7", 0, dp.IPProtoICMP, 0, false, dp.PolicyActionAllow, 0)
	s.query("other-scope-ICMP-ingress-remains-allowed", scopedMACB, "203.0.113.7", "10.0.0.2", 0, dp.IPProtoICMP, 0, true, dp.PolicyActionAllow, 0)
	s.query("monitor-wildcard-TCP-stays-violate", scopedMACB, "10.0.0.2", "203.0.113.7", 32000, dp.IPProtoTCP, 0, false, dp.PolicyActionViolate, 22)
	s.query("monitor-wildcard-UDP-stays-violate", scopedMACB, "10.0.0.2", "203.0.113.7", 53, dp.IPProtoUDP, 0, false, dp.PolicyActionViolate, 22)
	s.a.Rules = s.a.Rules[:len(s.a.Rules)-1]
	s.publish(s.a, s.b)
	s.query("ICMP-gate-off-restores-protect-baseline", scopedMACA, "10.0.0.1", "203.0.113.7", 0, dp.IPProtoICMP, 0, false, dp.PolicyActionAllow, 0)
	s.query("ICMP-gate-off-preserves-monitor-baseline", scopedMACB, "10.0.0.2", "203.0.113.7", 0, dp.IPProtoICMP, 0, false, dp.PolicyActionAllow, 0)
}

func (s *nativeAcceptanceScenario) partialTransfer() {
	replacement := s.a
	replacement.Rules = append([]*dp.PolicyRule(nil), s.a.Rules...)
	changed := *replacement.Rules[1]
	changed.Action = dp.PolicyActionAllow
	replacement.Rules[1] = &changed
	for index := 0; index < 200; index++ {
		replacement.Rules = append(replacement.Rules, &dp.PolicyRule{Port: uint16(11000 + index), IPProto: dp.IPProtoTCP, Action: dp.PolicyActionDeny})
	}
	bundle := scopedPolicyEnvelope(replacement, s.b)
	if err := validateRuntimePolicyBundle(&bundle, scopedPolicyCluster); err != nil {
		s.t.Fatal(err)
	}
	candidate := buildRuntimePolicyScopePlan(bundle.Policies, s.dataplane.endpoints).wanted[scopedMACA]
	if candidate == nil {
		s.t.Fatal("partial candidate unresolved")
	}
	s.dataplane.steps = append(s.dataplane.steps, nativeAcceptanceStep{Name: "unfinished-fragment-prefix", Policy: candidate, Command: dp.CmdModify, Prefix: true})
	s.egress("prefix-without-MSG-END-retains-prior-table", scopedMACA, "10.0.0.1", 8443, 0, dp.PolicyActionDeny, 11)
	s.query("prefix-does-not-touch-other-MAC", scopedMACB, "10.0.0.2", "203.0.113.7", 53, dp.IPProtoUDP, 0, false, dp.PolicyActionViolate, 22)
	s.dataplane.steps = append(s.dataplane.steps, nativeAcceptanceStep{Name: "fresh-complete-retry", Policy: candidate, Command: dp.CmdModify})
	s.egress("complete-retry-replaces-only-own-table", scopedMACA, "10.0.0.1", 8443, 0, dp.PolicyActionAllow, 11)
}

func (s *nativeAcceptanceScenario) scopedLifecycle() {
	s.publish(s.b)
	s.egress("scoped-delete-clears-only-removed-workload", scopedMACA, "10.0.0.1", 443, 100, dp.PolicyActionOpen, 0)
	s.query("scoped-delete-preserves-other-workload", scopedMACB, "10.0.0.2", "203.0.113.7", 53, dp.IPProtoUDP, 0, false, dp.PolicyActionViolate, 22)
	// Native refcount regression: legacy multi-MAC handles must survive removing
	// one MAC. This is a test-only native input, never a new worker union.
	s.dataplane.steps = append(s.dataplane.steps, nativeAcceptanceStep{Policy: &dp.WorkloadPolicy{MACs: []string{scopedMACA, scopedMACB}, DefAction: dp.PolicyActionAllow, ApplyDir: dp.ApplyDirBoth}, Command: dp.CmdModify})
	s.dataplane.steps = append(s.dataplane.steps, nativeAcceptanceStep{Policy: &dp.WorkloadPolicy{MACs: []string{scopedMACA}}, Command: dp.CmdDelete})
	s.egress("retired-MAC-on-shared-native-handle-is-open", scopedMACA, "10.0.0.1", 22, 0, dp.PolicyActionOpen, 0)
	s.egress("other-MAC-sharing-prior-handle-still-present", scopedMACB, "10.0.0.2", 22, 0, dp.PolicyActionAllow, 0)
}
