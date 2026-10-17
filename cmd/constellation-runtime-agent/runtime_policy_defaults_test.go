package main

import (
	"encoding/json"
	"net"
	"reflect"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func TestNativeTerminalDefaultsPreserveSourceAndAuthoredOrder(t *testing.T) {
	source := &dp.WorkloadPolicy{DefAction: dp.PolicyActionDeny, ApplyDir: dp.ApplyDirIngress, LocalIPs: []net.IP{net.ParseIP("10.0.0.1").To4(), net.ParseIP("10.0.0.3").To4()}, Rules: []*dp.PolicyRule{{ID: 11, IPProto: dp.IPProtoTCP, Port: 443, Action: dp.PolicyActionAllow}}}
	before, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	got, err := nativeTerminalDefaults(source, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 5 || got.Rules[0] != source.Rules[0] {
		t.Fatal("authored rule order or terminal count changed")
	}
	for _, rule := range got.Rules[1:] {
		assertTerminalDefault(t, rule, true, dp.PolicyActionDeny)
		if rule.IPProto == dp.IPProtoICMP {
			t.Fatal("ICMP enabled without scope opt-in")
		}
		if !rule.DstIP.Equal(source.LocalIPs[0]) && !rule.DstIP.Equal(source.LocalIPs[1]) {
			t.Fatal("fallback borrowed local identity")
		}
	}
	after, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("source policy mutated")
	}
	again, err := nativeTerminalDefaults(source, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, again) {
		t.Fatal("translation accumulates or changes defaults")
	}
}

func assertTerminalDefault(t *testing.T, rule *dp.PolicyRule, ingress bool, action uint8) {
	t.Helper()
	if rule.ID != 0 || rule.Ingress != ingress || rule.Action != action || len(rule.Apps) != 1 || rule.Apps[0] != (dp.PolicyApp{App: 0, RuleID: 0, Action: action}) {
		t.Fatalf("default attribution/app/direction changed: %+v", rule)
	}
	if rule.Port != 0 || rule.IPProto != dp.IPProtoICMP && rule.PortR != 65535 {
		t.Fatal("default port range truncated")
	}
}

func TestNativeTerminalDefaultsRespectDirectionAndICMPOptIn(t *testing.T) {
	for _, action := range []uint8{dp.PolicyActionDeny, dp.PolicyActionViolate} {
		source := &dp.WorkloadPolicy{DefAction: action, ApplyDir: dp.ApplyDirEgress, LocalIPs: []net.IP{net.ParseIP("10.0.0.1").To4()}}
		got, err := nativeTerminalDefaults(source, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Rules) != 3 {
			t.Fatalf("expected TCP/UDP/ICMP defaults, got%d", len(got.Rules))
		}
		for _, rule := range got.Rules {
			assertTerminalDefault(t, rule, false, action)
		}
		if got.Rules[2].IPProto != dp.IPProtoICMP || got.Rules[2].PortR != 0 {
			t.Fatal("ICMP port semantics changed")
		}
	}
	source := &dp.WorkloadPolicy{DefAction: dp.PolicyActionAllow}
	got, err := nativeTerminalDefaults(source, true)
	if err != nil || got != source {
		t.Fatal("allow default gained enforcement rules")
	}
}

func TestRuntimeTerminalDefaultsRetryAndRestartKeepExactSource(t *testing.T) {
	a := scopedPolicyFixture("a", "a-1", "uid-a", 11, "monitor")
	a.DefAction = dp.PolicyActionDeny
	worker, dataplane, _ := scopedPolicyHarness(t, a)
	dataplane.endpoints[0].IPs = []string{"10.0.0.1", "10.0.0.1", "0.0.0.0", "2001:db8::1"}
	dataplane.failMAC, dataplane.failCommand = scopedMACA, dp.CmdModify
	worker.SyncOnce(t.Context())
	if worker.Snapshot().UncertainMACs != 1 || worker.confirmed[scopedMACA].Source != nil {
		t.Fatal("failed transfer became confirmed")
	}
	dataplane.failMAC = ""
	worker.SyncOnce(t.Context())
	assertConfirmedTerminalRules(t, worker, dataplane, 5)
	worker.SyncOnce(t.Context())
	calls := len(dataplane.calls)
	worker.SyncOnce(t.Context())
	if len(dataplane.calls) != calls {
		t.Fatal("unchanged source reapplied or accumulated defaults")
	}
	dataplane.generation++
	worker.SyncOnce(t.Context())
	assertConfirmedTerminalRules(t, worker, dataplane, 5)
	dataplane.endpoints = nil
	worker.SyncOnce(t.Context())
	if len(worker.confirmed) != 0 {
		t.Fatal("retired endpoint kept confirmed source")
	}
}

func assertConfirmedTerminalRules(t *testing.T, worker *RuntimePolicySyncWorker, dataplane *scopedPolicyDP, expected int) {
	t.Helper()
	if worker.Snapshot().UncertainMACs != 0 || len(worker.confirmed[scopedMACA].Source.Rules) != 1 {
		t.Fatal("source retained generated rules or uncertain receipt")
	}
	for index := len(dataplane.calls) - 1; index >= 0; index-- {
		call := dataplane.calls[index]
		if call.command == dp.CmdModify && call.policy.MACs[0] == scopedMACA {
			if len(call.policy.Rules) != expected {
				t.Fatalf("wire rules=%d want%d", len(call.policy.Rules), expected)
			}
			return
		}
	}
	t.Fatal("no submitted scoped policy")
}

func TestNativeTerminalExpansionBudgetIncludesAuthoredAndICMP(t *testing.T) {
	source := &dp.WorkloadPolicy{DefAction: dp.PolicyActionDeny, ApplyDir: dp.ApplyDirBoth, LocalIPs: []net.IP{net.ParseIP("10.0.0.1").To4()}, Rules: make([]*dp.PolicyRule, dp.MaxExpandedPolicyRules-4)}
	rule := &dp.PolicyRule{IPProto: dp.IPProtoTCP, Action: dp.PolicyActionAllow}
	for index := range source.Rules {
		source.Rules[index] = rule
	}
	got, err := scopedNativePolicy(source, false)
	if err != nil || len(got.Rules) != dp.MaxExpandedPolicyRules {
		t.Fatalf("exact expanded limit rejected: %v", err)
	}
	source.Rules = append(source.Rules, rule)
	if got, err := scopedNativePolicy(source, false); err == nil || got != nil {
		t.Fatal("one-over terminal expansion accepted")
	}
	source.Rules = source.Rules[:dp.MaxExpandedPolicyRules/2]
	for index := range source.Rules {
		source.Rules[index] = &dp.PolicyRule{IPProto: dp.IPProtoAny, Action: dp.PolicyActionAllow}
	}
	if got, err := scopedNativePolicy(source, true); err == nil || got != nil {
		t.Fatal("ICMP compatibility expansion bypassed combined limit")
	}
}

func TestRuntimeTerminalExpansionLimitRetainsPriorWithoutReceipt(t *testing.T) {
	for _, prior := range []bool{false, true} {
		a := scopedPolicyFixture("a", "a-1", "uid-a", 11, "enforce")
		a.DefAction = dp.PolicyActionDeny
		worker, dataplane, _ := scopedPolicyHarness(t, a)
		if prior {
			worker.SyncOnce(t.Context())
		}
		old := worker.confirmed[scopedMACA].Source
		dataplane.calls = nil
		plan := buildRuntimePolicyScopePlan([]runtimePolicyWire{a}, dataplane.endpoints)
		candidate := plan.wanted[scopedMACA]
		candidate.Rules = make([]*dp.PolicyRule, dp.MaxExpandedPolicyRules-3)
		for index := range candidate.Rules {
			candidate.Rules[index] = &dp.PolicyRule{IPProto: dp.IPProtoTCP, Action: dp.PolicyActionAllow}
		}
		pushes := worker.Snapshot().Pushes
		worker.reconcileMAC(scopedMACA, plan, 1, false)
		current := worker.confirmed[scopedMACA]
		if !current.Dirty || current.Source != old || worker.Snapshot().Pushes != pushes || len(dataplane.calls) != 0 || worker.Snapshot().UncertainMACs != 1 {
			t.Fatal("over-limit candidate produced receipt, replaced reviewed source or did not report uncertainty")
		}
		plan = buildRuntimePolicyScopePlan([]runtimePolicyWire{a}, dataplane.endpoints)
		worker.reconcileMAC(scopedMACA, plan, 1, false)
		if worker.Snapshot().UncertainMACs != 0 || worker.Snapshot().Pushes != pushes+1 || worker.confirmed[scopedMACA].Source == nil {
			t.Fatal("corrected bounded candidate did not recover")
		}
	}
}
