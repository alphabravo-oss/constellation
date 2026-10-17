package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

const scopedPolicyCluster = "75c07597-7b64-4bd8-80cf-5c6c15d29142"
const scopedMACA = "02:00:00:00:00:01"
const scopedMACB = "02:00:00:00:00:02"

type scopedPolicyCall struct {
	policy  *dp.WorkloadPolicy
	command uint
}
type scopedPolicyDP struct {
	ready       bool
	generation  uint64
	endpoints   []dp.PolicyEndpoint
	calls       []scopedPolicyCall
	allowed     []string
	icmp        []bool
	failMAC     string
	failCommand uint
}

func (d *scopedPolicyDP) Ready() bool        { return d.ready }
func (d *scopedPolicyDP) Generation() uint64 { return d.generation }
func (d *scopedPolicyDP) PolicyEndpoints() []dp.PolicyEndpoint {
	return append([]dp.PolicyEndpoint(nil), d.endpoints...)
}
func (d *scopedPolicyDP) PushEndpointPolicy(p *dp.WorkloadPolicy, command uint, expected *dp.PolicyEndpoint, generation uint64) error {
	if !d.ready || d.generation != generation {
		return errors.New("lifecycle changed")
	}
	var current *dp.PolicyEndpoint
	for _, endpoint := range d.endpoints {
		if endpoint.MAC == p.MACs[0] {
			copy := endpoint
			current = &copy
		}
	}
	if (expected == nil) != (current == nil) || expected != nil && !dp.SamePolicyEndpoint(*expected, *current) {
		return errors.New("endpoint changed")
	}
	d.calls = append(d.calls, scopedPolicyCall{p, command})
	if len(p.MACs) == 1 && p.MACs[0] == d.failMAC && command == d.failCommand {
		return errors.New("fixture datagram failure")
	}
	return nil
}
func (d *scopedPolicyDP) SetAllowedFqdns(names []string) { d.allowed = append([]string(nil), names...) }
func (d *scopedPolicyDP) SetICMPPolicy(enabled bool) error {
	d.icmp = append(d.icmp, enabled)
	return nil
}

func scopedPolicyFixture(workload, pod, uid string, id int64, mode string) runtimePolicyWire {
	return runtimePolicyWire{ID: uuid.NewString(), DPPolicyID: id, Workload: "test/" + workload, Namespace: "test", BindingStatus: "resolved", PodBindings: []runtimePolicyPodBinding{{Namespace: "test", PodName: pod, PodUID: uid}}, Version: 1, Mode: mode, DefAction: dp.PolicyActionAllow, ApplyDir: dp.ApplyDirBoth, Rules: []*dp.PolicyRule{{SrcIP: net.IPv4zero, DstIP: net.ParseIP("203.0.113.7"), Port: 443, IPProto: dp.IPProtoTCP, Action: dp.PolicyActionDeny, Apps: []dp.PolicyApp{{App: 100, Action: dp.PolicyActionDeny}}}}}
}
func scopedPolicyEnvelope(policies ...runtimePolicyWire) runtimePolicyBundle {
	if policies == nil {
		policies = []runtimePolicyWire{}
	}
	return runtimePolicyBundle{ProtocolVersion: 2, ClusterID: scopedPolicyCluster, SourceComplete: true, Policies: policies}
}
func scopedPolicyHarness(t *testing.T, policies ...runtimePolicyWire) (*RuntimePolicySyncWorker, *scopedPolicyDP, *atomic.Value) {
	t.Helper()
	var payload atomic.Value
	storeScopedPolicyPayload(t, &payload, scopedPolicyEnvelope(policies...))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cluster_id") != scopedPolicyCluster || r.URL.Query().Get("protocol") != "2" || r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("policy source scope changed")
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(payload.Load().([]byte)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	dataplane := &scopedPolicyDP{ready: true, generation: 1, endpoints: []dp.PolicyEndpoint{{MAC: scopedMACA, Namespace: "test", PodName: "a-1", PodUID: "uid-a", IPs: []string{"10.0.0.1"}}, {MAC: scopedMACB, Namespace: "test", PodName: "b-1", PodUID: "uid-b", IPs: []string{"10.0.0.2"}}}}
	worker := NewRuntimePolicySyncWorker(RuntimePolicySyncConfig{APIBaseURL: server.URL, Token: "fixture-token", ClusterID: scopedPolicyCluster, DPSup: dataplane, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	saved := pushedPolicyRIDs.Load()
	t.Cleanup(func() { pushedPolicyRIDs.Store(saved) })
	return worker, dataplane, &payload
}
func storeScopedPolicyPayload(t *testing.T, payload *atomic.Value, bundle runtimePolicyBundle) {
	t.Helper()
	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	payload.Store(body)
}
func scopedPolicyForMAC(t *testing.T, worker *RuntimePolicySyncWorker, mac string) *dp.WorkloadPolicy {
	t.Helper()
	source := worker.confirmed[mac].Source
	if source == nil {
		t.Fatalf("no submitted configuration for %s", mac)
	}
	return source
}

func TestRuntimePolicyScopesKeepTwoWorkloadsRulesDefaultsAndModesSeparate(t *testing.T) {
	a := scopedPolicyFixture("a", "a-1", "uid-a", 11, "enforce")
	a.DefAction, a.ApplyDir = dp.PolicyActionDeny, dp.ApplyDirEgress
	b := scopedPolicyFixture("b", "b-1", "uid-b", 22, "monitor")
	b.ApplyDir = dp.ApplyDirIngress
	worker, dataplane, _ := scopedPolicyHarness(t, a, b)
	worker.SyncOnce(t.Context())
	if len(dataplane.calls) != 2 {
		t.Fatalf("expected two scoped writes: %+v", dataplane.calls)
	}
	first, second := scopedPolicyForMAC(t, worker, scopedMACA), scopedPolicyForMAC(t, worker, scopedMACB)
	if !reflect.DeepEqual(first.MACs, []string{scopedMACA}) || !reflect.DeepEqual(second.MACs, []string{scopedMACB}) {
		t.Fatal("workloads shared a policy MAC scope")
	}
	if first.DefAction != dp.PolicyActionDeny || second.DefAction != dp.PolicyActionAllow || first.ApplyDir != dp.ApplyDirEgress || second.ApplyDir != dp.ApplyDirIngress {
		t.Fatal("defaults or directions crossed workload boundaries")
	}
	if len(first.Rules) != 1 || first.Rules[0].ID != 11 || first.Rules[0].Action != dp.PolicyActionDeny || first.Rules[0].Apps[0].Action != dp.PolicyActionDeny || first.Rules[0].Apps[0].RuleID != 11 {
		t.Fatal("protect policy changed")
	}
	if len(second.Rules) != 1 || second.Rules[0].ID != 22 || second.Rules[0].Action != dp.PolicyActionViolate || second.Rules[0].Apps[0].Action != dp.PolicyActionViolate || second.Rules[0].Apps[0].RuleID != 22 {
		t.Fatal("monitor policy can still block")
	}
	if b.Rules[0].Action != dp.PolicyActionDeny || b.Rules[0].Apps[0].Action != dp.PolicyActionDeny || b.Rules[0].Apps[0].RuleID != 0 {
		t.Fatal("source policy mutated during mode mapping")
	}
}

func TestRuntimePolicyDefaultOnlyRemovalAndSemanticChangesAreScoped(t *testing.T) {
	a := scopedPolicyFixture("a", "a-1", "uid-a", 11, "enforce")
	b := scopedPolicyFixture("b", "b-1", "uid-b", 22, "monitor")
	worker, dataplane, payload := scopedPolicyHarness(t, a, b)
	worker.SyncOnce(t.Context())
	dataplane.calls = nil
	a.Rules[0].Vhost = true
	a.Rules[0].Apps[0].App = 200
	storeScopedPolicyPayload(t, payload, scopedPolicyEnvelope(a, b))
	worker.SyncOnce(t.Context())
	if len(dataplane.calls) != 1 || dataplane.calls[0].policy.MACs[0] != scopedMACA {
		t.Fatal("app/vhost changes did not reapply only their workload")
	}
	b.Rules = []*dp.PolicyRule{}
	b.DefAction = dp.PolicyActionDeny
	storeScopedPolicyPayload(t, payload, scopedPolicyEnvelope(b))
	dataplane.calls = nil
	worker.SyncOnce(t.Context())
	if len(dataplane.calls) != 2 || dataplane.calls[0].command != dp.CmdDelete || dataplane.calls[0].policy.MACs[0] != scopedMACA {
		t.Fatal("removal cleared the wrong workload")
	}
	last := dataplane.calls[1]
	if last.command != dp.CmdModify || last.policy.MACs[0] != scopedMACB || len(last.policy.Rules) != 0 || last.policy.DefAction != dp.PolicyActionViolate {
		t.Fatal("default-only monitor policy was deleted instead of installed")
	}
}

func TestRuntimePolicyConflictsRetainOnlyTheSameExactPodGeneration(t *testing.T) {
	a := scopedPolicyFixture("a", "a-1", "uid-a", 11, "enforce")
	worker, dataplane, payload := scopedPolicyHarness(t, a)
	worker.SyncOnce(t.Context())
	before := fingerprintWorkloadPolicy(scopedPolicyForMAC(t, worker, scopedMACA))
	conflict := a
	conflict.ID, conflict.DPPolicyID, conflict.DefAction = uuid.NewString(), 12, dp.PolicyActionDeny
	storeScopedPolicyPayload(t, payload, scopedPolicyEnvelope(a, conflict))
	dataplane.calls = nil
	worker.SyncOnce(t.Context())
	if len(dataplane.calls) != 0 || worker.Snapshot().Conflicts == 0 || fingerprintWorkloadPolicy(scopedPolicyForMAC(t, worker, scopedMACA)) != before {
		t.Fatal("conflict replaced confirmed configuration")
	}
	dataplane.endpoints[0].PodUID = "uid-reassigned"
	worker.SyncOnce(t.Context())
	if len(dataplane.calls) != 1 || dataplane.calls[0].command != dp.CmdDelete || worker.confirmed[scopedMACA].Source != nil {
		t.Fatal("reassigned MAC inherited another pod generation's policy")
	}
}

func TestRuntimePolicyInvalidBundleNeverMutatesConfirmedState(t *testing.T) {
	a := scopedPolicyFixture("a", "a-1", "uid-a", 11, "enforce")
	a.Rules[0].Fqdn = "retained.example.test"
	worker, dataplane, payload := scopedPolicyHarness(t, a)
	worker.SyncOnce(t.Context())
	confirmed := worker.confirmed[scopedMACA]
	for _, invalid := range []string{"version", "cluster", "incomplete", "null", "duplicate", "bad-rule", "bad-ip", "bad-bindings"} {
		t.Run(invalid, func(t *testing.T) {
			bundle := scopedPolicyEnvelope(a)
			switch invalid {
			case "version":
				bundle.ProtocolVersion = 1
			case "cluster":
				bundle.ClusterID = uuid.NewString()
			case "incomplete":
				bundle.SourceComplete = false
			case "null":
				bundle.Policies = nil
			case "duplicate":
				bundle.Policies = append(bundle.Policies, a)
			case "bad-rule":
				bundle.Policies[0].Rules = []*dp.PolicyRule{nil}
			case "bad-ip":
				bundle.Policies[0].Rules = []*dp.PolicyRule{{SrcIP: net.ParseIP("2001:db8::1")}}
			case "bad-bindings":
				bundle.Policies[0].PodBindings = nil
			}
			storeScopedPolicyPayload(t, payload, bundle)
			writes, icmp := len(dataplane.calls), len(dataplane.icmp)
			before := worker.Snapshot()
			worker.SyncOnce(t.Context())
			if worker.Snapshot().Errors != before.Errors+1 || len(dataplane.calls) != writes || len(dataplane.icmp) != icmp || worker.confirmed[scopedMACA].Source != confirmed.Source {
				t.Fatal("invalid bundle partially changed confirmed state")
			}
			if !reflect.DeepEqual(dataplane.allowed, []string{"retained.example.test"}) {
				t.Fatal("invalid bundle changed resolver scope")
			}
		})
	}
}

func TestRuntimePolicyTransportFailureRetainsPriorScopeAndRetriesDeterministically(t *testing.T) {
	a := scopedPolicyFixture("a", "a-1", "uid-a", 11, "enforce")
	b := scopedPolicyFixture("b", "b-1", "uid-b", 22, "monitor")
	worker, dataplane, payload := scopedPolicyHarness(t, a, b)
	worker.SyncOnce(t.Context())
	prior := worker.confirmed[scopedMACA]
	a.Rules[0].Port = 8443
	b.Rules[0].Port = 9443
	storeScopedPolicyPayload(t, payload, scopedPolicyEnvelope(a, b))
	dataplane.calls = nil
	dataplane.failMAC, dataplane.failCommand = scopedMACA, dp.CmdModify
	worker.SyncOnce(t.Context())
	if worker.confirmed[scopedMACA].Source != prior.Source || worker.Snapshot().UncertainMACs != 1 || len(dataplane.calls) != 2 {
		t.Fatal("failed write was reported as confirmed or blocked unrelated workload")
	}
	if scopedPolicyForMAC(t, worker, scopedMACB).Rules[0].Port != 9443 {
		t.Fatal("independent workload did not progress")
	}
	dataplane.failMAC = ""
	dataplane.calls = nil
	worker.SyncOnce(t.Context())
	if worker.Snapshot().UncertainMACs != 0 || len(dataplane.calls) != 1 || dataplane.calls[0].policy.MACs[0] != scopedMACA || scopedPolicyForMAC(t, worker, scopedMACA).Rules[0].Port != 8443 {
		t.Fatal("retry replayed confirmed workloads or lost failed scope")
	}
	dataplane.generation++
	dataplane.ready = false
	dataplane.calls = nil
	worker.SyncOnce(t.Context())
	if len(dataplane.calls) != 0 {
		t.Fatal("not-ready restart received policy writes")
	}
	dataplane.ready = true
	worker.SyncOnce(t.Context())
	if len(dataplane.calls) != 2 {
		t.Fatal("restart did not reapply both workload scopes")
	}
}

func TestRuntimePolicyICMPGateDoesNotBroadenAnotherWorkloadsWildcardOrDefault(t *testing.T) {
	a := scopedPolicyFixture("a", "a-1", "uid-a", 11, "enforce")
	b := scopedPolicyFixture("b", "b-1", "uid-b", 22, "enforce")
	b.Rules[0].IPProto = dp.IPProtoAny
	b.DefAction = dp.PolicyActionDeny
	worker, dataplane, payload := scopedPolicyHarness(t, a, b)
	worker.SyncOnce(t.Context())
	a.Rules[0].IPProto, a.Rules[0].Port = dp.IPProtoICMP, 0
	a.Rules[0].Apps = nil
	storeScopedPolicyPayload(t, payload, scopedPolicyEnvelope(a, b))
	dataplane.calls = nil
	worker.SyncOnce(t.Context())
	assertScopedICMPBaseline(t, dataplane.calls)
	if !reflect.DeepEqual(dataplane.icmp, []bool{false, true}) {
		t.Fatalf("ICMP gate=%v", dataplane.icmp)
	}
	a.Rules[0].IPProto = dp.IPProtoTCP
	storeScopedPolicyPayload(t, payload, scopedPolicyEnvelope(a, b))
	worker.SyncOnce(t.Context())
	if !reflect.DeepEqual(dataplane.icmp, []bool{false, true, false}) {
		t.Fatalf("ICMP gate did not return off: %v", dataplane.icmp)
	}
	if final := worker.confirmed[scopedMACB]; final.Dirty || scopedPolicyForMAC(t, worker, scopedMACB).Rules[0].IPProto != dp.IPProtoAny {
		t.Fatal("B's source policy was mutated")
	}
}

func assertScopedICMPBaseline(t *testing.T, calls []scopedPolicyCall) {
	t.Helper()
	var scoped *dp.WorkloadPolicy
	for _, call := range calls {
		if call.policy.MACs[0] == scopedMACB {
			scoped = call.policy
		}
	}
	if scoped == nil || len(scoped.Rules) != 4 {
		t.Fatalf("missing independent ICMP compatibility table: %+v", scoped)
	}
	for index := 0; index < 2; index++ {
		rule := scoped.Rules[index]
		if rule.IPProto != dp.IPProtoICMP || rule.Action != dp.PolicyActionAllow || rule.Ingress != (index == 1) || !icmpCompatibilityMatchesLocal(rule, "10.0.0.2") {
			t.Fatalf("ICMP baseline changed: %+v", rule)
		}
	}
	if scoped.Rules[2].IPProto != dp.IPProtoTCP || scoped.Rules[3].IPProto != dp.IPProtoUDP || scoped.Rules[2].Action != dp.PolicyActionDeny {
		t.Fatal("B wildcard broadened or lost protect action")
	}
}

func icmpCompatibilityMatchesLocal(rule *dp.PolicyRule, address string) bool {
	if rule.Ingress {
		return rule.SrcIP.String() == "0.0.0.0" && rule.SrcIPR.String() == "255.255.255.255" && rule.DstIP.String() == address && rule.DstIPR.String() == address
	}
	return rule.DstIP.String() == "0.0.0.0" && rule.DstIPR.String() == "255.255.255.255" && rule.SrcIP.String() == address && rule.SrcIPR.String() == address
}

func TestRuntimePolicyNativeSelectorsUseCurrentInterfaceAddresses(t *testing.T) {
	policy := scopedPolicyFixture("a", "a-1", "uid-a", 11, "enforce")
	policy.Rules = append(policy.Rules, &dp.PolicyRule{Ingress: true, Port: 0, IPProto: dp.IPProtoTCP, Action: dp.PolicyActionDeny})
	worker, dataplane, _ := scopedPolicyHarness(t, policy)
	dataplane.endpoints[0].IPs = []string{"10.0.0.1", "10.0.1.1", "2001:db8::1"}
	worker.SyncOnce(t.Context())
	scoped := scopedPolicyForMAC(t, worker, scopedMACA)
	if len(scoped.Rules) != 4 {
		t.Fatalf("expected two exact local IPs per rule, got %d", len(scoped.Rules))
	}
	egress := scoped.Rules[0]
	if egress.SrcIP.String() != "10.0.0.1" || egress.SrcIPR.String() != "10.0.0.1" || egress.DstIPR.String() != "203.0.113.7" || egress.PortR != 443 {
		t.Fatalf("single-port native selector=%+v", egress)
	}
	if !nativeScopedRangeMatches(egress, "10.0.0.1", "203.0.113.7", 443, false) {
		t.Fatal("native keyed/range lookup cannot match intended egress")
	}
	if nativeScopedRangeMatches(egress, "10.0.0.2", "203.0.113.7", 443, false) || nativeScopedRangeMatches(egress, "10.0.0.1", "203.0.113.7", 444, false) {
		t.Fatal("native selector broadened to other workload/port")
	}
	ingress := scoped.Rules[2]
	if ingress.PortR != 65535 || !nativeScopedRangeMatches(ingress, "198.51.100.2", "10.0.0.1", 8080, true) {
		t.Fatalf("wildcard ingress cannot match intended flow: %+v", ingress)
	}
	if nativeScopedRangeMatches(ingress, "198.51.100.2", "10.0.0.2", 8080, true) {
		t.Fatal("ingress borrowed another workload local address")
	}
}

// Mirrors native get_range_key + rule_key_in_range: the local IP is a hash
// key, not a wildcard range, before the ordinary lower/upper range checks.
func nativeScopedRangeMatches(rule *dp.PolicyRule, src, dst string, port uint16, ingress bool) bool {
	source, destination := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	if rule.Ingress != ingress || port < rule.Port || port > rule.PortR {
		return false
	}
	if ingress && !destination.Equal(rule.DstIP) || !ingress && !source.Equal(rule.SrcIP) {
		return false
	}
	return bytes.Compare(source, rule.SrcIP) >= 0 && bytes.Compare(source, rule.SrcIPR) <= 0 && bytes.Compare(destination, rule.DstIP) >= 0 && bytes.Compare(destination, rule.DstIPR) <= 0
}

func TestRuntimePolicyRegistrationChangeReappliesWithoutInheritance(t *testing.T) {
	policy := scopedPolicyFixture("a", "a-1", "uid-a", 11, "monitor")
	worker, dataplane, _ := scopedPolicyHarness(t, policy)
	worker.SyncOnce(t.Context())
	dataplane.calls = nil
	dataplane.endpoints[0].Registration++
	worker.SyncOnce(t.Context())
	if len(dataplane.calls) != 2 || dataplane.calls[0].command != dp.CmdDelete || dataplane.calls[1].command != dp.CmdModify {
		t.Fatalf("same UID re-registration failed to reapply: %+v", dataplane.calls)
	}
	dataplane.calls = nil
	dataplane.endpoints[0].IPs = nil
	worker.SyncOnce(t.Context())
	if worker.confirmed[scopedMACA].Source != nil {
		t.Fatal("unresolved current local addresses inherited prior workload policy")
	}
	for _, call := range dataplane.calls {
		if call.command == dp.CmdModify {
			t.Fatal("unknown local address programmed")
		}
	}
}

func TestRuntimePolicyPartialSubmissionNeverBecomesConfirmed(t *testing.T) {
	policy := scopedPolicyFixture("a", "a-1", "uid-a", 11, "enforce")
	worker, dataplane, _ := scopedPolicyHarness(t, policy)
	dataplane.failMAC, dataplane.failCommand = scopedMACA, dp.CmdModify
	worker.SyncOnce(t.Context())
	if state := worker.confirmed[scopedMACA]; state.Source != nil || !state.Dirty || state.Possible == nil {
		t.Fatalf("partial send claimed confirmed: %+v", state)
	}
	if stats := worker.Snapshot(); stats.Pushes != 0 || stats.UncertainMACs != 1 {
		t.Fatalf("partial send stats=%+v", stats)
	}
	dataplane.failMAC = ""
	worker.SyncOnce(t.Context())
	if state := worker.confirmed[scopedMACA]; state.Source == nil || state.Dirty {
		t.Fatalf("retry did not confirm complete transfer: %+v", state)
	}
}
