package dp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPolicyTransferSerializesConcurrentScopedClear(t *testing.T) {
	server := newCaptureServer(t)
	client := newClientPointedAt(t, server)
	rules := make([]*PolicyRule, 2000)
	for index := range rules {
		rules[index] = &PolicyRule{ID: uint32(index + 1), Fqdn: strings.Repeat("x", 120), Action: PolicyActionDeny}
	}
	pushed := make(chan error, 1)
	go func() {
		pushed <- client.pushPolicy(&WorkloadPolicy{MACs: []string{"02:00:00:00:00:01"}, Rules: rules}, CmdModify)
	}()
	first := server.drain(1)
	if len(first) != 1 {
		t.Fatal("missing initial fragment")
	}
	cleared := make(chan error, 1)
	go func() { cleared <- client.pushPolicy(&WorkloadPolicy{MACs: []string{"02:00:00:00:00:02"}}, CmdDelete) }()
	assertSerializedPolicyTransfer(t, server, first, len(rules))
	if err := <-pushed; err != nil {
		t.Fatal(err)
	}
	if err := <-cleared; err != nil {
		t.Fatal(err)
	}
}

func assertSerializedPolicyTransfer(t *testing.T, server *captureServer, first [][]byte, expected int) {
	t.Helper()
	sawEnd := false
	total := 0
	for index := 0; index < 2000; index++ {
		messages := first
		if index > 0 {
			messages = server.drain(1)
		}
		if len(messages) != 1 {
			t.Fatal("incomplete transfer")
		}
		var request policyCfgReq
		if err := json.Unmarshal(messages[0], &request); err != nil {
			t.Fatal(err)
		}
		if request.Cfg.Cmd == CmdDelete {
			if !sawEnd {
				t.Fatal("scoped clear interrupted native global staging handle")
			}
			if got := request.Cfg.WorkloadMac; len(got) != 1 || got[0] != "02:00:00:00:00:02" {
				t.Fatalf("clear targets=%v", got)
			}
			break
		}
		if sawEnd {
			t.Fatal("fragment after end")
		}
		total += len(request.Cfg.IPRules)
		sawEnd = request.Cfg.Flag&MsgEnd != 0
	}
	if total != expected {
		t.Fatalf("transferred=%d want=%d", total, expected)
	}
}

func TestPolicyTransferReportsPartialDatagramFailure(t *testing.T) {
	server := newCaptureServer(t)
	client := newClientPointedAt(t, server)
	rules := make([]*PolicyRule, 2000)
	for index := range rules {
		rules[index] = &PolicyRule{ID: uint32(index + 1), Fqdn: strings.Repeat("x", 120)}
	}
	result := make(chan error, 1)
	go func() {
		result <- client.pushPolicy(&WorkloadPolicy{MACs: []string{"02:00:00:00:00:01"}, Rules: rules}, CmdModify)
	}()
	first := server.drain(1)
	if len(first) != 1 {
		t.Fatal("missing first fragment")
	}
	var request policyCfgReq
	if err := json.Unmarshal(first[0], &request); err != nil {
		t.Fatal(err)
	}
	if request.Cfg.Flag&MsgEnd != 0 {
		t.Fatal("fixture must leave incomplete native handle")
	}
	if err := server.conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("partial transfer reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("failed transfer did not terminate")
	}
}

func TestTapRegistrationRecycledUIDAndDataplaneEpoch(t *testing.T) {
	server := newCaptureServer(t)
	client := newClientPointedAt(t, server)
	a := TapTarget{NetNS: "/proc/20/ns/net", Iface: "eth0", EPMAC: "02:00:00:00:00:01", Namespace: "ns", PodName: "pod", PodUID: "uid-a"}
	b := TapTarget{NetNS: "/proc/21/ns/net", Iface: "eth0", EPMAC: "02:00:00:00:00:02", Namespace: "ns", PodName: "other", PodUID: "uid-b"}
	provider := &fakeTapProvider{targets: []TapTarget{a, b}}
	manager := newTapManager(client, provider, newSilentLogger(), time.Second)
	epoch := uint64(1)
	manager.ready = func() bool { return true }
	manager.generation = func() uint64 { return epoch }
	manager.reconcileOnce(t.Context())
	before := manager.current[a.key()].Registration
	_ = server.drain(9)
	a.PodUID = "uid-new"
	provider.targets = []TapTarget{a, b}
	manager.reconcileOnce(t.Context())
	after := manager.current[a.key()].Registration
	if after <= before {
		t.Fatalf("registration did not advance: %d -> %d", before, after)
	}
	messages := server.drain(8)
	assertRetireBeforeRegister(t, messages, a.EPMAC, b.EPMAC)
	// A native restart invalidates endpoints until registrations are rebuilt.
	supervisor := &Supervisor{client: client, taps: manager}
	supervisor.generation.Store(2)
	if got := supervisor.PolicyEndpoints(); len(got) != 0 {
		t.Fatalf("stale epoch endpoints=%v", got)
	}
	epoch = 2
	// Drain concurrently: rebuilding both registrations includes retirement+add.
	drained := make(chan struct{})
	go func() { _ = server.drain(20); close(drained) }()
	manager.reconcileOnce(t.Context())
	<-drained
	if next := manager.current[a.key()].Registration; next <= after {
		t.Fatalf("restart reused registration %d", next)
	}
	if manager.snapshot().CurrentTaps != 2 {
		t.Fatal("restart lost targets")
	}
}

func assertRetireBeforeRegister(t *testing.T, messages [][]byte, mac, untouched string) {
	t.Helper()
	retired, registered := -1, -1
	for index, message := range messages {
		text := string(message)
		if strings.Contains(text, untouched) {
			t.Fatalf("retiring one endpoint touched other MAC: %s", text)
		}
		if strings.Contains(text, "ctrl_del_mac") {
			retired = index
		}
		if strings.Contains(text, "ctrl_add_mac") {
			registered = index
		}
	}
	if retired < 0 || registered <= retired {
		t.Fatalf("retirement must precede replacement registration: retired=%d registered=%d", retired, registered)
	}
}

func TestEndpointPolicyRejectsStaleRegistrationAndLifecycle(t *testing.T) {
	server := newCaptureServer(t)
	client := newClientPointedAt(t, server)
	manager := newTapManager(client, &fakeTapProvider{}, newSilentLogger(), time.Second)
	endpoint := PolicyEndpoint{MAC: "02:00:00:00:00:01", Namespace: "ns", PodName: "pod", PodUID: "uid", Registration: 2}
	manager.current["test"] = TapTarget{EPMAC: endpoint.MAC, Namespace: endpoint.Namespace, PodName: endpoint.PodName, PodUID: endpoint.PodUID, Registration: 2}
	supervisor := &Supervisor{client: client, taps: manager}
	supervisor.generation.Store(1)
	supervisor.readyGen.Store(1)
	supervisor.activeGen.Store(1)
	policy := &WorkloadPolicy{MACs: []string{endpoint.MAC}, DefAction: PolicyActionDeny}
	stale := endpoint
	stale.Registration = 1
	if err := supervisor.PushEndpointPolicy(policy, CmdModify, &stale, 1); err == nil {
		t.Fatal("stale registration accepted")
	}
	if err := supervisor.PushEndpointPolicy(policy, CmdModify, nil, 1); err == nil {
		t.Fatal("unregistered clear may not target current endpoint")
	}
	if err := supervisor.PushEndpointPolicy(policy, CmdModify, &endpoint, 2); err == nil {
		t.Fatal("wrong lifecycle accepted")
	}
	if got := server.drain(1); len(got) != 0 {
		t.Fatalf("stale request emitted %s", got[0])
	}
	if err := supervisor.PushEndpointPolicy(policy, CmdModify, &endpoint, 1); err != nil {
		t.Fatal(err)
	}
	if got := server.drain(1); len(got) != 1 {
		t.Fatal("current default-only policy not submitted")
	}
}

func TestEnforceRegistrationRecycledPodUID(t *testing.T) {
	server := newCaptureServer(t)
	client := newClientPointedAt(t, server)
	target := EnforceTarget{NetNS: "/proc/20/ns/net", Iface: "eth0", EPMAC: "02:00:00:00:00:01", Namespace: "ns", PodName: "pod", PodUID: "old"}
	provider := &fakeEnforceProvider{}
	provider.set(target)
	manager := newEnforceManager(client, provider, newSilentLogger(), time.Second, &ipt{runner: newFakeRunner()}, NewQnumAllocator(4000, 10))
	manager.reconcileOnce(context.Background())
	registration := manager.current[target.key()].Registration
	_ = server.drain(6)
	target.PodUID = "new"
	provider.set(target)
	manager.reconcileOnce(context.Background())
	if got := manager.current[target.key()]; got.PodUID != "new" || got.Registration <= registration {
		t.Fatalf("recycled target=%+v", got)
	}
	assertRetireBeforeRegister(t, server.drain(10), target.EPMAC, "does-not-exist")
	if got := manager.qnums.InUse(); got != 1 {
		t.Fatalf("queue leak: %d", got)
	}
}

type policyTapProviderFunc func(context.Context) ([]TapTarget, error)

func (f policyTapProviderFunc) Desired(ctx context.Context) ([]TapTarget, error) { return f(ctx) }

type policyEnforceProviderFunc func(context.Context) ([]EnforceTarget, error)

func (f policyEnforceProviderFunc) Desired(ctx context.Context) ([]EnforceTarget, error) {
	return f(ctx)
}

func TestEndpointManagersRejectRestartDuringDiscovery(t *testing.T) {
	for _, kind := range []string{"tap", "inline"} {
		t.Run(kind, func(t *testing.T) {
			server := newCaptureServer(t)
			client := newClientPointedAt(t, server)
			ready, epoch := true, uint64(1)
			restart := func() { ready = false; epoch++ }
			if kind == "tap" {
				provider := policyTapProviderFunc(func(context.Context) ([]TapTarget, error) {
					restart()
					return []TapTarget{{Iface: "eth0", EPMAC: "02:00:00:00:00:01"}}, nil
				})
				manager := newTapManager(client, provider, newSilentLogger(), time.Second)
				manager.ready, manager.generation = func() bool { return ready }, func() uint64 { return epoch }
				manager.reconcileOnce(t.Context())
				if manager.snapshot().CurrentTaps != 0 {
					t.Fatal("not-ready dataplane registered tap")
				}
			} else {
				provider := policyEnforceProviderFunc(func(context.Context) ([]EnforceTarget, error) {
					restart()
					return []EnforceTarget{{Iface: "eth0", EPMAC: "02:00:00:00:00:01"}}, nil
				})
				runner := newFakeRunner()
				manager := newEnforceManager(client, provider, newSilentLogger(), time.Second, &ipt{runner: runner}, NewQnumAllocator(4000, 10))
				manager.ready, manager.generation = func() bool { return ready }, func() uint64 { return epoch }
				manager.reconcileOnce(t.Context())
				if manager.snapshot().Current != 0 || len(runner.calls) != 0 {
					t.Fatal("not-ready dataplane installed inline registration")
				}
			}
			if got := server.drain(1); len(got) != 0 {
				t.Fatalf("not-ready dataplane received %s", got[0])
			}
		})
	}
}
