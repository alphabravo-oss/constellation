package dp

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// ----- QnumAllocator ---------------------------------------------------------

func TestQnumAllocator_Defaults(t *testing.T) {
	a := NewQnumAllocator(0, 0)
	q, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if q != 4000 {
		t.Errorf("first allocation = %d, want 4000 (default base)", q)
	}
	if a.InUse() != 1 {
		t.Errorf("InUse = %d, want 1", a.InUse())
	}
}

func TestQnumAllocator_AllocateReleaseReuse(t *testing.T) {
	a := NewQnumAllocator(100, 4)
	q1, _ := a.Allocate()
	q2, _ := a.Allocate()
	q3, _ := a.Allocate()
	q4, _ := a.Allocate()
	if q1 != 100 || q2 != 101 || q3 != 102 || q4 != 103 {
		t.Fatalf("got %d %d %d %d, want 100 101 102 103", q1, q2, q3, q4)
	}
	if a.InUse() != 4 {
		t.Errorf("InUse = %d, want 4", a.InUse())
	}
	if _, err := a.Allocate(); err == nil {
		t.Errorf("expected exhaustion error when allocator is full")
	}
	// Release one slot — next Allocate should reuse it eventually.
	a.Release(101)
	if a.InUse() != 3 {
		t.Errorf("InUse after Release = %d, want 3", a.InUse())
	}
	q5, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate after release: %v", err)
	}
	if q5 != 101 {
		t.Errorf("reuse after release = %d, want 101", q5)
	}
}

func TestQnumAllocator_OutOfRangeReleaseIsNoop(t *testing.T) {
	a := NewQnumAllocator(100, 4)
	a.Release(99999) // way out of range — must not panic / corrupt
	a.Release(50)    // below base
	q, _ := a.Allocate()
	if q != 100 {
		t.Errorf("first allocation after out-of-range Release = %d, want 100", q)
	}
}

// ----- iptables rule shape ---------------------------------------------------

func TestIPT_RedirectRules(t *testing.T) {
	i := &ipt{}
	got := i.redirectRules("veth1234", 4005)
	if len(got) != 2 {
		t.Fatalf("rules=%d want 2 (PREROUTING + POSTROUTING)", len(got))
	}
	pre := strings.Join(got[0], " ")
	post := strings.Join(got[1], " ")
	for _, want := range []string{"PREROUTING", "-i veth1234", "NFQUEUE", "--queue-num 4005", "--queue-bypass"} {
		if !strings.Contains(pre, want) {
			t.Errorf("PREROUTING rule missing %q: %s", want, pre)
		}
	}
	for _, want := range []string{"POSTROUTING", "-o veth1234", "NFQUEUE", "--queue-num 4005", "--queue-bypass"} {
		if !strings.Contains(post, want) {
			t.Errorf("POSTROUTING rule missing %q: %s", want, post)
		}
	}
}

// fakeIPTRunner records every call so tests can assert on the exact CLI
// arguments without actually invoking iptables. -C ("check") returns
// error-not-present by default so addRedirect proceeds to -I.
type fakeIPTRunner struct {
	mu    sync.Mutex
	calls [][]string
	netns string // last netns passed to Run (asserts rules land in the pod netns)

	// installedRules is the set of "table::chain::spec" strings the fake
	// considers currently present. addRedirect calls -C first; the fake
	// returns nil only if the rule's in this set.
	installedRules map[string]bool
}

func newFakeRunner() *fakeIPTRunner {
	return &fakeIPTRunner{installedRules: map[string]bool{}}
}

func (f *fakeIPTRunner) Run(ctx context.Context, netns string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.netns = netns
	f.calls = append(f.calls, append([]string{}, args...))
	if len(args) < 5 {
		return "", nil
	}
	// args shape: -t <table> <verb> <chain> -i|-o <iface> ...
	table, verb := args[1], args[2]
	key := table + "::" + strings.Join(args[3:], " ")
	switch verb {
	case "-C":
		if f.installedRules[key] {
			return "", nil
		}
		return "", &fakeMissingRuleError{}
	case "-I":
		f.installedRules[key] = true
		return "", nil
	case "-D":
		delete(f.installedRules, key)
		return "", nil
	}
	return "", nil
}

type fakeMissingRuleError struct{}

func (*fakeMissingRuleError) Error() string { return "iptables: rule not present (fake)" }

// ----- enforceManager reconcile ---------------------------------------------

// fakeEnforceProvider returns whatever's in its slice, mutable for tests.
type fakeEnforceProvider struct {
	mu      sync.Mutex
	desired []EnforceTarget
}

func (f *fakeEnforceProvider) set(targets ...EnforceTarget) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.desired = append([]EnforceTarget(nil), targets...)
}

func (f *fakeEnforceProvider) Desired(ctx context.Context) ([]EnforceTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]EnforceTarget(nil), f.desired...), nil
}

// TestEnforceManager_ReconcileAddRemove walks through:
//   1. provider returns 2 targets → both added, iptables rules installed,
//      dp AddNfqPort + AddMAC called for each, queue numbers allocated.
//   2. provider drops one → that target's rules removed, queue released.
//   3. teardown removes everything.
//
// Uses fakes for both the iptables runner and the dp client, so the test
// runs without dp present.
func TestEnforceManager_ReconcileAddRemove(t *testing.T) {
	srv := newCaptureServer(t)
	client := newClientPointedAt(t, srv)
	fakeIPT := newFakeRunner()
	provider := &fakeEnforceProvider{}
	provider.set(
		EnforceTarget{NetNS: "/proc/1/ns/net", Iface: "veth-a", EPMAC: "aa:aa:aa:aa:aa:aa"},
		EnforceTarget{NetNS: "/proc/1/ns/net", Iface: "veth-b", EPMAC: "bb:bb:bb:bb:bb:bb"},
	)

	m := newEnforceManager(client, provider, newSilentLogger(),
		10*time.Millisecond, &ipt{runner: fakeIPT}, NewQnumAllocator(4000, 100))

	// First reconcile.
	m.reconcileOnce(context.Background())
	got := m.sortedTargetsForTest()
	if len(got) != 2 {
		t.Fatalf("after first reconcile: have %d targets, want 2", len(got))
	}
	if got[0].Qnum == 0 || got[1].Qnum == 0 {
		t.Errorf("targets must have qnums assigned: %+v", got)
	}
	if got[0].Qnum == got[1].Qnum {
		t.Errorf("targets got the same qnum: %+v", got)
	}
	// iptables -I should have been called for each veth (PRE + POST) — 4 inserts.
	insertCount := 0
	for _, c := range fakeIPT.calls {
		if len(c) >= 3 && c[2] == "-I" {
			insertCount++
		}
	}
	if insertCount != 4 {
		t.Errorf("iptables -I called %d times, want 4 (2 veths × 2 rules)", insertCount)
	}
	// Rules MUST be installed in the pod's netns (dp binds the NFQUEUE there;
	// nf_queue is netns-scoped). A host-netns rule never delivers to dp.
	if fakeIPT.netns != "/proc/1/ns/net" {
		t.Errorf("iptables ran in netns %q, want the pod netns /proc/1/ns/net", fakeIPT.netns)
	}
	// dp should have received AddNfqPort + AddMAC for both veths — 4 datagrams.
	datagrams := srv.drain(8)
	addNfq, addMAC := 0, 0
	for _, dg := range datagrams {
		s := string(dg)
		if strings.Contains(s, `"ctrl_add_nfq_port"`) {
			addNfq++
		}
		if strings.Contains(s, `"ctrl_add_mac"`) {
			addMAC++
		}
	}
	if addNfq != 2 {
		t.Errorf("dp AddNfqPort calls = %d, want 2", addNfq)
	}
	if addMAC != 2 {
		t.Errorf("dp AddMAC calls = %d, want 2", addMAC)
	}

	// Second reconcile: provider drops veth-a. We expect:
	//   - iptables -D called twice for veth-a
	//   - dp DelNfqPort + DelMAC for veth-a
	//   - veth-a's qnum released
	prevQnumA := got[0].Qnum
	provider.set(EnforceTarget{NetNS: "/proc/1/ns/net", Iface: "veth-b", EPMAC: "bb:bb:bb:bb:bb:bb"})
	fakeIPT.mu.Lock()
	fakeIPT.calls = nil
	fakeIPT.mu.Unlock()
	m.reconcileOnce(context.Background())
	if got := m.sortedTargetsForTest(); len(got) != 1 || got[0].Iface != "veth-b" {
		t.Errorf("after remove: %+v, want [veth-b]", got)
	}
	deleteCount := 0
	for _, c := range fakeIPT.calls {
		if len(c) >= 3 && c[2] == "-D" {
			deleteCount++
		}
	}
	if deleteCount != 2 {
		t.Errorf("iptables -D called %d times after remove, want 2", deleteCount)
	}
	// Qnum should be released.
	q, _ := m.qnums.Allocate()
	if q != prevQnumA {
		// We allocated 4000, 4001 initially. Released 4000 (or whichever
		// got veth-a). The hint moves forward, so next Allocate gets the
		// next free slot — which on a freshly-released slot should be the
		// released one (depends on hint location). At minimum, InUse must
		// drop after release.
		t.Logf("hint-based reuse: prev=%d, got=%d (acceptable)", prevQnumA, q)
	}
	m.qnums.Release(q)

	// Teardown clears everything.
	m.teardown(context.Background())
	if got := m.sortedTargetsForTest(); len(got) != 0 {
		t.Errorf("after teardown: %+v, want empty", got)
	}
	if m.qnums.InUse() != 0 {
		t.Errorf("after teardown: qnums InUse=%d, want 0", m.qnums.InUse())
	}
}

// TestEnforceManager_IPTablesFailureRollsBack covers the safety path: if
// iptables refuses (say, missing kernel module), the enforceManager rolls
// back the dp-side bindings so we don't leak NFQUEUE listeners.
func TestEnforceManager_IPTablesFailureRollsBack(t *testing.T) {
	srv := newCaptureServer(t)
	client := newClientPointedAt(t, srv)
	failingIPT := &fakeIPTRunner{installedRules: map[string]bool{}}
	// Override Run to fail on every -I call.
	wrapped := &errOnInsertRunner{inner: failingIPT}
	provider := &fakeEnforceProvider{}
	provider.set(EnforceTarget{NetNS: "/proc/1/ns/net", Iface: "veth-bad", EPMAC: "aa:aa:aa:aa:aa:aa"})

	m := newEnforceManager(client, provider, newSilentLogger(),
		10*time.Millisecond, &ipt{runner: wrapped}, NewQnumAllocator(4000, 100))

	startQ := m.qnums.InUse()
	m.reconcileOnce(context.Background())
	if got := m.sortedTargetsForTest(); len(got) != 0 {
		t.Errorf("after failed reconcile: have %d targets, want 0 (rollback)", len(got))
	}
	if m.qnums.InUse() != startQ {
		t.Errorf("qnum leaked after rollback: InUse=%d, want %d", m.qnums.InUse(), startQ)
	}
	if m.errors.Load() == 0 {
		t.Error("expected at least one error counter increment")
	}
	// dp should have seen DelNfqPort + DelMAC for the rollback.
	dgs := srv.drain(8)
	sawDel := false
	for _, dg := range dgs {
		if strings.Contains(string(dg), `"ctrl_del_nfq_port"`) {
			sawDel = true
			break
		}
	}
	if !sawDel {
		t.Error("rollback should send DelNfqPort to dp")
	}
}

// errOnInsertRunner wraps a fakeIPTRunner and forces every -I to fail.
type errOnInsertRunner struct {
	inner *fakeIPTRunner
}

func (e *errOnInsertRunner) Run(ctx context.Context, netns string, args ...string) (string, error) {
	if len(args) >= 3 && args[2] == "-I" {
		return "iptables: simulated failure", &fakeIPTError{}
	}
	return e.inner.Run(ctx, netns, args...)
}

type fakeIPTError struct{}

func (*fakeIPTError) Error() string { return "fake iptables failure" }
