package netpolicy

import (
	"testing"
	"time"

	netpolicy "github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func TestNetpolicyApproval(t *testing.T) {
	// alerts present -> blocked regardless of target.
	if got := netpolicyApproval(netpolicy.Decision{TargetMode: netpolicy.ModeMonitor}, 3); got != "blocked" {
		t.Fatalf("alerts>0 should be blocked, got %s", got)
	}
	// ready to elevate, no alerts -> approved.
	if got := netpolicyApproval(netpolicy.Decision{TargetMode: netpolicy.ModeMonitor}, 0); got != "approved" {
		t.Fatalf("target set, no alerts should be approved, got %s", got)
	}
	// still learning (no target), no alerts -> pending.
	if got := netpolicyApproval(netpolicy.Decision{}, 0); got != "pending" {
		t.Fatalf("no target should be pending, got %s", got)
	}
}

func TestNetpolicyEnvOverrides(t *testing.T) {
	// Unset -> 0 (fall through to engine defaults).
	if w := netpolicyLearnWindowFromEnv(); w != 0 {
		t.Fatalf("unset window should be 0, got %v", w)
	}
	if n := netpolicyMinFlowsFromEnv(); n != 0 {
		t.Fatalf("unset min flows should be 0, got %d", n)
	}
	t.Setenv("CONSTELLATION_NETPOLICY_LEARN_WINDOW", "1s")
	t.Setenv("CONSTELLATION_NETPOLICY_MIN_FLOWS", "2")
	if w := netpolicyLearnWindowFromEnv(); w.String() != "1s" {
		t.Fatalf("expected 1s, got %v", w)
	}
	if n := netpolicyMinFlowsFromEnv(); n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}
	// With a 1s window, a workload observed >1s ago with no alerts and enough
	// flows promotes discover->monitor (proves the override unblocks fresh clusters).
	mgr := netpolicy.NewManager()
	d := mgr.Evaluate(
		netpolicy.WorkloadState{Workload: "ns/app", Mode: netpolicy.ModeDiscover,
			ModeSince:        time.Now().Add(-2 * time.Second),
			LearnWindow:      netpolicyLearnWindowFromEnv(),
			MinObservedFlows: netpolicyMinFlowsFromEnv()},
		netpolicy.FlowsSummary{TotalFlows: 10, UniquePortProtocol: 5, NewTuplesLast24h: 0},
	)
	if string(d.TargetMode) != "monitor" {
		t.Fatalf("short-window fresh workload should target monitor, got %q (%s)", d.TargetMode, d.Reason)
	}
}
