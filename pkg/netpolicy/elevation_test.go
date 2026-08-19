package netpolicy

import (
	"testing"
	"time"
)

func staticClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestEvaluate_DiscoverNotReadyDuringLearnWindow(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	m := NewManager()
	m.Now = staticClock(now)
	d := m.Evaluate(
		WorkloadState{Mode: ModeDiscover, ModeSince: now.Add(-1 * time.Hour)},
		FlowsSummary{UniquePortProtocol: 10},
	)
	if d.TargetMode != "" {
		t.Fatalf("should not elevate during learn window, got %+v", d)
	}
}

func TestEvaluate_DiscoverElevatesAfterWindowAndStable(t *testing.T) {
	now := time.Now()
	m := NewManager()
	m.Now = staticClock(now)

	d := m.Evaluate(
		WorkloadState{
			Mode: ModeDiscover, ModeSince: now.Add(-8 * 24 * time.Hour),
			AutoElevate: true,
		},
		FlowsSummary{UniquePortProtocol: 12, NewTuplesLast24h: 0, OutOfPolicyAlerts: 0},
	)
	if d.TargetMode != ModeMonitor {
		t.Fatalf("expected Discover→Monitor, got %+v", d)
	}
	if !d.AutoApplied {
		t.Fatalf("AutoElevate=true should set AutoApplied")
	}
}

func TestEvaluate_DiscoverHoldsBeforeD2MWindow(t *testing.T) {
	now := time.Now()
	m := NewManager() // D2M = 6h
	m.Now = staticClock(now)
	d := m.Evaluate(
		WorkloadState{Mode: ModeDiscover, ModeSince: now.Add(-5 * time.Hour), AutoElevate: true},
		FlowsSummary{UniquePortProtocol: 12},
	)
	if d.TargetMode != "" {
		t.Fatalf("should hold before the 6h D2M window: %+v", d)
	}
}

func TestEvaluate_DiscoverElevatesAfterD2MWindow(t *testing.T) {
	now := time.Now()
	m := NewManager()
	m.Now = staticClock(now)
	// Past 6h + enough traffic; new tuples do NOT hold discover back (learning).
	d := m.Evaluate(
		WorkloadState{Mode: ModeDiscover, ModeSince: now.Add(-7 * time.Hour), AutoElevate: true},
		FlowsSummary{UniquePortProtocol: 12, NewTuplesLast24h: 3},
	)
	if d.TargetMode != ModeMonitor {
		t.Fatalf("expected Discover→Monitor after 6h: %+v", d)
	}
}

func TestEvaluate_D2MDisabledWhenWindowZero(t *testing.T) {
	now := time.Now()
	m := NewManager()
	m.D2MWindow = 0 // disabled, like NeuVector ConfigureCompleteDuration(mover, 0)
	m.Now = staticClock(now)
	d := m.Evaluate(
		WorkloadState{Mode: ModeDiscover, ModeSince: now.Add(-30 * 24 * time.Hour), AutoElevate: true},
		FlowsSummary{UniquePortProtocol: 99},
	)
	if d.TargetMode != "" {
		t.Fatalf("D2M window 0 must disable auto discover→monitor: %+v", d)
	}
}

func TestEvaluate_MonitorHoldsWhenThreatInWindow(t *testing.T) {
	now := time.Now()
	m := NewManager() // M2P = 12h continuous-clean
	m.Now = staticClock(now)
	d := m.Evaluate(
		WorkloadState{Mode: ModeMonitor, ModeSince: now.Add(-24 * time.Hour), AutoElevate: true},
		FlowsSummary{OutOfPolicyAlerts: 0, ThreatsInWindow: 1}, // a threat resets the clean clock
	)
	if d.TargetMode != "" {
		t.Fatalf("a DPI threat inside the M2P window must hold protect: %+v", d)
	}
}

func TestEvaluate_M2PDisabledWhenWindowZero(t *testing.T) {
	now := time.Now()
	m := NewManager()
	m.M2PWindow = 0
	m.Now = staticClock(now)
	d := m.Evaluate(
		WorkloadState{Mode: ModeMonitor, ModeSince: now.Add(-30 * 24 * time.Hour), AutoElevate: true},
		FlowsSummary{OutOfPolicyAlerts: 0, ThreatsInWindow: 0},
	)
	if d.TargetMode != "" {
		t.Fatalf("M2P window 0 must disable auto monitor→protect: %+v", d)
	}
}

func TestEvaluate_MonitorHoldsWhenAlertsExist(t *testing.T) {
	now := time.Now()
	m := NewManager()
	m.Now = staticClock(now)
	d := m.Evaluate(
		WorkloadState{Mode: ModeMonitor, ModeSince: now.Add(-8 * 24 * time.Hour)},
		FlowsSummary{OutOfPolicyAlerts: 3},
	)
	if d.TargetMode != "" {
		t.Fatalf("alerts should hold elevation: %+v", d)
	}
}

func TestEvaluate_MonitorElevatesToProtect(t *testing.T) {
	now := time.Now()
	m := NewManager()
	m.Now = staticClock(now)
	d := m.Evaluate(
		WorkloadState{Mode: ModeMonitor, ModeSince: now.Add(-8 * 24 * time.Hour), AutoElevate: true},
		FlowsSummary{OutOfPolicyAlerts: 0},
	)
	if d.TargetMode != ModeProtect {
		t.Fatalf("expected Monitor→Protect, got %+v", d)
	}
}

func TestElevate_RejectsInvalidTransitions(t *testing.T) {
	_, err := Elevate(WorkloadState{Mode: ModeDiscover}, Decision{TargetMode: ModeProtect})
	if err == nil {
		t.Fatal("Discover→Protect should be rejected (must go through Monitor)")
	}
}

func TestDemote_StepsBackOne(t *testing.T) {
	s, err := Demote(WorkloadState{Mode: ModeProtect}, "ops rollback")
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode != ModeMonitor {
		t.Fatalf("Protect demotes to Monitor, got %s", s.Mode)
	}
	s, err = Demote(s, "still broken")
	if err != nil || s.Mode != ModeDiscover {
		t.Fatalf("Monitor demotes to Discover: mode=%s err=%v", s.Mode, err)
	}
	if _, err := Demote(s, "x"); err == nil {
		t.Fatal("Discover cannot demote further")
	}
}
