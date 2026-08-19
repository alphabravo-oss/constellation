// Discover → Monitor → Protect lifecycle (NeuVector-style policy elevation automation).
//
// Each workload tracks a Mode. The Manager observes flows over a configurable learn window
// and emits ElevationDecision when the policy is "stable enough" to elevate to the next
// mode. Stability rules (defaults; per-workload overrides via WorkloadConfig):
//
//   Discover → Monitor:  observed ≥ 7 days, no new (peer, port, proto) tuple in last 24h,
//                        observed flow count ≥ MinObservedFlows.
//   Monitor  → Protect:  observed ≥ 7 days in Monitor, zero out-of-policy alerts in last
//                        24h, customer has explicitly clicked "approve elevation" or
//                        AutoElevate is true on the workload's config.
//
// Why mirror NeuVector exactly: customers migrating from NeuVector get a familiar lifecycle;
// runbooks transfer verbatim; the spec calls for this (Runtime Enforcement Modes section).
package netpolicy

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Mode is the per-workload enforcement state.
type Mode string

const (
	ModeDiscover Mode = "discover" // learn-only; observe + record baseline; no alerts
	ModeMonitor  Mode = "monitor"  // observe + alert on out-of-baseline; never block
	ModeProtect  Mode = "protect"  // observe + alert + block
)

// AllModes is the elevation order.
var AllModes = []Mode{ModeDiscover, ModeMonitor, ModeProtect}

// WorkloadState captures the per-workload state the elevation engine needs.
type WorkloadState struct {
	Workload   string    // "namespace/name"
	Namespace  string
	Mode       Mode
	ModeSince  time.Time

	// AutoElevate: when true, the elevation manager automatically transitions
	// Discover→Monitor→Protect as criteria are met. When false, the manager emits
	// "ready-to-elevate" suggestions but waits for a human to click.
	AutoElevate bool

	// LearnWindow overrides the default 7-day learn window. 0 = use default.
	LearnWindow time.Duration

	// MinObservedFlows: how many distinct (peer, port, proto) tuples need to be seen
	// before Discover can elevate to Monitor. Prevents elevating a workload that's barely
	// running.
	MinObservedFlows int
}

// FlowsSummary is the manager's view of observed traffic + alerts for a workload over a
// time window. The caller supplies this from the network_flows + events tables.
type FlowsSummary struct {
	TotalFlows         int
	UniquePeers        int
	UniquePortProtocol int
	OutOfPolicyAlerts  int // out-of-policy / denied flows within the M2P window (continuous-clean signal)
	ThreatsInWindow    int // DPI threats attributed to the workload within the M2P window
	NewTuplesLast24h   int // tuples observed in last 24h that weren't seen before
	FirstObservation   time.Time
	LastObservation    time.Time
}

// Decision is the manager's verdict for a workload.
type Decision struct {
	Workload    string
	CurrentMode Mode
	TargetMode  Mode // "" if no change
	Reason      string
	AutoApplied bool // true when manager actually transitioned the workload
	EvaluatedAt time.Time
}

// Manager drives the elevation lifecycle. It's stateless across calls — caller stores the
// WorkloadState in the DB and passes it in each cycle.
//
// The two transition windows are independent and mirror NeuVector's ATMO
// (controller/atmo): a Discover→Monitor "complete" period that ACCUMULATES
// (elapsed learning time), and a Monitor→Protect period that requires CONTINUOUS
// cleanliness — any out-of-policy alert or DPI threat inside the window resets
// the clock (the worker enforces this by counting alerts/threats over exactly
// D2M/M2P). A window of 0 DISABLES that transition, exactly like NeuVector's
// ConfigureCompleteDuration(mover, 0).
type Manager struct {
	// D2MWindow is the Discover→Monitor complete period (NeuVector default 6h;
	// discover_complete). 0 disables auto discover→monitor.
	D2MWindow time.Duration
	// M2PWindow is the Monitor→Protect continuous-clean period (NeuVector default
	// 12h; monitor_complete). 0 disables auto monitor→protect.
	M2PWindow time.Duration
	// DefaultLearnWindow is a back-compat fallback used only when a per-workload
	// LearnWindow override is set; the D2M/M2P windows above are authoritative.
	DefaultLearnWindow time.Duration
	DefaultMinFlows    int
	Now                func() time.Time // injectable clock for tests
}

// NewManager returns a Manager with NeuVector-parity defaults: Discover→Monitor
// after 6h of learning, Monitor→Protect after 12h continuously clean, minimum 5
// distinct flow tuples before Discover can advance.
func NewManager() *Manager {
	return &Manager{
		D2MWindow:          6 * time.Hour,
		M2PWindow:          12 * time.Hour,
		DefaultLearnWindow: 7 * 24 * time.Hour,
		DefaultMinFlows:    5,
		Now:                time.Now,
	}
}

// Evaluate returns the Decision for a workload given its current state + observed flows.
// The decision either elevates the workload (when AutoElevate=true and criteria pass),
// suggests an elevation (when AutoElevate=false), or recommends staying in the current
// mode (when criteria don't pass).
func (m *Manager) Evaluate(state WorkloadState, summary FlowsSummary) Decision {
	now := m.now()
	d := Decision{Workload: state.Workload, CurrentMode: state.Mode, EvaluatedAt: now}

	minFlows := state.MinObservedFlows
	if minFlows == 0 {
		minFlows = m.DefaultMinFlows
	}
	// Per-workload LearnWindow override applies to whichever transition is active;
	// otherwise the mover-specific D2M/M2P windows are authoritative.
	d2mWindow, m2pWindow := m.D2MWindow, m.M2PWindow
	if state.LearnWindow > 0 {
		d2mWindow, m2pWindow = state.LearnWindow, state.LearnWindow
	}

	switch state.Mode {
	case ModeDiscover:
		// Discover→Monitor ACCUMULATES: advance once the workload has learned for
		// D2MWindow and has seen enough distinct traffic (NeuVector: 6h + group
		// has members). New tuples do NOT hold it back — discovering means
		// learning new tuples is expected.
		if d2mWindow <= 0 {
			d.Reason = "auto discover→monitor disabled (D2M window = 0)"
			return d
		}
		age := now.Sub(state.ModeSince)
		if age < d2mWindow {
			d.Reason = fmt.Sprintf("learning: %s of %s elapsed", age.Truncate(time.Minute), d2mWindow)
			return d
		}
		if summary.UniquePortProtocol < minFlows {
			d.Reason = fmt.Sprintf("traffic too sparse: %d distinct flows observed (need ≥ %d)", summary.UniquePortProtocol, minFlows)
			return d
		}
		d.TargetMode = ModeMonitor
		d.Reason = fmt.Sprintf("learned %s with %d distinct flows; ready to monitor", d2mWindow, summary.UniquePortProtocol)
		d.AutoApplied = state.AutoElevate
		return d

	case ModeMonitor:
		// Monitor→Protect requires CONTINUOUS cleanliness for M2PWindow: zero
		// out-of-policy alerts AND zero DPI threats within the window. The worker
		// computes those counts over exactly M2PWindow, so any violation inside
		// the window fails the gate — matching NeuVector's reset-on-activity.
		if m2pWindow <= 0 {
			d.Reason = "auto monitor→protect disabled (M2P window = 0)"
			return d
		}
		age := now.Sub(state.ModeSince)
		if age < m2pWindow {
			d.Reason = fmt.Sprintf("monitoring: %s of %s clean elapsed", age.Truncate(time.Minute), m2pWindow)
			return d
		}
		if bad := summary.OutOfPolicyAlerts + summary.ThreatsInWindow; bad > 0 {
			d.Reason = fmt.Sprintf("not clean: %d alerts + %d threats within the last %s; clock resets until quiet", summary.OutOfPolicyAlerts, summary.ThreatsInWindow, m2pWindow)
			return d
		}
		d.TargetMode = ModeProtect
		d.Reason = fmt.Sprintf("clean for %s (no alerts or threats); ready to enforce", m2pWindow)
		d.AutoApplied = state.AutoElevate
		return d

	case ModeProtect:
		d.Reason = "already in protect mode"
		return d
	}
	d.Reason = "unknown mode"
	return d
}

// Elevate applies the manager's decision to the WorkloadState — used when AutoElevate is
// true. Returns the new state. The caller persists it.
func Elevate(state WorkloadState, d Decision) (WorkloadState, error) {
	if d.TargetMode == "" {
		return state, errors.New("netpolicy: decision has no target mode")
	}
	if !isValidTransition(state.Mode, d.TargetMode) {
		return state, fmt.Errorf("netpolicy: invalid transition %s → %s", state.Mode, d.TargetMode)
	}
	state.Mode = d.TargetMode
	state.ModeSince = d.EvaluatedAt
	return state, nil
}

// Demote moves a workload back one mode (Protect → Monitor → Discover). Used when an
// admin sees enforcement-side breakage and rolls back.
func Demote(state WorkloadState, reason string) (WorkloadState, error) {
	switch state.Mode {
	case ModeProtect:
		state.Mode = ModeMonitor
	case ModeMonitor:
		state.Mode = ModeDiscover
	case ModeDiscover:
		return state, errors.New("netpolicy: already at discover; cannot demote further")
	default:
		return state, fmt.Errorf("netpolicy: unknown mode %q", state.Mode)
	}
	state.ModeSince = time.Now().UTC()
	_ = reason // reason is logged by caller via audit log
	return state, nil
}

func isValidTransition(from, to Mode) bool {
	allowed := map[Mode]Mode{
		ModeDiscover: ModeMonitor,
		ModeMonitor:  ModeProtect,
	}
	return allowed[from] == to
}

// Sort returns workload decisions sorted by namespace + name (stable UI output).
func Sort(in []Decision) []Decision {
	out := append([]Decision(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Workload < out[j].Workload })
	return out
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}
