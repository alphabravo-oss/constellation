package main

import (
	"log/slog"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
)

// Agent-side process enforcer (kill-on-exec). For each observed exec, if the
// workload is in enforce mode with a non-empty learned baseline and the exec's
// basename is not in that baseline, SIGKILL it. Mirrors NeuVector's
// agent/probe/process_linux.go (syscall.Kill under PolicyActionDeny). This is
// kill-AFTER-start (post-exec), identical to NeuVector's netlink window — honest
// parity, not a pre-exec block (the pre-exec FAN_OPEN_EXEC_PERM deny lives in
// file_profile_enforcer_linux.go, P0-3).
//
// Default OFF (opt-in via CONSTELLATION_PROCESS_ENFORCER) because killing real
// processes is destructive; the server records the block decision regardless.
//
// Two granularity gaps are layered on, both default-off:
//   - P0-2 CONSTELLATION_PROCESS_MATCH_GRANULAR: match on full path + sha256 +
//     parent + uid via the rich processProfileEntry matcher instead of the bare
//     basename. With today's basename-only bundle it bridges to allow-by-basename
//     (no behavior change); it bites once the server emits rich entries.
//   - P0-4 CONSTELLATION_PROCESS_ZERO_DRIFT=monitor|enforce: flag/kill an exec
//     whose binary drifted from the image or whose lineage is not anchored to the
//     container root, regardless of name. Needs the container start time, so it is
//     dormant unless cfg.Workloads is wired.

type processEnforcerConfig struct {
	Disabled bool
	Sync     *ProcessBaselineSyncWorker
	Status   *processEnforcementStatusStore
	Logger   *slog.Logger
	// OnKill reports a killed exec. reason is the block cause ("zero-drift:image-drift"
	// | "zero-drift:unanchored" | "baseline") so the server records WHY the process was
	// killed, mirroring the reason OnAlert carries for monitor-mode observations.
	OnKill func(pid int, workloadID, containerID, comm, filename, reason string)

	// Workloads resolves a container ID to its identity, including the container
	// start time the zero-drift provenance proxy needs. Optional: when nil, the
	// zero-drift path stays dormant (fail-open). main.go wires this to the shared
	// workloadResolver, so CONSTELLATION_PROCESS_ZERO_DRIFT is live in production.
	Workloads *workloadResolver

	// Protected is the non-overridable self/host/system guard. When a process's
	// container is in a protected namespace (or it's a host process), the enforcer
	// never kills it — Constellation's own components and the node are sacrosanct.
	// Optional: a nil guard still protects the host (see protectedSet.protects).
	Protected *protectedSet

	// Granular / ZeroDrift override the env defaults (mainly for tests). Empty/false
	// falls back to the CONSTELLATION_* env flags.
	Granular  bool
	ZeroDrift string // "" | "off" | "monitor" | "enforce"

	// OnAlert records a monitor-mode (non-killing) zero-drift observation. Optional.
	OnAlert func(pid int, workloadID, containerID, comm, filename, reason string)
}

type processEnforcer struct {
	cfg       processEnforcerConfig
	granular  bool
	zeroDrift string // off|monitor|enforce
}

func newProcessEnforcer(cfg processEnforcerConfig) *processEnforcer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	e := &processEnforcer{cfg: cfg}
	e.granular = cfg.Granular || processMatchGranularFromEnv(os.Getenv("CONSTELLATION_PROCESS_MATCH_GRANULAR"))
	e.zeroDrift = normalizeZeroDriftMode(firstNonEmpty(cfg.ZeroDrift, os.Getenv("CONSTELLATION_PROCESS_ZERO_DRIFT")))
	return e
}

// namespaceForContainer resolves a container ID to its Kubernetes namespace via the
// shared workload resolver, for the protected-set check. Empty for host processes
// (protects() treats those as protected regardless) or when the resolver is unwired.
func (e *processEnforcer) namespaceForContainer(containerID string) string {
	if strings.TrimSpace(containerID) == "" || e.cfg.Workloads == nil {
		return ""
	}
	return e.cfg.Workloads.Resolve(containerID).Namespace
}

// onExec decides and enforces for a single exec. Safe on a nil receiver or a
// disabled config (no-op), so the event loop can call it unconditionally.
func (e *processEnforcer) onExec(pid int, containerID, comm, filename, workloadID string) {
	if e == nil || e.cfg.Disabled || e.cfg.Sync == nil {
		return
	}
	// Non-overridable self/host/system protection (checked BEFORE any rule): never
	// kill a process on the host or in the platform's own / a system namespace.
	// Mirrors NeuVector's capBlock exemption — those targets can't enter block mode.
	if e.cfg.Protected.protects(containerID, e.namespaceForContainer(containerID)) {
		return
	}
	wl := strings.TrimSpace(workloadID)

	// P0-4 zero-drift, evaluated first so a drift is reported even when the baseline
	// would allow the (renamed) binary. Monitor mode alerts without killing.
	if drift, reason := e.driftViolation(pid, containerID, wl); drift {
		if e.zeroDrift == "enforce" {
			e.block(pid, containerID, comm, filename, wl, "zero-drift:"+reason)
			return
		}
		// monitor: alert only, then fall through to the baseline decision.
		if e.cfg.OnAlert != nil {
			e.cfg.OnAlert(pid, wl, containerID, comm, filename, "zero-drift:"+reason)
		}
		e.cfg.Logger.Info("process-enforcer: zero-drift observed (monitor)",
			slog.Int("pid", pid), slog.String("comm", comm),
			slog.String("filename", filename), slog.String("workload", wl),
			slog.String("reason", reason))
	}

	// P0-1/P0-2 baseline kill decision.
	if e.baselineViolation(pid, comm, filename, wl) {
		e.block(pid, containerID, comm, filename, wl, "baseline")
	}
}

// block performs the SIGKILL + status/callback bookkeeping shared by the baseline
// and zero-drift enforce paths.
func (e *processEnforcer) block(pid int, containerID, comm, filename, wl, cause string) {
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		e.cfg.Logger.Warn("process-enforcer: kill failed",
			slog.Int("pid", pid), slog.String("comm", comm), slog.String("err", err.Error()))
		return
	}
	if e.cfg.Status != nil {
		e.cfg.Status.Replace(wl, processEnforcementStatus{Protect: true, State: "enforced"})
	}
	e.cfg.Logger.Info("process-enforcer: killed out-of-policy exec",
		slog.Int("pid", pid), slog.String("comm", comm),
		slog.String("filename", filename), slog.String("workload", wl),
		slog.String("cause", cause))
	if e.cfg.OnKill != nil {
		e.cfg.OnKill(pid, wl, containerID, comm, filename, cause)
	}
}

// baselineViolation is the enforce-mode allowlist decision. In granular mode it uses
// the rich processProfileEntry matcher; otherwise the legacy basename matcher.
func (e *processEnforcer) baselineViolation(pid int, comm, filename, wl string) bool {
	rows := e.cfg.Sync.Rows()
	if !e.granular {
		return processEnforceShouldKill(rows, wl, comm, filename)
	}
	if wl == "" {
		return false
	}
	row, ok := lookupProcessBaselineRow(rows, wl)
	if !ok || row.Mode != "enforce" || (len(row.Processes) == 0 && len(row.Entries) == 0) {
		return false
	}
	// RT-MATCH-16: the server bundle now emits rich Entries (full path + sha256 +
	// parent + action) built from learned observations and authored rules, so a
	// binary renamed/relocated to an allowed basename is rejected on the path key.
	// A row without Entries (older server, or a process with no absolute path) falls
	// back to allow-by-basename — bug-for-bug identical to the legacy matcher.
	entries := entriesFromBundle(row.Entries)
	if len(entries) == 0 {
		entries = bridgeBasenameEntries(row.Processes)
	}
	return !processProfileAllows(entries, e.execContext(pid, comm, filename))
}

// execContext builds the enriched matcher input from /proc. The sha256 is only read
// in granular mode (it is the only consumer today).
func (e *processEnforcer) execContext(pid int, comm, filename string) processExecContext {
	meta := enrichExecMeta(uint32(pid))
	if e.granular {
		meta = meta.withHash(uint32(pid))
	}
	exe := meta.ExePath
	if strings.TrimSpace(exe) == "" {
		exe = filename // fall back to the eBPF filename if /proc/<pid>/exe is gone
	}
	return processExecContext{
		Comm:       comm,
		ExePath:    exe,
		Sha256:     meta.Sha256,
		ParentName: meta.ParentComm,
	}
}

// driftViolation evaluates the P0-4 zero-drift invariant for a container exec. It is
// dormant unless a mode is set AND cfg.Workloads is wired (so a container start time
// is available). Returns (drift, reason). Fail-open on unknown start time.
func (e *processEnforcer) driftViolation(pid int, containerID, wl string) (bool, string) {
	if e.zeroDrift == "" || e.zeroDrift == "off" || e.cfg.Workloads == nil {
		return false, ""
	}
	cid := normalizeContainerID(containerID)
	if cid == "" {
		return false, ""
	}
	ident := e.cfg.Workloads.Resolve(cid)
	if ident.StartUnixNano == 0 {
		return false, "" // unknown start -> cannot judge provenance, fail open
	}
	z := zeroDriftContextFromProc(procRoot, uint32(pid), cid, ident.StartUnixNano)
	if !execIsDrift(z) {
		return false, ""
	}
	if !z.Anchored {
		return true, "unanchored"
	}
	return true, "image-drift"
}

// processEnforceShouldKill is the pure legacy kill decision: true iff the workload is
// in enforce mode with a non-empty baseline and the exec's basename is not in it.
// Pure so it's testable without spawning/killing real processes.
func processEnforceShouldKill(rows []processBaselineRowWire, workloadID, comm, filename string) bool {
	if strings.TrimSpace(workloadID) == "" {
		return false
	}
	row, ok := lookupProcessBaselineRow(rows, strings.TrimSpace(workloadID))
	if !ok || row.Mode != "enforce" || len(row.Processes) == 0 {
		return false // learn/monitor, no state, or not-yet-learned -> never kill
	}
	return !processBaselineAllows(row.Processes, comm, filename)
}

func lookupProcessBaselineRow(rows []processBaselineRowWire, workloadID string) (processBaselineRowWire, bool) {
	for _, row := range rows {
		if row.WorkloadID == workloadID || slices.Contains(row.PodWorkloadIDs, workloadID) {
			return row, true
		}
	}
	return processBaselineRowWire{}, false
}

// processBaselineAllows returns true if EITHER the executable basename or the
// comm is in the baseline set. Allow-if-any-candidate-matches is the safe
// direction for a kill path (the server keys the set on both forms).
func processBaselineAllows(set []string, comm, filename string) bool {
	if f := strings.TrimSpace(filename); f != "" && slices.Contains(set, path.Base(f)) {
		return true
	}
	if c := strings.TrimSpace(comm); c != "" && slices.Contains(set, c) {
		return true
	}
	return false
}

func processEnforcerEnabledFromEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false // default OFF — kill-on-exec is opt-in
	}
}

func processMatchGranularFromEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false // default OFF — granular matching is opt-in
	}
}

// normalizeZeroDriftMode maps the CONSTELLATION_PROCESS_ZERO_DRIFT env to one of
// off|monitor|enforce. Anything unrecognized (including "") is "off" — never block
// or alert by default.
func normalizeZeroDriftMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "observe", "alert":
		return "monitor"
	case "enforce", "block", "protect":
		return "enforce"
	default:
		return "off"
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
