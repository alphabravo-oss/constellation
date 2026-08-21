package main

// RT-SETUID-49 — setuid-without-exec (in-process privilege escalation) detection.
//
// realUIDEscalation (proc_enrich + runtime_detections) catches a process that gains
// root AT EXEC (a setuid binary / sudo): euid==0 while ruid!=0 on the exec event. It
// does NOT catch a long-running process that calls setuid(2)/setresuid(2) directly to
// escalate to root with no exec — the classic in-process privilege escalation
// NeuVector's rootEscalationCheck flags from its process monitor.
//
// Capturing the setuid(2) syscall itself would need a new BPF tracepoint. This is the
// best-effort userspace alternative the task calls for: periodically sample the
// effective UID of running container processes from /proc/<pid>/status and emit a
// uid_change event when a pid's effective UID escalated to root on the SAME process
// instance (matching /proc/<pid>/stat starttime, so pid reuse doesn't false-fire)
// WITHOUT an exec in the interval (an exec-driven escalation is already covered by
// realUIDEscalation and is excluded via the exec tracker).
//
// Default OFF (opt-in via CONSTELLATION_PROCESS_UID_MONITOR): a full /proc scan every
// interval is a per-node cost, and the signal is a refinement of the exec-time check.

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// uidSample is one observation of a pid's effective UID + an opaque process-instance
// id (the /proc stat starttime in clock ticks) used to detect pid reuse.
type uidSample struct {
	euid       uint32
	startTicks uint64
	comm       string
	container  string
}

// uidEscalation is a detected exec-less escalation of a pid's effective UID to root.
type uidEscalation struct {
	PID       uint32
	PrevUID   uint32
	UID       uint32
	Comm      string
	Container string
}

// detectSetuidEscalations compares two pid->sample snapshots and returns the pids
// whose effective UID escalated to root (0) from a non-root UID on the SAME process
// instance (matching startTicks). A new pid, or a reused pid (different startTicks),
// is never a match. Pure so it is unit-testable without a real /proc. Callers must
// additionally exclude pids that exec'd in the interval (exec-driven escalation).
func detectSetuidEscalations(prev, cur map[uint32]uidSample) []uidEscalation {
	out := make([]uidEscalation, 0)
	for pid, c := range cur {
		p, ok := prev[pid]
		if !ok || p.startTicks != c.startTicks {
			continue // new process or pid reuse -> not the same instance changing UID
		}
		if p.euid != 0 && c.euid == 0 {
			out = append(out, uidEscalation{
				PID:       pid,
				PrevUID:   p.euid,
				UID:       c.euid,
				Comm:      c.comm,
				Container: c.container,
			})
		}
	}
	return out
}

// execTracker records the last time each pid was seen exec'ing, so the UID monitor can
// exclude exec-driven UID changes (which realUIDEscalation already handles) from the
// exec-less setuid signal. Bounded by pruning pids not seen for a while.
type execTracker struct {
	mu   sync.Mutex
	last map[uint32]time.Time
}

func newExecTracker() *execTracker { return &execTracker{last: map[uint32]time.Time{}} }

// Record notes that pid exec'd at t. Safe on a nil receiver (monitor disabled).
func (e *execTracker) Record(pid uint32, t time.Time) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.last[pid] = t
	e.mu.Unlock()
}

// ExecedSince reports whether pid exec'd at or after `since`. A nil tracker reports
// false (no data -> don't suppress, but the monitor is disabled anyway).
func (e *execTracker) ExecedSince(pid uint32, since time.Time) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.last[pid]
	return ok && !t.Before(since)
}

// prune drops entries older than maxAge so the map does not grow unbounded.
func (e *execTracker) prune(maxAge time.Duration) {
	if e == nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	e.mu.Lock()
	for pid, t := range e.last {
		if t.Before(cutoff) {
			delete(e.last, pid)
		}
	}
	e.mu.Unlock()
}

type uidMonitorConfig struct {
	Disabled  bool
	Node      string
	Interval  time.Duration
	Exec      *execTracker
	Workloads *workloadResolver
	Logger    *slog.Logger
	// OnEscalation reports a detected exec-less UID escalation. main.go wires this to
	// the upload pipeline as a uid_change event.
	OnEscalation func(e uidEscalation, workloadID, namespace, pod string)
}

// uidMonitorLoop periodically samples container-process effective UIDs and reports
// exec-less escalations to root. It is a no-op when disabled.
func uidMonitorLoop(ctx context.Context, cfg uidMonitorConfig) {
	if cfg.Disabled {
		return
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	var prev map[uint32]uidSample
	lastSample := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur := sampleContainerUIDs(procRoot)
		if prev != nil {
			for _, esc := range detectSetuidEscalations(prev, cur) {
				// Exclude exec-driven escalation (covered by realUIDEscalation): if the
				// pid exec'd since the previous sample, its UID change is an exec, not a
				// bare setuid(2).
				if cfg.Exec.ExecedSince(esc.PID, lastSample) {
					continue
				}
				ident := cfg.Workloads.Resolve(esc.Container)
				if cfg.OnEscalation != nil {
					cfg.OnEscalation(esc, ident.WorkloadID, ident.Namespace, ident.Pod)
				}
				cfg.Logger.Info("uid-monitor: exec-less privilege escalation",
					slog.Int("pid", int(esc.PID)), slog.String("comm", esc.Comm),
					slog.Uint64("prev_uid", uint64(esc.PrevUID)), slog.Uint64("uid", uint64(esc.UID)),
					slog.String("workload", ident.WorkloadID))
			}
		}
		prev = cur
		lastSample = time.Now()
		cfg.Exec.prune(10 * time.Minute)
	}
}

// sampleContainerUIDs reads the effective UID + start-ticks of every container process
// under procRootDir. Non-container (host) processes are skipped — a host root daemon
// legitimately runs as root and is out of scope for container privilege-escalation.
func sampleContainerUIDs(procRootDir string) map[uint32]uidSample {
	out := map[uint32]uidSample{}
	entries, err := os.ReadDir(procRootDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		cid := containerIDFromProcCgroup(procRootDir, int(pid))
		if cid == "" {
			continue // host process — out of scope
		}
		euid, ok := readEuid(procRootDir + "/" + e.Name() + "/status")
		if !ok {
			continue
		}
		out[pid] = uidSample{
			euid:       euid,
			startTicks: readStartTicks(procRootDir + "/" + e.Name() + "/stat"),
			comm:       strings.TrimSpace(procReadFile(procRootDir + "/" + e.Name() + "/comm")),
			container:  cid,
		}
	}
	return out
}

// readEuid parses the EFFECTIVE uid (second field of the "Uid:" line) from
// /proc/<pid>/status. (readRuid in proc_enrich.go reads the first/real field.)
func readEuid(statusPath string) (uint32, bool) {
	raw := procReadFile(statusPath)
	for _, line := range strings.Split(raw, "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			return 0, false
		}
		v, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(v), true
	}
	return 0, false
}

// readStartTicks parses the process start time (field 22, in clock ticks since boot)
// from /proc/<pid>/stat. It is used only as an opaque per-instance id to detect pid
// reuse (equality compare), so the raw tick value needs no conversion. Returns 0 when
// unparseable — two zero values compare equal, which is acceptable for the reuse guard.
func readStartTicks(statPath string) uint64 {
	raw := procReadFile(statPath)
	idx := strings.LastIndex(raw, ")")
	if idx < 0 || idx+1 >= len(raw) {
		return 0
	}
	fields := strings.Fields(raw[idx+1:])
	// After ')': fields[0]=state (stat field 3). starttime is stat field 22 => index 19.
	if len(fields) <= 19 {
		return 0
	}
	v, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func uidMonitorEnabledFromEnv(value string) bool {
	return procBoolFromEnv(value)
}
