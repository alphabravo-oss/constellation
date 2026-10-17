package main

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type processActionV2 struct {
	Version     int    `json:"protocol_version"`
	ID          string `json:"id"`
	ActionToken string `json:"action_token"`
	Type        string `json:"type"`
	Node        string `json:"node"`
	WorkloadID  string `json:"workload_id"`
	ContainerID string `json:"container_id"`
	PID         int    `json:"pid"`
	Comm        string `json:"comm"`
	BootID      string `json:"boot_id"`
	StartBootNS string `json:"start_boot_ns"`
	StartTicks  string `json:"process_start_ticks"`
}

type processResultV2 struct {
	Version     int       `json:"protocol_version"`
	ID          string    `json:"id"`
	ActionToken string    `json:"action_token"`
	Type        string    `json:"type"`
	Node        string    `json:"node"`
	Outcome     string    `json:"outcome"`
	Reason      string    `json:"reason"`
	At          time.Time `json:"at"`
}

type responseProcessHandle interface {
	Signal() error
	Close() error
}

func readResponseProcFile(directory, name string) ([]byte, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(name)
}

func readResponseStartTicks(root string, pid int) (string, error) {
	raw, err := readResponseProcFile(root, filepath.Join(strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	last := strings.LastIndexByte(string(raw), ')')
	if last < 0 {
		return "", errors.New("invalid process stat")
	}
	fields := strings.Fields(string(raw[last+1:]))
	if len(fields) <= 19 {
		return "", errors.New("incomplete process stat")
	}
	n, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil || n <= 0 {
		return "", errors.New("invalid process start ticks")
	}
	return strconv.FormatInt(n, 10), nil
}

// Linux exports /proc starttime in USER_HZ (100 on supported amd64/arm64),
// flooring task start_boottime nanoseconds to the same 10ms tick. Identity comes
// from the kernel event, never from a possibly-reused PID sampled afterwards.
func captureResponseProcessIdentity(root string, pid uint32, startBootNS uint64) (string, string) {
	if pid <= 1 || pid > math.MaxInt32 || startBootNS == 0 {
		return "", ""
	}
	expected := strconv.FormatUint(startBootNS/uint64(time.Second/100), 10)
	actual, err := readResponseStartTicks(root, int(pid))
	if err != nil || actual != expected {
		return "", ""
	}
	raw, err := readResponseProcFile(root, "sys/kernel/random/boot_id")
	if err != nil {
		return "", ""
	}
	boot, err := uuid.Parse(strings.TrimSpace(string(raw)))
	if err != nil || boot == uuid.Nil {
		return "", ""
	}
	return boot.String(), expected
}

func validateProcessAction(a processActionV2) error {
	if len(a.Node) > 253 || len(a.WorkloadID) > 4096 || len(a.ContainerID) > 256 || len(a.Comm) > 16 {
		return errors.New("process action identity exceeds size limit")
	}
	for _, raw := range []string{a.ID, a.ActionToken, a.BootID} {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw {
			return errors.New("invalid process action identity")
		}
	}
	start, nsErr := strconv.ParseUint(a.StartBootNS, 10, 64)
	ticks, err := strconv.ParseInt(a.StartTicks, 10, 64)
	if nsErr != nil || start == 0 || strconv.FormatUint(start, 10) != a.StartBootNS || strconv.FormatUint(start/uint64(time.Second/100), 10) != a.StartTicks || err != nil || ticks <= 0 || strconv.FormatInt(ticks, 10) != a.StartTicks || a.Version != 2 || a.Type != "kill_process" || a.PID <= 1 || a.PID > math.MaxInt32 || strings.TrimSpace(a.Node) == "" || strings.TrimSpace(a.WorkloadID) == "" || strings.TrimSpace(a.Comm) == "" {
		return errors.New("incomplete process action identity")
	}
	return nil
}

func (r *responder) ExecuteProcessV2(a processActionV2) processResultV2 {
	result := processResultV2{Version: 2, ID: a.ID, ActionToken: a.ActionToken, Type: a.Type, Node: r.cfg.Node, Outcome: "refused", At: time.Now().UTC()}
	result.Reason = r.signalProcessV2(a)
	if result.Reason == "" {
		result.Outcome = "applied"
	}
	return result
}

func (r *responder) signalProcessV2(a processActionV2) string {
	if !r.cfg.KillProcessEnabled {
		return "disabled"
	}
	if err := validateProcessAction(a); err != nil {
		return err.Error()
	}
	if a.Node != r.cfg.Node {
		return "process action node mismatch"
	}
	if reason := r.processWorkloadGuard(a); reason != "" {
		return reason
	}
	root := responderProcRoot(r.cfg.HostRoot)
	raw, err := readResponseProcFile(root, "sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(raw)) != a.BootID {
		return "process boot identity unavailable or changed"
	}
	handle, err := r.cfg.openProcess(a.PID)
	if err != nil {
		return "process handle unavailable; no PID fallback"
	}
	defer func() { _ = handle.Close() }()
	if r.cfg.currentProcessStart == nil {
		return "kernel process identity unavailable or changed"
	}
	if a.PID <= 1 || a.PID > math.MaxInt32 {
		return "invalid process pid"
	}
	current, known := r.cfg.currentProcessStart(uint32(a.PID))
	if !known || strconv.FormatUint(current, 10) != a.StartBootNS {
		return "kernel process identity unavailable or changed"
	}
	ticks, err := readResponseStartTicks(root, a.PID)
	if err != nil || ticks != a.StartTicks {
		return "process start identity unavailable or changed"
	}
	legacy := responseAction{PID: a.PID, Comm: a.Comm, ContainerID: a.ContainerID}
	if ok, reason := killProcessDecision(legacy, readProcComm(root, a.PID), containerIDFromProcCgroup(root, a.PID)); !ok {
		return reason
	}
	if err := handle.Signal(); err != nil {
		return "process signal failed"
	}
	return ""
}

// Resolve only a full current container identity. Telemetry's prefix/node-local
// fallback is useful for capture, but cannot authorize a destructive action.
func (r *responder) processWorkloadGuard(a processActionV2) string {
	id := normalizeContainerID(a.ContainerID)
	if id == "" {
		return "protected host process"
	}
	if r.cfg.Workloads == nil || r.cfg.Protected == nil {
		return "process workload protection unavailable"
	}
	r.cfg.Workloads.mu.RLock()
	identity, known := r.cfg.Workloads.byID[id]
	r.cfg.Workloads.mu.RUnlock()
	if !known || identity.ContainerID != id || identity.Namespace == "" || identity.Pod == "" || identity.WorkloadID != a.WorkloadID {
		return "process workload identity unavailable or changed"
	}
	if r.cfg.Protected.protects(id, identity.Namespace) {
		return "protected workload process"
	}
	return ""
}
