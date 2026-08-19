// B4: kill-process / kill-session response actions.
//
// The agent can already QUARANTINE (isolate a workload's network) but cannot
// sever a single live process or network session. This adds two targeted
// response capabilities:
//
//   - kill_process: SIGKILL a specific pid, verified by comm and (when known)
//     the owning workload/container so a reused pid isn't killed by mistake.
//     Models NeuVector agent/probe/process_linux.go syscall.Kill under a deny.
//   - kill_session: drop a specific network 5-tuple by deleting its conntrack
//     entry, severing an in-flight connection without a broad quarantine.
//
// SAFETY: both are DEFAULT OFF and independently gated
// (CONSTELLATION_RESPONSE_KILL_PROCESS / CONSTELLATION_RESPONSE_KILL_SESSION).
// Killing live processes / connections is destructive, so nothing here runs
// unless an operator explicitly enables it. The decision layer is pure and
// unit-tested; the syscall/exec layer is a thin wrapper.
//
// Transport: the responder is driven by a pull-poller against the control plane
// (responseActionWorker), mirroring the other runtime sync workers. The server
// endpoint that emits pending actions is a separate subsystem — see
// TODO(matrix) on responseActionWorker.fetch.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// responseAction is one pending action fetched from the control plane.
type responseAction struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // "kill_process" | "kill_session"
	WorkloadID  string `json:"workload_id,omitempty"`
	ContainerID string `json:"container_id,omitempty"`

	// kill_process target.
	PID  int    `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`

	// kill_session 5-tuple.
	Protocol string `json:"protocol,omitempty"`
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
}

// responseActionResult is reported back after an action is attempted.
type responseActionResult struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"`
	Node    string    `json:"node,omitempty"`
	Applied bool      `json:"applied"`
	Reason  string    `json:"reason,omitempty"`
	At      time.Time `json:"at"`
}

type responderConfig struct {
	Node               string
	HostRoot           string
	KillProcessEnabled bool
	KillSessionEnabled bool
	Workloads          *workloadResolver
	Logger             *slog.Logger

	// conntrackBin / killFn are injection seams for tests. Empty/nil fall back to
	// the real "conntrack" binary and syscall.Kill.
	conntrackBin string
	killFn       func(pid int, sig syscall.Signal) error
}

type responder struct {
	cfg responderConfig
}

func newResponder(cfg responderConfig) *responder {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.killFn == nil {
		cfg.killFn = func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
	}
	if strings.TrimSpace(cfg.conntrackBin) == "" {
		cfg.conntrackBin = "conntrack"
	}
	return &responder{cfg: cfg}
}

// Execute dispatches one action and returns the result. Unknown or disabled
// action types are refused (Applied=false) rather than erroring, so the poller
// can always report a terminal outcome.
func (r *responder) Execute(ctx context.Context, a responseAction) responseActionResult {
	res := responseActionResult{ID: a.ID, Type: a.Type, Node: r.cfg.Node, At: time.Now().UTC()}
	switch strings.ToLower(strings.TrimSpace(a.Type)) {
	case "kill_process":
		if !r.cfg.KillProcessEnabled {
			res.Reason = "disabled"
			return res
		}
		applied, reason := r.killProcess(a)
		res.Applied, res.Reason = applied, reason
	case "kill_session":
		if !r.cfg.KillSessionEnabled {
			res.Reason = "disabled"
			return res
		}
		applied, reason := r.killSession(ctx, a)
		res.Applied, res.Reason = applied, reason
	default:
		res.Reason = "unknown action type"
	}
	if res.Applied {
		r.cfg.Logger.Info("responder: action applied",
			slog.String("type", res.Type), slog.String("id", res.ID))
	} else {
		r.cfg.Logger.Info("responder: action not applied",
			slog.String("type", res.Type), slog.String("id", res.ID),
			slog.String("reason", res.Reason))
	}
	return res
}

// killProcess verifies the target then SIGKILLs it.
func (r *responder) killProcess(a responseAction) (bool, string) {
	procRootDir := responderProcRoot(r.cfg.HostRoot)
	procComm := readProcComm(procRootDir, a.PID)
	procContainerID := containerIDFromProcCgroup(procRootDir, a.PID)
	if ok, reason := killProcessDecision(a, procComm, procContainerID); !ok {
		return false, reason
	}
	if err := r.cfg.killFn(a.PID, syscall.SIGKILL); err != nil {
		return false, "kill failed: " + err.Error()
	}
	r.cfg.Logger.Info("responder: killed process",
		slog.Int("pid", a.PID), slog.String("comm", procComm),
		slog.String("workload", a.WorkloadID))
	return true, ""
}

// killProcessDecision is the pure guard for a kill_process action. It refuses:
//   - system pids (<= 1): never kill init or the kernel.
//   - comm mismatch: the pid's live comm differs from the requested comm, which
//     means the pid was recycled — killing it would hit the wrong process.
//   - container mismatch: the pid is not in the requested container.
//
// When a verification input is empty (unknown) that check is skipped (fail-open
// on that dimension), but at least an in-range pid is always required.
func killProcessDecision(a responseAction, procComm, procContainerID string) (bool, string) {
	if a.PID <= 1 {
		return false, "invalid pid"
	}
	if want := strings.TrimSpace(a.Comm); want != "" && procComm != "" && want != procComm {
		return false, "comm mismatch"
	}
	if want := normalizeContainerID(a.ContainerID); want != "" && procContainerID != "" &&
		want != normalizeContainerID(procContainerID) {
		return false, "container mismatch"
	}
	return true, ""
}

// killSession severs a network 5-tuple by deleting its conntrack entry. This is
// the honest, kernel-backed way to drop a single in-flight connection without a
// broad quarantine: `conntrack -D` removes the tracked flow so subsequent packets
// have no state and the connection stalls/resets.
//
// TODO(matrix): a dp-native drop (push a transient deny for the 5-tuple over the
// dp policy socket) would sever the session even when conntrack is unavailable
// (e.g. a pure-XDP dataplane). conntrack-delete is the portable first cut.
func (r *responder) killSession(ctx context.Context, a responseAction) (bool, string) {
	args, reason := conntrackDeleteArgs(a)
	if args == nil {
		return false, reason
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, r.cfg.conntrackBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// conntrack exits non-zero when no matching flow exists; treat "0 flows
		// deleted" as not-applied rather than an error the operator must chase.
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return false, "conntrack: " + msg
	}
	r.cfg.Logger.Info("responder: dropped session",
		slog.String("src", a.SrcIP), slog.String("dst", a.DstIP),
		slog.String("proto", a.Protocol))
	return true, ""
}

// conntrackDeleteArgs builds the `conntrack -D ...` argument vector for a
// 5-tuple, or (nil, reason) when the tuple is too incomplete to target safely.
// Requiring both endpoints avoids a wildcard delete that would tear down every
// flow to a host.
func conntrackDeleteArgs(a responseAction) ([]string, string) {
	src := strings.TrimSpace(a.SrcIP)
	dst := strings.TrimSpace(a.DstIP)
	if net.ParseIP(src) == nil || net.ParseIP(dst) == nil {
		return nil, "invalid src/dst ip"
	}
	proto := strings.ToLower(strings.TrimSpace(a.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return nil, "unsupported protocol"
	}
	args := []string{"-D", "-s", src, "-d", dst, "-p", proto}
	if a.SrcPort > 0 {
		args = append(args, "--sport", strconv.Itoa(a.SrcPort))
	}
	if a.DstPort > 0 {
		args = append(args, "--dport", strconv.Itoa(a.DstPort))
	}
	return args, ""
}

func responderProcRoot(hostRoot string) string {
	if strings.TrimSpace(hostRoot) != "" {
		return filepath.Join(hostRoot, "proc")
	}
	return procRoot
}

func readProcComm(procRootDir string, pid int) string {
	if pid <= 0 {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(procRootDir, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// responseKillProcessEnabledFromEnv / responseKillSessionEnabledFromEnv default OFF.
func responseKillProcessEnabledFromEnv(value string) bool { return responseActionEnabled(value) }
func responseKillSessionEnabledFromEnv(value string) bool { return responseActionEnabled(value) }

func responseActionEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled", "enforce":
		return true
	default:
		return false
	}
}

// ----- pull-poller transport --------------------------------------------------

type responseActionWorker struct {
	APIBaseURL string
	Token      string
	ClusterID  string
	Node       string
	Interval   time.Duration
	Responder  *responder
	HTTPClient *http.Client
	Logger     *slog.Logger
}

func (w *responseActionWorker) Run(ctx context.Context) {
	if w.Logger == nil {
		w.Logger = slog.Default()
	}
	if w.HTTPClient == nil {
		w.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if w.Interval <= 0 {
		w.Interval = 15 * time.Second
	}
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.pollOnce(ctx)
			t.Reset(w.Interval)
		}
	}
}

func (w *responseActionWorker) pollOnce(ctx context.Context) {
	actions, err := w.fetch(ctx)
	if err != nil {
		// A missing endpoint (server subsystem not yet shipped) or transient error
		// is logged at debug so an opted-in agent doesn't spam warnings.
		w.Logger.Debug("responder: fetch failed", slog.String("err", err.Error()))
		return
	}
	for _, a := range actions {
		res := w.Responder.Execute(ctx, a)
		if err := w.report(ctx, res); err != nil {
			w.Logger.Debug("responder: report failed",
				slog.String("id", res.ID), slog.String("err", err.Error()))
		}
	}
}

// fetch pulls pending response actions for this node.
//
// NOTE (RT-KILL-02): this poller only runs when kill-process/kill-session is
// explicitly enabled (CONSTELLATION_RESPONSE_KILL_PROCESS/_SESSION, default off).
// The server-side producer endpoint (/api/v1/runtime/response-actions:pending)
// is NOT yet implemented, so an opted-in agent stays inert (empty on 404) rather
// than erroring. Pre-exec BLOCKING is instead delivered by the enforcer path
// (RT-ENFORCE-01: set runtimeAgent.enforcement.mode=protect). Building the full
// response-action kill pipeline (server producer + result sink + response-rule
// wiring) is tracked as RT-KILL-02 in docs/NEUVECTOR-PARITY-PLAN-2026-08.md.
func (w *responseActionWorker) fetch(ctx context.Context) ([]responseAction, error) {
	url := strings.TrimRight(w.APIBaseURL, "/") +
		"/api/v1/runtime/response-actions:pending?cluster_id=" + w.ClusterID +
		"&node=" + w.Node
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.Token)
	resp, err := w.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // endpoint not present yet — inert
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Actions []responseAction `json:"actions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Actions, nil
}

func (w *responseActionWorker) report(ctx context.Context, res responseActionResult) error {
	url := strings.TrimRight(w.APIBaseURL, "/") + "/api/v1/runtime/response-actions:result"
	body, err := json.Marshal(res)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+w.Token)
	resp, err := w.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server %d", resp.StatusCode)
	}
	return nil
}
