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
// (responseActionWorker), mirroring the other runtime sync workers.
//
// Exact process actions use the isolated V2 queue and a durable execution journal.
// Kernel start identity and pidfd verification prevent selecting another process;
// legacy process requests are refused. The legacy poller still handles sessions.
// Actual deployed signal/termination proof remains RUN-1 acceptance work.
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
	Protected          *protectedSet
	Workloads          *workloadResolver
	Logger             *slog.Logger

	// Process handles and the conntrack executable are injectable in isolated tests.
	conntrackRun        func(context.Context, []string) ([]byte, error)
	openProcess         func(int) (responseProcessHandle, error)
	currentProcessStart func(uint32) (uint64, bool)
}

type responder struct {
	cfg responderConfig
}

func newResponder(cfg responderConfig) *responder {
	if cfg.openProcess == nil {
		cfg.openProcess = openResponseProcess
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	if cfg.conntrackRun == nil {
		cfg.conntrackRun = func(ctx context.Context, args []string) ([]byte, error) {
			return exec.CommandContext(ctx, "conntrack", args...).CombinedOutput()
		}
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
		res.Reason = "legacy process actions require exact V2 process identity"
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

// killProcessDecision is the pure guard for a kill_process action. It refuses:
//   - system pids (<= 1): never kill init or the kernel.
//   - missing requested or live comm: a bare pid is not a verified target.
//   - comm mismatch: the pid's live comm differs from the requested comm, which
//     means the pid was recycled — killing it would hit the wrong process.
//   - missing live container identity or mismatch when a container was requested.
//
// Failed /proc reads must never remove a requested identity constraint.
func killProcessDecision(a responseAction, procComm, procContainerID string) (bool, string) {
	if a.PID <= 1 {
		return false, "invalid pid"
	}
	wantComm := strings.TrimSpace(a.Comm)
	if wantComm == "" {
		return false, "missing target comm"
	}
	procComm = strings.TrimSpace(procComm)
	if procComm == "" {
		return false, "process comm unavailable"
	}
	if wantComm != procComm {
		return false, "comm mismatch"
	}
	if want := normalizeContainerID(a.ContainerID); want != "" {
		actual := normalizeContainerID(procContainerID)
		if actual == "" {
			return false, "process container unavailable"
		}
		if want != actual {
			return false, "container mismatch"
		}
	} else if strings.TrimSpace(a.ContainerID) != "" {
		return false, "invalid target container"
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
	out, err := r.cfg.conntrackRun(cctx, args)
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
// Both IPs, ports and the protocol must be explicit; omitting either port would
// delete multiple connections rather than the requested session.
func conntrackDeleteArgs(a responseAction) ([]string, string) {
	src := strings.TrimSpace(a.SrcIP)
	dst := strings.TrimSpace(a.DstIP)
	if net.ParseIP(src) == nil || net.ParseIP(dst) == nil {
		return nil, "invalid src/dst ip"
	}
	proto := strings.ToLower(strings.TrimSpace(a.Protocol))
	if proto != "tcp" && proto != "udp" {
		return nil, "unsupported protocol"
	}
	if a.SrcPort < 1 || a.SrcPort > 65535 || a.DstPort < 1 || a.DstPort > 65535 {
		return nil, "invalid src/dst port"
	}
	return []string{"-D", "-s", src, "-d", dst, "-p", proto,
		"--sport", strconv.Itoa(a.SrcPort), "--dport", strconv.Itoa(a.DstPort)}, ""
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
// This poller only runs when kill-process/kill-session is explicitly enabled
// (CONSTELLATION_RESPONSE_KILL_PROCESS/_SESSION, default off). The server queues
// response-rule kill actions through /runtime/response-actions:pending and this
// worker reports the outcome to /runtime/response-actions:result. Live delivery
// validation is tracked as RUN-1 in docs/NEUVECTOR-PARITY-PLAN.md.
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
