package dp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DefaultBinary is where the runtime image places the vendored NeuVector dp.
// Override via Options.Binary if you've installed it elsewhere.
const DefaultBinary = "/usr/local/bin/dp"

// DefaultCtrlSocket is the agent-side listener that dp posts notifications to.
// This path is hardcoded in dp itself (third_party/neuvector/dp/ctrl.c) — we
// cannot change it without forking the C source.
const DefaultCtrlSocket = "/tmp/ctrl_listen.sock"

// Options configures the Supervisor. Sensible zero-value defaults are filled in
// by Start so a caller can pass dp.Options{Logger: lg} and get a working setup.
//
// TapProvider, when non-nil, drives the per-interface AddTapPort / DelTapPort
// reconciler. Wave 3a ships envTapProvider (CONSTELLATION_DP_TAP_PORTS); Wave
// 3b will add a pod-veth provider that walks /sys/class/net + netlink.
type Options struct {
	Logger *slog.Logger

	// Binary is the absolute path to the dp executable. Empty → DefaultBinary.
	Binary string

	// Threads is dp's worker-thread count (passed as `-n N`). NeuVector's
	// monitor hardcodes 1. Empty / zero → 1.
	Threads int

	// TapInterface, when non-empty, switches dp into per-interface AF_PACKET
	// TAP mode (passed as `-i IFACE`). Empty → NFQUEUE mode (default), which
	// requires the agent to install TC redirects per veth (Wave 3 work).
	TapInterface string

	// NoTC disables TC kernel-module use and forces AF_PACKET ringbuffer
	// fallback (passed as `-c`). Set on kernels without act_mirred/act_pedit.
	NoTC bool

	// CtrlSocket overrides DefaultCtrlSocket. Almost never needed.
	CtrlSocket string

	// RestartBackoff is the minimum delay between dp exits and restart attempts.
	// Empty → 1s. A 10x exponential backoff is applied up to 30s after
	// consecutive failures.
	RestartBackoff time.Duration

	// EventBuffer sizes the channel returned by Events(). Empty → 4096.
	EventBuffer int

	// TapProvider sources the desired list of interfaces dp should tap.
	// Nil → no taps are installed (dp will idle until something asks it to
	// inspect an interface).
	TapProvider TapProvider

	// TapReconcileInterval is how often we re-query the provider and reconcile.
	// Empty → 10s.
	TapReconcileInterval time.Duration

	// EnforceProvider — Wave A3. When non-nil, the supervisor runs a
	// parallel reconciler that installs NFQUEUE iptables rules + dp's
	// inline-mode bindings for every workload the provider returns.
	// Independent of TapProvider; both can run simultaneously (a
	// workload in monitor mode goes through TapProvider, in enforce
	// mode goes through EnforceProvider).
	EnforceProvider EnforceProvider

	// QnumBase / QnumCapacity — Wave A3. NFQUEUE number range. Zero
	// values use the defaults from NewQnumAllocator.
	QnumBase     int
	QnumCapacity int

	// SessionPollInterval — Wave C1. How often to request a full session
	// list from dp for the per-direction byte split. 0 disables polling
	// (the agent falls back to "all in client_bytes" on every flow).
	// Empty → 30s, a reasonable cadence on a busy node.
	SessionPollInterval time.Duration

	// FqdnExpireInterval — F1b. How often the supervisor ages out (Expire)
	// learned FQDN→IP mappings and reconciles the result into dp. Empty → 30s.
	FqdnExpireInterval time.Duration
}

// Supervisor forks and watches dp, owns the IPC server + request client,
// and exposes a typed Event channel to consumers.
type Supervisor struct {
	opt    Options
	logger *slog.Logger

	events   chan Event
	ipc      *ipcServer
	client   *dpClient
	taps     *tapManager
	enforce  *enforceManager
	sessions *SessionCache

	// fqdn resolves FQDN-anchored egress rules to live IP sets (F1b). It is
	// fed by FeedDNS, aged by a periodic Expire loop, and reconciled into dp
	// via ctrl_cfg_set_fqdn. fqdnPushed is the last set programmed per name so
	// reconcile only sends real changes.
	fqdn       *FqdnResolver
	fqdnMu     sync.Mutex
	fqdnPushed map[string][]net.IP

	mu     sync.Mutex
	cmd    *exec.Cmd
	stopCh chan struct{}

	// State counters surfaced via Stats(). dp lifecycle counters; the
	// IPC byte counters live on ipcServer and are merged in Stats().
	startCount uint64
	exitCount  uint64
	crashCount uint64

	// generation mirrors startCount as a lock-free atomic so consumers can
	// detect a dp restart without taking s.mu. Bumped in runOnce inside the
	// same s.mu block that increments startCount.
	generation atomic.Uint64

	// readyGen is the generation whose dp instance has answered at least one
	// keepalive. Set (lock-free) on every successful keepalive reply via the
	// client's onReply hook. Ready() compares it against generation: a restart
	// bumps generation and leaves Ready() false until the fresh dp replies.
	readyGen atomic.Uint64
}

// New returns a configured Supervisor. Start runs it.
//
// IMPORTANT: the events channel is allocated here, not in Start. Callers
// typically do `events := sup.Events()` before launching Start in a
// goroutine, and a nil channel from a not-yet-started Supervisor would
// silently swallow every event. Allocating early avoids that race.
func New(opt Options) *Supervisor {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Binary == "" {
		opt.Binary = DefaultBinary
	}
	if opt.CtrlSocket == "" {
		opt.CtrlSocket = DefaultCtrlSocket
	}
	if opt.Threads <= 0 {
		opt.Threads = 1
	}
	if opt.RestartBackoff <= 0 {
		opt.RestartBackoff = time.Second
	}
	if opt.EventBuffer <= 0 {
		opt.EventBuffer = 4096
	}
	return &Supervisor{
		opt:        opt,
		logger:     opt.Logger.With(slog.String("subsystem", "dp")),
		events:     make(chan Event, opt.EventBuffer),
		sessions:   NewSessionCache(),
		fqdn:       NewFqdnResolver(),
		fqdnPushed: map[string][]net.IP{},
	}
}

// Sessions returns the supervisor's session cache. The agent's flow
// emitter (cmd/constellation-runtime-agent/dp_flow.go) calls Lookup on
// this to fill in client_bytes/server_bytes when a Connection event has
// a matching session. Wave C1.
func (s *Supervisor) Sessions() *SessionCache { return s.sessions }

// ClearSession asks dp to terminate one live session by its dp id (NV session-kill).
func (s *Supervisor) ClearSession(id uint32) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp: supervisor not started")
	}
	return s.client.ClearSession(id)
}

// SetWeakTLSDetection enables/disables the weak-TLS version signatures (SSLv3, TLS 1.0,
// TLS 1.1) at runtime. Off by default (noisy false positives in tap mode); the console can
// turn it on when genuine legacy-TLS detection is wanted.
func (s *Supervisor) SetWeakTLSDetection(enable bool) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp: supervisor not started")
	}
	for _, idx := range []uint32{ThreatSSLv3, ThreatTLS10, ThreatTLS11} {
		if err := s.client.SetThreatStatus(idx, enable); err != nil {
			return err
		}
	}
	return nil
}

// TapMACs returns the EPMAC of every interface dp is currently inspecting.
// Wave C4.5: the DLP sync worker uses this to scope BuildDLPRules pushes
// to the workloads on this node. Returns nil before the supervisor has
// started its tap manager.
func (s *Supervisor) TapMACs() []string {
	if s == nil || s.taps == nil {
		return nil
	}
	return s.taps.currentMACs()
}

// DPIScopeMACs returns the tapped EPMACs opted into WAF and into DLP (from pod
// labels). DPI is OFF by default; only opted-in workloads are bound, mirroring
// NeuVector's per-group waf_group/dlp_group model. Empty maps before the tap
// manager has started. See tapManager.dpiScopeMACs.
func (s *Supervisor) DPIScopeMACs() (wafMACs, dlpMACs map[string]bool) {
	if s == nil || s.taps == nil {
		return nil, nil
	}
	return s.taps.dpiScopeMACs()
}

// EnforceDPIScopeMACs returns the inline NFQUEUE enforce-mode ep MACs opted into
// WAF and into DLP respectively (the verdict-capable datapath), the enforce-path
// analogue of DPIScopeMACs's tap MACs. The DLP/WAF sync worker unions these into
// its opt-in sets so opted workloads' detectors bind to the veth NFQUEUE rather
// than a verdict-less mirror copy, letting drop/reset actually fire. Empty maps
// before the enforce manager starts — the EnforceProvider is unset or the inline
// path is CNI-gated off (see main.go).
func (s *Supervisor) EnforceDPIScopeMACs() (wafMACs, dlpMACs map[string]bool) {
	if s == nil || s.enforce == nil {
		return nil, nil
	}
	return s.enforce.enforceDPIScopeMACs()
}

// Generation returns the current dp lifecycle generation: it equals the number
// of times dp has been (re)started and is bumped atomically each time a new dp
// instance is launched. Consumers compare it against a cached value to detect a
// restart and force a config re-push. Lock-free.
func (s *Supervisor) Generation() uint64 {
	return s.generation.Load()
}

// Ready reports whether the CURRENT dp instance has answered at least one
// keepalive. After a restart, Generation bumps and Ready is false until the
// fresh dp replies to a keepalive. Config pushers gate on this to avoid the
// startup race where a push lands before dp finishes initializing. Lock-free.
func (s *Supervisor) Ready() bool {
	gen := s.generation.Load()
	return gen > 0 && s.readyGen.Load() == gen
}

// Events returns the channel emitting decoded notifications from dp. The
// channel is created by Start and stays open until Start returns; consumers
// should range over it (or select with ctx.Done()).
func (s *Supervisor) Events() <-chan Event {
	return s.events
}

// Start the supervisor. Returns when ctx is canceled (graceful) or when an
// unrecoverable setup error occurs (eg. missing dp binary). The dp subprocess
// is killed cleanly on ctx cancel.
//
// While running, Start performs two jobs concurrently:
//  1. Listens on the unixgram control socket; decodes inbound notifications.
//  2. Spawns dp, captures stderr/stdout to the logger, restarts on exit
//     with exponential backoff capped at 30s.
func (s *Supervisor) Start(ctx context.Context) error {
	if _, err := os.Stat(s.opt.Binary); err != nil {
		return fmt.Errorf("dp supervisor: binary not found at %s: %w", s.opt.Binary, err)
	}
	defer close(s.events)

	// dp opens a POSIX shm segment without O_CREAT; we must create it first
	// (NeuVector's monitor does this — see third_party/neuvector/monitor/monitor.c:1139).
	if err := ensureSharedMemory(); err != nil {
		return fmt.Errorf("dp supervisor: %w", err)
	}
	defer removeSharedMemory()

	// IPC server first so the socket exists by the time dp tries to connect.
	s.ipc = newIPCServer(s.opt.CtrlSocket, s.logger, s.events)
	if err := s.ipc.listen(); err != nil {
		return err
	}

	// Keepalive client — dp doesn't emit unprompted; the agent has to poke
	// it via ctrl_keep_alive JSON every 2s. Without this, even a perfectly
	// healthy dp will look silent. See third_party/neuvector/dp/ctrl.c:141.
	s.client = newDPClient(s.logger)
	// Readiness hook: every successful keepalive reply advances readyGen to the
	// current generation. Set before keepAliveLoop is launched below, so the
	// hot path only ever reads an immutable func pointer (no mutex, no race).
	s.client.onReply = func() { s.readyGen.Store(s.generation.Load()) }
	// Session dumps arrive on the request socket (dp sends them to g_client_addr,
	// not the notification socket), so the keepalive reader demuxes them and hands
	// each complete snapshot here → the live-session cache.
	s.client.onSessionDump = func(sessions []*Session) { s.sessions.Replace(sessions) }

	// Tap manager — Wave 3a. Drives dp's per-interface AF_PACKET state
	// from the configured provider. Optional: if the caller didn't supply
	// one, dp idles (useful for testing the IPC plumbing without committing
	// to which interfaces to watch).
	if s.opt.TapProvider != nil {
		s.taps = newTapManager(s.client, s.opt.TapProvider, s.logger, s.opt.TapReconcileInterval)
	}
	// Enforce manager — Wave A3. Same shape as the tap manager but for the
	// NFQUEUE inline path. Allocates its own QnumAllocator + iptables runner.
	if s.opt.EnforceProvider != nil {
		qnums := NewQnumAllocator(s.opt.QnumBase, s.opt.QnumCapacity)
		s.enforce = newEnforceManager(s.client, s.opt.EnforceProvider, s.logger,
			s.opt.TapReconcileInterval, newIPT(), qnums)
	}
	// Let the tap reconciler defer to the enforce path: a MAC that is an active
	// inline enforce target must never be tapped (that would send tap=true and
	// clobber the ep->tap=false the NFQUEUE verdict needs). Belt-and-suspenders
	// over the provider's Enforce skip, against a transient Enforce=false flap.
	if s.taps != nil && s.enforce != nil {
		s.taps.isEnforcedMAC = s.enforce.isEnforcedMAC
	}

	// Run IPC reader, dp spawn loop, keepalive client, and (optionally) the
	// tap + enforce reconcilers concurrently; they all exit when ctx is canceled.
	var wg sync.WaitGroup
	workers := 4 // ipc, spawn, keepalive, fqdn-expire
	if s.taps != nil {
		workers++
	}
	if s.enforce != nil {
		workers++
	}
	wg.Add(workers)
	ipcErr := make(chan error, 1)
	spawnErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		ipcErr <- s.ipc.run(ctx)
	}()
	go func() {
		defer wg.Done()
		spawnErr <- s.spawnLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		s.client.keepAliveLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		s.fqdnExpireLoop(ctx)
	}()
	if s.taps != nil {
		go func() {
			defer wg.Done()
			s.taps.run(ctx)
		}()
	}
	if s.enforce != nil {
		go func() {
			defer wg.Done()
			s.enforce.run(ctx)
		}()
	}

	// Wave C1: session-cache builder. The IPC reader (already running
	// above) decodes DP_KIND_SESSION_LIST datagrams into EventSession
	// events; this goroutine consumes those events and applies them to
	// the cache. Wave C1 uses Apply semantics (not Replace) because dp
	// fragments a list across multiple datagrams; entries accumulate
	// within a poll cycle.
	pollInterval := s.opt.SessionPollInterval
	if pollInterval == 0 {
		pollInterval = 30 * time.Second
	}
	if pollInterval > 0 {
		go runSessionPoller(ctx, s.logger, s.client, pollInterval)
		// The session events come through the same Events channel as the
		// other event types — main.go's consumer goroutine routes them.
		// No new goroutine here. The cache is updated by main.go's switch
		// statement when it sees EventSession.
	}
	wg.Wait()
	close(ipcErr)
	close(spawnErr)

	if e, ok := <-ipcErr; ok && e != nil {
		return e
	}
	if e, ok := <-spawnErr; ok && e != nil {
		return e
	}
	return nil
}

// spawnLoop runs dp, waits for it to exit, then either restarts (with backoff)
// or returns when ctx is canceled.
func (s *Supervisor) spawnLoop(ctx context.Context) error {
	backoff := s.opt.RestartBackoff
	const maxBackoff = 30 * time.Second
	consecutiveFailures := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		exitedCleanly := s.runOnce(ctx)
		if exitedCleanly {
			consecutiveFailures = 0
			backoff = s.opt.RestartBackoff
		} else {
			consecutiveFailures++
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		s.logger.Warn("dp: scheduling restart",
			slog.Duration("after", backoff),
			slog.Int("consecutive_failures", consecutiveFailures))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
	}
}

// runOnce launches dp once and waits for it to exit. Returns true if dp
// exited cleanly (signal-based shutdown counts as clean — that's the
// happy path on ctx cancel).
func (s *Supervisor) runOnce(ctx context.Context) bool {
	args := s.dpArgs()
	cmd := exec.CommandContext(ctx, s.opt.Binary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Put dp in its own process group so a signal to the agent doesn't
		// race with dp's own signal handler. We kill explicitly on ctx cancel
		// via Cancel below.
		Setpgid: true,
	}
	// Forward dp's stderr / stdout into our structured logger one line at a
	// time. NeuVector's dp writes to /var/log/agent/dp.log normally; in our
	// container we don't keep a separate logfile.
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()

	s.mu.Lock()
	s.cmd = cmd
	s.startCount++
	s.generation.Store(s.startCount)
	s.mu.Unlock()
	s.logger.Info("dp: starting",
		slog.String("binary", s.opt.Binary),
		slog.Any("args", args))

	if err := cmd.Start(); err != nil {
		s.logger.Error("dp: start failed", slog.String("err", err.Error()))
		s.mu.Lock()
		s.crashCount++
		s.mu.Unlock()
		return false
	}

	go pipeToLogger(stderr, s.logger, slog.LevelInfo, "dp.stderr")
	go pipeToLogger(stdout, s.logger, slog.LevelInfo, "dp.stdout")

	err := cmd.Wait()
	s.mu.Lock()
	s.exitCount++
	s.cmd = nil
	s.mu.Unlock()

	if ctx.Err() != nil {
		// Shutdown path — signal-induced exit is expected.
		s.logger.Info("dp: exited on shutdown",
			slog.String("err", errStr(err)))
		return true
	}

	if err == nil {
		s.logger.Warn("dp: exited cleanly without shutdown — will restart")
		return true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		s.logger.Warn("dp: exited",
			slog.Int("code", exitErr.ExitCode()),
			slog.String("err", err.Error()))
	} else {
		s.logger.Error("dp: wait", slog.String("err", err.Error()))
	}
	s.mu.Lock()
	s.crashCount++
	s.mu.Unlock()
	return false
}

func (s *Supervisor) dpArgs() []string {
	args := []string{"-n", fmt.Sprintf("%d", s.opt.Threads)}
	if s.opt.TapInterface != "" {
		args = append(args, "-i", s.opt.TapInterface)
	}
	if s.opt.NoTC {
		args = append(args, "-c")
	}
	return args
}

// LifecycleStats is the dp-process-side companion to ipcServer's Stats.
type LifecycleStats struct {
	StartCount uint64
	ExitCount  uint64
	CrashCount uint64
}

// Stats returns a snapshot of lifecycle, IPC, keepalive, tap, and enforce
// counters. Each component reports zero values when not configured.
func (s *Supervisor) Stats() (LifecycleStats, Stats, ClientStats, TapStats) {
	life, ipc, ka, taps, _ := s.StatsAll()
	return life, ipc, ka, taps
}

// SessionStats forwards SessionCache.Snapshot for the metrics endpoint.
func (s *Supervisor) SessionStats() SessionCacheStats {
	if s == nil || s.sessions == nil {
		return SessionCacheStats{}
	}
	return s.sessions.Snapshot()
}

// StatsAll returns the Wave A3-extended snapshot including enforce manager
// counters. Existing callers (heartbeat, /metrics, /readyz) keep using the
// 4-return Stats() for backward compat; new callers can ask for the full
// shape here.
func (s *Supervisor) StatsAll() (LifecycleStats, Stats, ClientStats, TapStats, EnforceStats) {
	s.mu.Lock()
	life := LifecycleStats{
		StartCount: s.startCount,
		ExitCount:  s.exitCount,
		CrashCount: s.crashCount,
	}
	s.mu.Unlock()
	var ipc Stats
	if s.ipc != nil {
		ipc = s.ipc.snapshot()
	}
	var ka ClientStats
	if s.client != nil {
		ka = s.client.snapshot()
	}
	var taps TapStats
	if s.taps != nil {
		taps = s.taps.snapshot()
	}
	var enf EnforceStats
	if s.enforce != nil {
		enf = s.enforce.snapshot()
	}
	return life, ipc, ka, taps, enf
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// pipeToLogger consumes one of dp's pipes line by line and forwards each line
// through the supplied slog handler. Done as a goroutine; returns when the
// pipe closes (which happens when dp exits).
func pipeToLogger(r io.ReadCloser, logger *slog.Logger, lvl slog.Level, stream string) {
	defer r.Close()
	buf := make([]byte, 4096)
	var leftover []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			leftover = append(leftover, buf[:n]...)
			for {
				idx := indexByte(leftover, '\n')
				if idx < 0 {
					break
				}
				line := string(leftover[:idx])
				leftover = leftover[idx+1:]
				if line == "" {
					continue
				}
				logger.Log(nil, lvl, line, slog.String("stream", stream))
			}
		}
		if err != nil {
			if len(leftover) > 0 {
				logger.Log(nil, lvl, string(leftover), slog.String("stream", stream))
			}
			return
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
