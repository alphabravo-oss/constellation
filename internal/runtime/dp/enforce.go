// Wave A3: per-pod NFQUEUE enforcement.
//
// enforceManager is to inline-enforcement what tapManager is to TAP-mode
// observation. The desired set comes from an EnforceProvider; the
// reconciler diffs against the current set and:
//
//   add new entry:
//     1. allocate a queue number from QnumAllocator
//     2. tell dp to bind its NFQUEUE listener via AddNfqPort
//     3. tell dp the workload identity via AddMAC
//     4. install iptables PREROUTING + POSTROUTING rules with --queue-bypass
//
//   remove gone entry:
//     1. drop the iptables rules (fail-open: if dp dies before this
//        completes, --queue-bypass keeps the pod connected)
//     2. tell dp to release the NFQUEUE via DelNfqPort + DelMAC
//     3. release the queue number
//
// The policy state machine (Wave A5) decides which workloads belong in
// the desired set — typically "every workload with an enforce-mode
// runtime_policies row attached, matched to its host-side veth(s)".
package dp

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// EnforceTarget is one veth that should be in NFQUEUE inline mode.
// Extends TapTarget with the queue number the agent allocated.
type EnforceTarget struct {
	NetNS string
	Iface string
	EPMAC string
	// Qnum is the kernel NFQUEUE number dp will bind. Set by enforceManager
	// from QnumAllocator before the AddNfqPort RPC; providers leave it 0.
	Qnum int
	// WAF/DLP are the per-workload DPI opt-in decisions (pod labels), carried
	// from the TapTarget so the DLP/WAF sync worker can bind the detector to
	// this inline (verdict-capable) ep. An inline-only workload is skipped by
	// the tap reconciler, so it never appears in the tap-derived opt-in sets —
	// the opt-in must ride the enforce path or ENFORCE drop/reset never binds.
	WAF bool
	DLP bool

	// Apps are the workload's listening-port hints, sent to dp via ctrl_cfg_mac
	// after AddMAC so dp fixes mid-stream session direction and recruits the L7
	// parser on the inline ep — the precondition for DLP/WAF to scan + enforce.
	Apps []protoPortApp

	// PIPS are the pod's IPs, passed to dp via AddMAC. On the NFQUEUE path the
	// packet's L2 header is faked, so dp cannot tell ingress from egress by MAC;
	// it compares src/dst IP against ep->pips (third_party/neuvector/dp/dpi/
	// dpi_entry.c nfq_packet_direction :367-374). Without the pod IPs dp falls
	// back to a port-order guess, can misassign direction, and the HTTP request
	// parser bails ("first packet from server") so no L7 parser is recruited and
	// DLP/WAF never scan. NeuVector passes these on its inline path for exactly
	// this reason (neuvector/agent/engine.go:1462-1481 pAddrs). Empty is tolerated
	// (dp then relies on the app-port hints alone).
	PIPS []string
}

func (t EnforceTarget) key() string {
	return t.NetNS + "|" + t.Iface
}

// EnforceProvider is what the manager calls to discover the desired list
// of pods that should be in enforce mode. Reconciles on the same cadence
// as the tap reconciler.
//
// Default implementation will live in main.go (or a sibling package): it
// joins runtime_policies (mode='enforce') against the agent's pod-veth
// auto-discovery and emits one EnforceTarget per (workload-veth) pair.
type EnforceProvider interface {
	Desired(ctx context.Context) ([]EnforceTarget, error)
}

// enforceManager is the parallel of tapManager for the NFQUEUE path.
type enforceManager struct {
	client   *dpClient
	provider EnforceProvider
	logger   *slog.Logger
	interval time.Duration

	ipt    *ipt
	qnums  *QnumAllocator

	mu      sync.Mutex
	current map[string]EnforceTarget // key → target known to dp (with assigned Qnum)

	added   atomic.Uint64
	removed atomic.Uint64
	errors  atomic.Uint64
}

func newEnforceManager(client *dpClient, provider EnforceProvider, logger *slog.Logger, interval time.Duration, ipt *ipt, qnums *QnumAllocator) *enforceManager {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if ipt == nil {
		ipt = newIPT()
	}
	if qnums == nil {
		qnums = NewQnumAllocator(0, 0) // defaults
	}
	return &enforceManager{
		client:   client,
		provider: provider,
		logger:   logger,
		interval: interval,
		ipt:      ipt,
		qnums:    qnums,
		current:  map[string]EnforceTarget{},
	}
}

// run drives the reconcile loop. Mirrors tapManager.run: wait for dp's
// listen socket, reconcile once immediately, then on every tick.
func (m *enforceManager) run(ctx context.Context) {
	m.waitForSocket(ctx, 5*time.Second)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	m.reconcileOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			m.teardown(context.Background())
			return
		case <-t.C:
			m.reconcileOnce(ctx)
		}
	}
}

func (m *enforceManager) waitForSocket(ctx context.Context, timeout time.Duration) {
	// Re-use the tapManager helper's body — kept inline to avoid coupling.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(DPServerSocket); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (m *enforceManager) reconcileOnce(ctx context.Context) {
	desired, err := m.provider.Desired(ctx)
	if err != nil {
		m.errors.Add(1)
		m.logger.Warn("dp enforce: provider error", slog.String("err", err.Error()))
		return
	}
	want := make(map[string]EnforceTarget, len(desired))
	for _, d := range desired {
		want[d.key()] = d
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Add new entries.
	for k, t := range want {
		if _, has := m.current[k]; has {
			continue
		}
		if t.EPMAC == "" {
			if mac, err := resolveMAC(t.Iface); err == nil {
				t.EPMAC = mac
			}
		}
		qnum, err := m.qnums.Allocate()
		if err != nil {
			m.errors.Add(1)
			m.logger.Error("dp enforce: qnum allocator exhausted",
				slog.String("iface", t.Iface), slog.String("err", err.Error()))
			continue
		}
		t.Qnum = qnum
		// 1) dp binds the queue.
		if err := m.client.AddNfqPort(t.NetNS, t.Iface, qnum, t.EPMAC, nil); err != nil {
			m.qnums.Release(qnum)
			m.errors.Add(1)
			m.logger.Warn("dp enforce: AddNfqPort",
				slog.String("iface", t.Iface), slog.String("err", err.Error()))
			continue
		}
		// 2) dp learns the workload MAC for policy matching.
		if t.EPMAC != "" {
			if err := m.client.AddMAC(t.Iface, t.EPMAC, t.PIPS); err != nil {
				m.errors.Add(1)
				m.logger.Warn("dp enforce: AddMAC",
					slog.String("iface", t.Iface), slog.String("err", err.Error()))
				// Continue — iptables redirect still works, just no MAC tag.
			} else {
				// 2b) Seed ep->app_map with the pod's listening-port hints, exactly
				// like the tap path (taps.go ConfigMAC). Without this, dp can't fix
				// mid-stream session direction on the inline ep, never recruits the
				// L7 (HTTP) parser, and so DLP/WAF never scan -> enforce can't drop.
				// tap=false: this is the inline (NFQUEUE) ep, not a mirror. Must come
				// after AddMAC (dp skips MACs not yet in its ep map). Best-effort.
				inline := false
				if err := m.client.ConfigMAC([]string{t.EPMAC}, &inline, t.Apps); err != nil {
					m.logger.Debug("dp enforce: ConfigMAC (best-effort)",
						slog.String("iface", t.Iface), slog.String("err", err.Error()))
				}
			}
		}
		// 3) Kernel rules send packets to the queue. THIS IS THE TRAFFIC-
		//    AFFECTING STEP — fail-open via --queue-bypass means dp not
		//    listening => kernel ACCEPTs.
		if err := m.ipt.addRedirect(ctx, t.NetNS, t.Iface, qnum); err != nil {
			// Roll back the dp side so we don't leak queues.
			_ = m.client.DelNfqPort(t.NetNS, t.Iface)
			_ = m.client.DelMAC(t.Iface, t.EPMAC)
			m.qnums.Release(qnum)
			m.errors.Add(1)
			m.logger.Error("dp enforce: iptables install failed; rolled back",
				slog.String("iface", t.Iface), slog.String("err", err.Error()))
			continue
		}
		m.added.Add(1)
		m.current[k] = t
		m.logger.Info("dp enforce: added",
			slog.String("iface", t.Iface), slog.Int("qnum", qnum),
			slog.String("epmac", t.EPMAC))
	}

	// Re-assert ep->tap=false (+ app hints) for EVERY current inline target on
	// EVERY pass — not just on first add. AddMAC defaults ep->tap=true (dp
	// ctrl.c:560) and a lost oneway or a competing ConfigMAC(tap=true) from the
	// tap path can leave ep->tap stuck true. With tap=true dp never emits the
	// NFQUEUE verdict (dpi_entry.c:653 `if(!tap && nfq) return 1`) and never runs
	// the DROP/RESET switch (the else of `if(ep->tap)` at dpi_packet.c:1222), so
	// SQLi returns 200 and no reset fires. Fire-and-forget: this self-heals a
	// clobbered/dropped tap=false so DLP/WAF drop+reset keeps firing inline.
	inline := false
	for _, t := range m.current {
		if t.EPMAC == "" {
			continue
		}
		if err := m.client.ConfigMAC([]string{t.EPMAC}, &inline, t.Apps); err != nil {
			m.logger.Debug("dp enforce: ConfigMAC re-assert (best-effort)",
				slog.String("iface", t.Iface), slog.String("err", err.Error()))
		}
	}

	// Remove gone entries.
	for k, t := range m.current {
		if _, still := want[k]; still {
			continue
		}
		// Remove iptables FIRST so packets stop going to a queue we're
		// about to close (avoids dp seeing packets for a queue it's
		// tearing down — harmless but noisy).
		_ = m.ipt.removeRedirect(ctx, t.NetNS, t.Iface, t.Qnum)
		if t.EPMAC != "" {
			_ = m.client.DelMAC(t.Iface, t.EPMAC)
		}
		_ = m.client.DelNfqPort(t.NetNS, t.Iface)
		m.qnums.Release(t.Qnum)
		m.removed.Add(1)
		delete(m.current, k)
		m.logger.Info("dp enforce: removed",
			slog.String("iface", t.Iface), slog.Int("qnum", t.Qnum))
	}
}

// teardown is called on supervisor shutdown. Best-effort removal of every
// installed iptables rule + dp NFQUEUE binding so a clean exit leaves the
// host in the same state we found it in.
func (m *enforceManager) teardown(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.current {
		_ = m.ipt.removeRedirect(ctx, t.NetNS, t.Iface, t.Qnum)
		if t.EPMAC != "" {
			_ = m.client.DelMAC(t.Iface, t.EPMAC)
		}
		_ = m.client.DelNfqPort(t.NetNS, t.Iface)
		m.qnums.Release(t.Qnum)
	}
	m.current = map[string]EnforceTarget{}
}

// EnforceStats is the enforce manager's contribution to the supervisor
// snapshot. Mirrors TapStats.
type EnforceStats struct {
	Added       uint64
	Removed     uint64
	Errors      uint64
	Current     int
	QueuesInUse int
}

func (m *enforceManager) snapshot() EnforceStats {
	m.mu.Lock()
	cur := len(m.current)
	m.mu.Unlock()
	return EnforceStats{
		Added:       m.added.Load(),
		Removed:     m.removed.Load(),
		Errors:      m.errors.Load(),
		Current:     cur,
		QueuesInUse: m.qnums.InUse(),
	}
}

// enforceDPIScopeMACs returns the inline-enforce (NFQUEUE, verdict-capable) ep
// MACs opted into WAF and into DLP respectively. It is the enforce-path analogue
// of tapManager.dpiScopeMACs: an inline-only workload is skipped by the tap
// reconciler, so its per-workload opt-in never reaches the tap-derived sets and
// must be carried on the EnforceTarget instead. The DLP/WAF sync worker unions
// these into its opt-in sets so a detector binds to the enforce ep and
// DPIActionDrop/Reset actually take effect instead of firing on a verdict-less
// mirror copy. Targets with an empty EPMAC are skipped (dp can't key a detector
// without a MAC). Empty before the first reconcile. Mutex-guarded like the rest.
func (m *enforceManager) enforceDPIScopeMACs() (wafMACs, dlpMACs map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wafMACs = make(map[string]bool)
	dlpMACs = make(map[string]bool)
	for _, t := range m.current {
		if t.EPMAC == "" {
			continue
		}
		if t.WAF {
			wafMACs[t.EPMAC] = true
		}
		if t.DLP {
			dlpMACs[t.EPMAC] = true
		}
	}
	return wafMACs, dlpMACs
}

// isEnforcedMAC reports whether mac is currently an active inline (NFQUEUE)
// enforce target. The tap reconciler consults this as a belt-and-suspenders
// guard over the EnforceTarget skip: even if a transient Enforce=false flap in
// the tap provider slips a MAC through, the tap path must never AddTapPort or
// ConfigMAC(tap=true) a veth the enforce path owns — that would clobber
// ep->tap=false and kill the NFQUEUE verdict. Empty mac / empty set => false.
func (m *enforceManager) isEnforcedMAC(mac string) bool {
	if mac == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.current {
		if t.EPMAC == mac {
			return true
		}
	}
	return false
}

// sortedTargetsForTest returns the current targets in a stable order so
// tests can assert deterministically. Not used by production code.
func (m *enforceManager) sortedTargetsForTest() []EnforceTarget {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]EnforceTarget, 0, len(m.current))
	for _, t := range m.current {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out
}
