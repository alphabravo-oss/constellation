package dp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TapTarget is one interface we want dp to inspect. Netns and Iface are
// passed to dp as-is; EPMAC is the workload identity dp tags every emitted
// DPMsgConnect record with. If EPMAC is empty we auto-resolve it from
// /sys/class/net/<iface>/address inside the agent's current netns (which
// only works if NetNS is empty or matches the agent's).
type TapTarget struct {
	NetNS string
	Iface string
	EPMAC string

	// PMAC is set ONLY for a proxymesh (service-mesh loopback) tap. When PMAC is
	// non-empty the reconciler registers this tap via the proxymesh AddMAC path:
	// EPMAC is a synthetic "lkst"-prefixed identity (dp keys its ep map + loopback
	// attribution off it), PMAC carries the pod's real eth0 MAC (dp's policy
	// handle). See ContainerTapProvider.
	PMAC string
	// PIPS are the ep's IPs. For a proxymesh lo tap these are the pod's loopback +
	// eth0 IPs (xff match for 127.0.0.x 5-tuples); for a plain eth0 tap they are
	// the pod IPs, carried so the enforce (NFQUEUE) provider can forward them to
	// dp for direction determination. The tap path itself only consumes PIPS on
	// the proxymesh (PMAC-set) branch; a plain eth0 tap's AddMAC passes nil.
	PIPS []string

	// Apps are the workload's listening-port app hints, sent to dp via
	// ctrl_cfg_mac after the MAC is registered. They seed dp's ep->app_map so
	// it identifies this MAC as the server on those ports and fixes mid-stream
	// session direction for TAP-copied flows — the precondition for recruiting
	// L7 parsers and running DLP/WAF. Empty is fine (dp then falls back to its
	// port-order direction heuristic).
	Apps []protoPortApp

	// WAF/DLP are the per-workload DPI opt-in flags (from pod labels). DPI is
	// OFF by default and fleet-wide binding false-positives (e.g. dp's
	// check_sql_query runs WAF SQLi rules on any workload's DB egress). The sync
	// worker binds the WAF pack only to WAF-opted MACs and the DLP catalog only
	// to DLP-opted MACs — mirroring NeuVector's per-group waf_group/dlp_group model.
	WAF bool
	DLP bool
	// Enforce marks the workload for INLINE (NFQUEUE) mode. The tap reconciler
	// SKIPS these (they are inline-only, handled by ContainerEnforceProvider /
	// enforceManager) so a veth is never both mirrored and NFQUEUE'd. Set by the
	// lister only under the agent enforce gate + pod opt-in (default false).
	Enforce bool

	// Namespace / PodName / Labels are the tapped pod's Kubernetes identity,
	// carried so the DLP/WAF sync worker can match this local pod against
	// group→sensor bindings (NET-43): groups are namespace + label selectors, and
	// the agent is the only place that knows a MAC's pod labels. Populated by the
	// ContainerTapProvider; empty for the env/veth providers (which have no pod
	// identity), leaving those MACs eligible only for the label opt-in path.
	Namespace string
	PodName   string
	Labels    map[string]string
}

// PodTapMeta is the pod identity of one actively-tapped MAC, exposed so the
// DLP/WAF sync worker can resolve group→sensor bindings (NET-43) against the
// pods this agent actually taps. MAC is the tap EPMAC (dp's workload handle).
type PodTapMeta struct {
	MAC       string
	Namespace string
	PodName   string
	Labels    map[string]string
}

// key returns the dedup key dp uses internally (netns+iface), so the
// reconciler's diff matches dp's notion of identity.
func (t TapTarget) key() string {
	return t.NetNS + "|" + t.Iface
}

// TapProvider is what the manager calls to discover the desired list of
// interfaces. Two implementations live below:
//
//   - envTapProvider: reads CONSTELLATION_DP_TAP_PORTS (comma-separated
//     iface names) and CONSTELLATION_DP_TAP_NETNS (one netns for all).
//     Useful in dev/test and as a stop-gap until pod-veth discovery lands.
//
//   - (Wave 3b) podVethProvider: enumerates host-side veths matching CNI
//     prefixes (veth*, cali*, lxc*) and resolves each peer's MAC via netlink.
//
// More providers can plug in; the manager doesn't care where the desired
// list comes from.
type TapProvider interface {
	Desired(ctx context.Context) ([]TapTarget, error)
}

// tapManager reconciles a desired-state TapProvider with dp's actual TAP
// state. It calls AddTapPort for entries that appear in the desired list
// and DelTapPort for ones that disappear. Runs on a 10s tick by default;
// the interval is tunable via Options.TapReconcileInterval.
type tapManager struct {
	client   *dpClient
	provider TapProvider
	logger   *slog.Logger
	interval time.Duration

	// isEnforcedMAC, when set, reports whether a MAC is an active inline
	// (NFQUEUE) enforce target. The reconciler skips such MACs so it can never
	// tap-mirror or ConfigMAC(tap=true) a veth the enforce path owns — guarding
	// the ep->tap=false invariant the NFQUEUE verdict depends on against a
	// transient Enforce=false flap in the provider. Nil in tests / no enforce mgr.
	isEnforcedMAC func(mac string) bool

	mu      sync.Mutex
	current map[string]TapTarget // key → target known to dp

	added   atomic.Uint64
	removed atomic.Uint64
	errors  atomic.Uint64
}

func newTapManager(client *dpClient, provider TapProvider, logger *slog.Logger, interval time.Duration) *tapManager {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &tapManager{
		client:   client,
		provider: provider,
		logger:   logger,
		interval: interval,
		current:  map[string]TapTarget{},
	}
}

// run reconciles immediately (after waiting for dp's listen socket), then on
// every tick until ctx is canceled. On shutdown we attempt a best-effort
// DelTapPort for every known target so the next agent restart doesn't see
// stale dp state — though in practice dp exits with us so it cleans up its
// own contexts.
func (m *tapManager) run(ctx context.Context) {
	// dp creates /tmp/dp_listen.sock during its init (third_party/neuvector/dp/ctrl.c:3032);
	// the supervisor forks dp asynchronously, so on a cold start the manager
	// can race ahead. Wait up to ~5s for the socket to appear before the
	// first reconcile — without this, the first tick fails noisily and the
	// next attempt is 10s away by default.
	m.waitForSocket(ctx, 5*time.Second)

	t := time.NewTicker(m.interval)
	defer t.Stop()
	m.reconcileOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			m.teardown()
			return
		case <-t.C:
			m.reconcileOnce(ctx)
		}
	}
}

// waitForSocket polls for dp's listen socket up to `timeout`. Returns early
// if the socket appears or ctx is canceled. Polling rather than netlink/inotify
// because we only do this once at supervisor startup and the path is fixed.
func (m *tapManager) waitForSocket(ctx context.Context, timeout time.Duration) {
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

func (m *tapManager) reconcileOnce(ctx context.Context) {
	desired, err := m.provider.Desired(ctx)
	if err != nil {
		m.errors.Add(1)
		m.logger.Warn("dp tap: provider error", slog.String("err", err.Error()))
		return
	}
	want := make(map[string]TapTarget, len(desired))
	for _, d := range desired {
		// Enforce workloads go through the inline (NFQUEUE) reconciler, not the
		// tap mirror — skip them here so a veth is never both tapped and NFQUEUE'd.
		if d.Enforce {
			continue
		}
		// Also skip any MAC the inline enforce path already owns. The provider's
		// Enforce flag can flap (a container-list race where one Desired() snapshot
		// misses the enforce label), which would otherwise let a veth back into the
		// tap set even though the enforce path is driving it. dp keys the ep by MAC:
		// tap and nfq SHARE one io_ep + policy_hdl, so a competing tap registration
		// (AddMAC/ConfigMAC tap=true) resets ep->tap=true and silently converts the
		// inline DENY into ACCEPT. Excluding it here means the removal loop below
		// tears our tap port down and leaves the ep to the enforce path.
		if m.isEnforcedMAC != nil && d.EPMAC != "" && m.isEnforcedMAC(d.EPMAC) {
			continue
		}
		want[d.key()] = d
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Add anything new.
	for k, t := range want {
		if _, has := m.current[k]; has {
			continue
		}
		if t.EPMAC == "" {
			if mac, err := resolveMAC(t.Iface); err == nil {
				t.EPMAC = mac
			} else {
				m.logger.Debug("dp tap: epmac auto-resolve failed; sending empty",
					slog.String("iface", t.Iface), slog.String("err", err.Error()))
			}
		}
		// Never tap a MAC the inline enforce path owns. The provider already
		// skips Enforce targets, but a transient Enforce=false flap could slip
		// one through — tapping it would issue ConfigMAC(tap=true) and clobber
		// the ep->tap=false the NFQUEUE verdict requires. Defensive skip.
		if m.isEnforcedMAC != nil && t.EPMAC != "" && m.isEnforcedMAC(t.EPMAC) {
			m.logger.Debug("dp tap: skipping MAC owned by inline enforce path",
				slog.String("iface", t.Iface), slog.String("mac", t.EPMAC))
			continue
		}
		if err := m.client.AddTapPort(t.NetNS, t.Iface, t.EPMAC); err != nil {
			m.errors.Add(1)
			m.logger.Warn("dp tap: AddTapPort",
				slog.String("netns", t.NetNS), slog.String("iface", t.Iface),
				slog.String("err", err.Error()))
			continue
		}
		// dp's session machinery only emits DPMsgConnect for MACs registered
		// via AddMAC. Without this, the tap reads packets but they go into
		// the void. The (Iface, MAC) pair here must match dp's per-tap
		// context — using the tap iface name is what NeuVector's engine does.
		if t.EPMAC != "" {
			var macErr error
			if t.PMAC != "" {
				// Proxymesh lo tap: register the synthetic "lkst" EPMAC with the
				// real eth0 MAC in PMAC and the pod IPs in PIPS so dp attributes
				// loopback packets and can xff-match 127.0.0.x traffic.
				macErr = m.client.AddProxyMeshMAC(t.Iface, t.EPMAC, t.PMAC, t.PIPS)
			} else {
				macErr = m.client.AddMAC(t.Iface, t.EPMAC, nil)
			}
			if macErr != nil {
				m.errors.Add(1)
				m.logger.Warn("dp tap: AddMAC",
					slog.String("iface", t.Iface), slog.String("mac", t.EPMAC),
					slog.String("err", macErr.Error()))
				// Don't unwind the AddTapPort — next reconcile will retry the
				// AddMAC, and the tap is harmlessly idle until the MAC lands.
			} else {
				// Seed dp with this MAC's tap flag + listening-port app hints
				// (ctrl_cfg_mac). This is what makes dp recruit L7 parsers and
				// run DLP/WAF on TAP-copied sessions — see ConfigMAC. Must come
				// after AddMAC (dp skips MACs not yet in its ep map). Best-effort:
				// tap=true just reasserts the current default, and empty Apps is
				// harmless, so a failure here only means recruitment stays
				// heuristic until the next reconcile.
				tap := true
				if err := m.client.ConfigMAC([]string{t.EPMAC}, &tap, t.Apps); err != nil {
					m.logger.Debug("dp tap: ConfigMAC (best-effort)",
						slog.String("iface", t.Iface), slog.String("mac", t.EPMAC),
						slog.String("err", err.Error()))
				}
			}
		}
		m.added.Add(1)
		m.current[k] = t
		m.logger.Info("dp tap: added",
			slog.String("netns", t.NetNS), slog.String("iface", t.Iface),
			slog.String("epmac", t.EPMAC))
	}

	// Remove anything that disappeared from the desired set.
	for k, t := range m.current {
		if _, still := want[k]; still {
			continue
		}
		// Never DelMAC a veth the inline enforce path now owns. dp keys the ep by
		// MAC and tap+nfq share ONE io_ep: DelMAC removes that ep from g_ep_map,
		// wiping the enforce path's policy_hdl (→ policy_id=0, default-allow) and,
		// on the next add_mac, resetting ep->tap=true (→ DENY silently ACCEPTed).
		// We still tear down our own tap PORT (dp stops mirroring), but the MAC/ep
		// stays with the enforce reconciler, which re-asserts tap=false each pass.
		enforced := m.isEnforcedMAC != nil && t.EPMAC != "" && m.isEnforcedMAC(t.EPMAC)
		if t.EPMAC != "" && !enforced {
			if err := m.client.DelMAC(t.Iface, t.EPMAC); err != nil {
				m.logger.Debug("dp tap: DelMAC (best-effort)",
					slog.String("iface", t.Iface), slog.String("err", err.Error()))
			}
		}
		if err := m.client.DelTapPort(t.NetNS, t.Iface); err != nil {
			m.errors.Add(1)
			m.logger.Warn("dp tap: DelTapPort",
				slog.String("netns", t.NetNS), slog.String("iface", t.Iface),
				slog.String("err", err.Error()))
		}
		m.removed.Add(1)
		delete(m.current, k)
		m.logger.Info("dp tap: removed",
			slog.String("netns", t.NetNS), slog.String("iface", t.Iface))
	}
}

// currentMACs returns a snapshot of the EPMAC of every actively-tapped
// interface. Wave C4.5's DLP sync worker uses this to scope rule sets to
// the workloads the agent actually observes (an empty list = "apply to
// nothing", so callers should skip the BuildDLPRules call in that case).
func (m *tapManager) currentMACs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.current))
	for _, t := range m.current {
		if t.EPMAC != "" {
			out = append(out, t.EPMAC)
		}
	}
	return out
}

// dpiScopeMACs returns the set of tapped EPMACs opted into WAF and into DLP
// respectively (from each workload's pod labels). DPI is OFF by default; a
// workload is bound only when it explicitly opts in — mirroring NeuVector's
// per-group waf_group/dlp_group model. This is what keeps the CRS WAF pack off
// internal API clients whose DB egress dp feeds to check_sql_query (the Postgres
// SQLi false positive), while letting an operator enable WAF on public web
// workloads.
func (m *tapManager) dpiScopeMACs() (wafMACs, dlpMACs map[string]bool) {
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

// podMeta returns the pod identity (namespace, name, labels) of every
// actively-tapped MAC that carries one. Only ContainerTapProvider populates
// pod identity, so env/veth-provider MACs are omitted (they can't be matched to
// a group selector). Used by the DLP/WAF sync worker to resolve group→sensor
// bindings (NET-43) against the pods this agent taps.
func (m *tapManager) podMeta() []PodTapMeta {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PodTapMeta, 0, len(m.current))
	for _, t := range m.current {
		if t.EPMAC == "" || (t.Namespace == "" && t.PodName == "" && len(t.Labels) == 0) {
			continue
		}
		out = append(out, PodTapMeta{
			MAC:       t.EPMAC,
			Namespace: t.Namespace,
			PodName:   t.PodName,
			Labels:    t.Labels,
		})
	}
	return out
}

// teardown removes every current tap. Best-effort, errors swallowed —
// shutdown is a "do what you can" path.
func (m *tapManager) teardown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.current {
		_ = m.client.DelTapPort(t.NetNS, t.Iface)
	}
	m.current = map[string]TapTarget{}
}

// TapStats is the reconciler's contribution to the supervisor's summary.
type TapStats struct {
	Added       uint64
	Removed     uint64
	Errors      uint64
	CurrentTaps int
}

func (m *tapManager) snapshot() TapStats {
	m.mu.Lock()
	cur := len(m.current)
	m.mu.Unlock()
	return TapStats{
		Added:       m.added.Load(),
		Removed:     m.removed.Load(),
		Errors:      m.errors.Load(),
		CurrentTaps: cur,
	}
}

// ---------------------------------------------------------------------------
// envTapProvider — CONSTELLATION_DP_TAP_PORTS=eth0,veth9a4b
// ---------------------------------------------------------------------------

// envTapProvider sources the desired list from a comma-separated env var.
// This is the bootstrap provider: it lets you point dp at a known interface
// in dev / test before the pod-veth discovery loop is wired up.
type envTapProvider struct {
	portsEnv string
	netnsEnv string
}

// NewEnvTapProvider reads CONSTELLATION_DP_TAP_PORTS (comma-separated iface
// names) and CONSTELLATION_DP_TAP_NETNS (single netns path applied to all).
// Returns nil if no ports are configured so the supervisor knows to skip
// starting the tap manager.
//
// netns defaults to "/proc/1/ns/net", which is dp's convention for "the host
// netns" — dp's enter_netns(netns) always open()'s the path, so empty string
// fails. With hostNetwork=true on the DaemonSet, /proc/1/ns/net inside the
// pod resolves to the host's netns, which is what we want for tapping
// host-side veths from the agent container.
func NewEnvTapProvider() TapProvider {
	ports := strings.TrimSpace(os.Getenv("CONSTELLATION_DP_TAP_PORTS"))
	if ports == "" {
		return nil
	}
	netns := os.Getenv("CONSTELLATION_DP_TAP_NETNS")
	if netns == "" {
		netns = "/proc/1/ns/net"
	}
	return &envTapProvider{
		portsEnv: ports,
		netnsEnv: netns,
	}
}

func (p *envTapProvider) Desired(ctx context.Context) ([]TapTarget, error) {
	parts := strings.Split(p.portsEnv, ",")
	out := make([]TapTarget, 0, len(parts))
	for _, raw := range parts {
		iface := strings.TrimSpace(raw)
		if iface == "" {
			continue
		}
		out = append(out, TapTarget{NetNS: p.netnsEnv, Iface: iface})
	}
	// Sort for stable diff behavior. The manager doesn't care about order
	// but it makes the log output deterministic.
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out, nil
}

// resolveMAC reads /sys/class/net/<iface>/address. Returns the canonical
// "aa:bb:cc:dd:ee:ff" form. Only works for interfaces in the agent's own
// netns — if the desired tap is inside a pod netns, dp resolves the MAC
// itself after setns()'ing in.
func resolveMAC(iface string) (string, error) {
	if iface == "" {
		return "", errors.New("empty iface")
	}
	path := filepath.Join("/sys/class/net", iface, "address")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	macStr := strings.TrimSpace(string(b))
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return "", fmt.Errorf("parse mac %q: %w", macStr, err)
	}
	return mac.String(), nil
}
