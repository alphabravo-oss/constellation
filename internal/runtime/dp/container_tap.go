package dp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// RunningContainer is the minimal view the tap provider needs of a running
// container: its identity (for logs) and the host PID of its main process
// (which yields /proc/<PID>/ns/net). main.go adapts
// hostscan.RunningContainer into this — keeping the dp package free of a
// hostscan import (hostscan already imports dp, so the reverse would cycle).
type RunningContainer struct {
	ID      string
	PodName string
	PID     int
	// Namespace + Labels are the pod's Kubernetes identity (namespace + user
	// labels from the sandbox), carried so the tap it produces can be matched
	// against group→sensor bindings (NET-43). Empty when the lister can't read
	// them; the workload then falls back to the label DPI opt-in only.
	Namespace string
	Labels    map[string]string
	// WAF/DLP are the per-workload DPI opt-in decisions (derived from pod labels
	// by the lister). Default false — DPI binds only to opted-in workloads.
	WAF bool
	DLP bool
	// Enforce marks a workload for INLINE (NFQUEUE) mode instead of the TAP
	// mirror path — the verdict-capable datapath where dp can DROP/RESET. The
	// lister sets it only when the agent's enforce gate is on AND the pod opts in
	// (default false), so inline interception never activates by accident. An
	// Enforce workload is routed to the enforce reconciler and excluded from tap.
	Enforce bool
}

// ContainerLister enumerates running containers. The production lister wraps
// hostscan.ListRunningContainers (crictl); tests inject a fake.
type ContainerLister func(ctx context.Context) ([]RunningContainer, error)

// ContainerTapProvider taps each running container INSIDE its own network
// namespace, with the container's real interface MAC — matching NeuVector's
// proven model and unlike PodVethProvider, which taps the host-side veth with
// the host-side MAC.
//
// Why this matters (the bug it fixes): dp uses EPMAC as a HARD packet filter
// against on-wire MACs (third_party/neuvector/dp/dpi/dpi_entry.c:474-559). On
// flannel's cni0 bridge the on-wire src/dst MACs are the POD-side veth MACs,
// not the host-side ones. Tapping the host veth with its host-side MAC makes
// every packet mismatch and get dropped → dp_rx_total=0 → empty network map.
// Entering the container netns and tapping its eth0 with eth0's MAC makes the
// filter always match, exactly like NeuVector.
//
// This mirrors NeuVector:
//   - agent/engine.go programDataPath: netns = GetNetNamespacePath(c.pid)
//     (= /proc/<pid>/ns/net), then dp.DPCtrlAddTapPort(netns, iface, mac).
//     (engine.go:1453-1507 for the TAP path; :644 for the lo/proxymesh path.)
//   - share/system/system_linux.go:351 GetNetNamespacePath(pid) =
//     /proc/<pid>/ns/net.
//   - share/system/system_linux.go:124-165 CallNetNamespaceFunc /
//     CallNetNamespaceFuncWithoutLock: LockOSThread, save current netns,
//     netns.Set(target), run callback, netns.Set(saved) — the setns dance we
//     reproduce in interfaceInNetns below (using x/sys/unix directly instead
//     of vishvananda/netns to avoid a new dependency).
type ContainerTapProvider struct {
	logger *slog.Logger

	// procRoot is "/proc" in production; tests don't touch it because they
	// inject listContainers + readIface.
	procRoot string

	// agentNetnsInode identifies the agent's own netns. With hostNetwork=true
	// the agent IS the host netns, so any container sharing it (hostNetwork
	// pods, the pause/sandbox of host-net pods) resolves to this same inode
	// and is skipped — NeuVector likewise skips host-mode containers.
	agentNetnsInode uint64

	// Injection points for tests. Production wires these to the real crictl
	// lister and the setns-based interface reader. readIface also returns the
	// interface's IPv4 addresses (used only for the proxymesh lo-tap PIPS).
	listContainers ContainerLister
	readIface      func(netnsPath string) (iface, mac string, ips []string, err error)

	// meshDetect reports whether the pod at this PID runs a service-mesh
	// sidecar proxy (Istio/Linkerd). Only consulted when the (default-off)
	// CONSTELLATION_MESH_LO_TAP flag is set; nil disables the lo-tap path.
	// Injected for tests; production scans /proc/<pid>/net/tcp.
	meshDetect func(pid int) bool
}

// NewContainerTapProvider builds the production provider. The lister comes
// from main.go (wrapping hostscan.ListRunningContainers via crictl); the
// per-container interface + MAC come from interfaceInNetns (which setns()'s
// into the container's netns).
func NewContainerTapProvider(logger *slog.Logger, lister ContainerLister) TapProvider {
	p := &ContainerTapProvider{
		logger:          logger,
		procRoot:        "/proc",
		agentNetnsInode: netnsInode("/proc/self/ns/net"),
		listContainers:  lister,
		readIface:       interfaceInNetns,
	}
	p.meshDetect = func(pid int) bool { return hasMeshListener(p.procRoot, pid) }
	return p
}

// Desired returns one TapTarget per running, non-host-network container:
// {NetNS: /proc/<pid>/ns/net, Iface: <primary up non-loopback iface, e.g.
// eth0>, EPMAC: <that iface's MAC>}. A failure on any single container is
// logged and skipped; it never aborts the whole reconcile.
func (p *ContainerTapProvider) Desired(ctx context.Context) ([]TapTarget, error) {
	containers, err := p.listContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	out := make([]TapTarget, 0, len(containers))
	seen := make(map[string]struct{}, len(containers)) // dedup by netns path
	for _, c := range containers {
		if c.PID <= 0 {
			continue
		}
		netnsPath := p.netnsPath(c.PID)

		// Skip host-network containers: their netns is the agent's own netns
		// (the host netns under hostNetwork=true). Tapping that would double-
		// count host traffic and duplicate the host-side veth problem.
		if p.agentNetnsInode != 0 {
			if inode := netnsInode(netnsPath); inode != 0 && inode == p.agentNetnsInode {
				p.logger.Debug("dp container-tap: skip host-network container",
					slog.String("id", c.ID), slog.String("pod", c.PodName))
				continue
			}
		}

		// Multiple containers in a pod share one netns; tap it once.
		if _, dup := seen[netnsPath]; dup {
			continue
		}

		iface, mac, ips, err := p.readIface(netnsPath)
		if err != nil {
			p.logger.Debug("dp container-tap: read iface failed",
				slog.String("id", c.ID), slog.String("pod", c.PodName),
				slog.String("netns", netnsPath), slog.String("err", err.Error()))
			continue
		}
		if iface == "" || mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}

		seen[netnsPath] = struct{}{}
		out = append(out, TapTarget{
			NetNS: netnsPath,
			Iface: iface,
			EPMAC: mac,
			// Listening-port hints so dp identifies this pod as the server on
			// those ports and fixes TAP session direction -> L7 parser
			// recruitment -> DLP/WAF. See listenPortApps / ConfigMAC.
			Apps: listenPortApps(p.procRoot, c.PID),
			// Per-workload DPI opt-in (from pod labels; default off).
			WAF:     c.WAF,
			DLP:     c.DLP,
			Enforce: c.Enforce,
			// Pod identity for group→sensor binding resolution (NET-43). Carried
			// only on the eth0 tap (the pod's workload MAC); the lo/proxymesh tap
			// below keeps no identity — it shares the pod but is keyed by a
			// synthetic MAC dp uses only for loopback attribution.
			Namespace: c.Namespace,
			PodName:   c.PodName,
			Labels:    c.Labels,
			// Pod IPs, carried so the enforce (NFQUEUE) provider can hand them to
			// dp via AddMAC: on the inline path dp needs ep->pips to determine
			// packet direction (faked L2 mac) -> L7 recruit -> DLP/WAF. Unused by
			// the tap path itself (eth0 AddMAC passes nil, matching NeuVector's
			// tap branch). See EnforceTarget.PIPS.
			PIPS: ips,
		})

		// Service-mesh lo-tap (MONITOR-ONLY, default off). If this pod runs a
		// sidecar proxy, ALSO tap its loopback so envoy<->app east-west traffic
		// becomes visible to DPI. Rides the TAP provider only (never the
		// enforce/NFQUEUE path), so there is no enforcement on lo yet. See the
		// ceiling comment on hasMeshListener.
		//
		// dp only attributes loopback packets (which carry all-zero L2 MACs)
		// via its proxymesh branch (third_party/neuvector/dp/dpi/dpi_entry.c:493),
		// which fires ONLY when the tap's EP MAC (ctx->ep_mac) carries the
		// "lkst" prefix (apis.h:42). So the lo tap's EPMAC must be a synthetic
		// proxymesh MAC — NOT the pod's real eth0 MAC, which would make every
		// mac_cmp miss and every loopback packet get dropped. The real eth0 MAC
		// rides along in PMAC (dp's policy handle) and the pod's loopback + eth0
		// IPs in PIPS (xff match for 127.0.0.x 5-tuples), mirroring NeuVector
		// ctrl.c:491-497. This is what makes the lo flows attribute to the app.
		if meshLoTapEnabled() && p.meshDetect != nil && p.meshDetect(c.PID) {
			epmac := proxyMeshMAC(mac)
			out = append(out, TapTarget{
				NetNS: netnsPath,
				Iface: "lo",
				EPMAC: epmac,
				PMAC:  mac,
				PIPS:  append(append([]string{}, ips...), "127.0.0.1"),
			})
			p.logger.Info("dp container-tap: mesh lo-tap added",
				slog.String("id", c.ID), slog.String("pod", c.PodName),
				slog.String("netns", netnsPath),
				slog.String("epmac", epmac), slog.String("pmac", mac))
		}
	}

	// Sort by (netns, iface) so a pod's eth0 and lo targets order stably.
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out, nil
}

func (p *ContainerTapProvider) netnsPath(pid int) string {
	root := p.procRoot
	if root == "" {
		root = "/proc"
	}
	return root + "/" + strconv.Itoa(pid) + "/ns/net"
}

// netnsInode returns the inode behind a /proc/<pid>/ns/net path, or 0 on
// error. Two paths with the same inode are the same network namespace.
func netnsInode(path string) uint64 {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0
	}
	return st.Ino
}

// interfaceInNetns enters the network namespace at netnsPath and returns the
// first UP, non-loopback interface's name and MAC (typically eth0). It mirrors
// NeuVector's CallNetNamespaceFuncWithoutLock (share/system/system_linux.go:
// 132-165): lock the OS thread, save the caller's netns, setns into the
// target, run the work, then ALWAYS setns back.
//
// Restore is guaranteed by defer even on panic. We deliberately do NOT
// UnlockOSThread if the restore fails — a thread left in a foreign netns must
// die with the goroutine rather than be reused for unrelated work.
func interfaceInNetns(netnsPath string) (iface, mac string, ips []string, err error) {
	// Pin this goroutine to its OS thread for the whole setns window.
	runtime.LockOSThread()

	// Save the thread's current netns so we can return to it. Use thread-self
	// (the per-thread netns) since we're operating at thread granularity.
	savedPath := "/proc/thread-self/ns/net"
	savedFD, err := unix.Open(savedPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		// Older kernels lack /proc/thread-self; fall back to /proc/self.
		savedPath = "/proc/self/ns/net"
		savedFD, err = unix.Open(savedPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			return "", "", nil, fmt.Errorf("open current netns: %w", err)
		}
	}

	targetFD, err := unix.Open(netnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(savedFD)
		runtime.UnlockOSThread()
		return "", "", nil, fmt.Errorf("open target netns %s: %w", netnsPath, err)
	}

	// Enter the container's netns.
	if err := unix.Setns(targetFD, unix.CLONE_NEWNET); err != nil {
		unix.Close(targetFD)
		unix.Close(savedFD)
		runtime.UnlockOSThread()
		return "", "", nil, fmt.Errorf("setns into %s: %w", netnsPath, err)
	}
	unix.Close(targetFD)

	// From here on, restore is mandatory. If it fails we keep the thread
	// locked (and never unlock) so the runtime retires it instead of handing
	// a netns-polluted thread to another goroutine.
	defer func() {
		if rerr := unix.Setns(savedFD, unix.CLONE_NEWNET); rerr != nil {
			// Could not get back to our own netns. Leave the thread locked.
			if err == nil {
				err = fmt.Errorf("restore netns (thread retired): %w", rerr)
			}
			unix.Close(savedFD)
			return
		}
		unix.Close(savedFD)
		runtime.UnlockOSThread()
	}()

	return primaryInterface()
}

// primaryInterface returns the first UP, non-loopback interface (its name, MAC
// and IPv4 addresses) in the CURRENT netns. Called only while inside a target
// container netns. The IPv4 list feeds the proxymesh lo-tap PIPS.
func primaryInterface() (name, mac string, ips []string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", nil, fmt.Errorf("list interfaces: %w", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		mac := ifi.HardwareAddr.String()
		if mac == "" {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil {
					ips = append(ips, v4.String())
				}
			}
		}
		return ifi.Name, mac, ips, nil
	}
	return "", "", nil, fmt.Errorf("no up non-loopback interface")
}

// proxyMeshMAC derives the synthetic "lkst"-prefixed EP MAC dp requires to
// attribute loopback packets (third_party/neuvector/dp/apis.h:42
// PROXYMESH_MAC_PREFIX, dpi_entry.c:493). It keeps the pod's real eth0 MAC
// unique in the low two octets so distinct pods don't collide in dp's ep map;
// on a parse failure it falls back to a zeroed suffix. The real MAC still
// travels in PMAC. "lkst" == 0x6c6b7374.
func proxyMeshMAC(realMAC string) string {
	b := []byte{0x6c, 0x6b, 0x73, 0x74, 0x00, 0x00}
	if hw, err := net.ParseMAC(realMAC); err == nil && len(hw) >= 6 {
		b[4], b[5] = hw[4], hw[5]
	}
	return net.HardwareAddr(b).String()
}

// ---------------------------------------------------------------------------
// Service-mesh loopback (sidecar<->app) inspection.
//
// ponytail (ceiling comment): NeuVector taps intra-pod lo (engine.go:644, the
// lo/proxymesh path) so Istio/Linkerd east-west (envoy<->app) traffic is
// inspected. We otherwise only re-attribute XFF on the north-south hop and
// never tap lo, so behind-the-sidecar app traffic is invisible to our DPI.
// This adds a MONITOR-ONLY lo-tap: when CONSTELLATION_MESH_LO_TAP is set and a
// pod looks meshed, Desired() also emits a "lo" TapTarget carrying the app's
// (pod eth0) EPMAC, feeding loopback flows through the same session-cache ->
// flow pipeline attributed to the app container. Additive and guarded; no
// enforcement on lo. LATER: enforce-on-lo, and image-based sidecar detection
// once the container lister surfaces image names (today we sniff proxy ports).
// ---------------------------------------------------------------------------

// meshPorts are well-known service-mesh proxy LISTEN ports. A listener on any
// of these inside a pod's netns is our proxymesh signature.
//   - Istio (envoy): 15001 out, 15006 in, 15000 admin, 15020/15021/15090 telemetry
//   - Linkerd2 (proxy): 4143 in, 4140 out, 4191 admin
var meshPorts = map[uint64]struct{}{
	15001: {}, 15006: {}, 15000: {}, 15020: {}, 15021: {}, 15090: {},
	4143: {}, 4140: {}, 4191: {},
}

// meshLoTapEnabled reports whether the default-off service-mesh lo-tap is on.
func meshLoTapEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CONSTELLATION_MESH_LO_TAP"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// listenPortApps enumerates the LISTEN TCP sockets in pid's network namespace
// and returns one app hint per distinct local port. dp seeds these into
// ep->app_map via ctrl_cfg_mac so it identifies the pod as the server on those
// ports and fixes mid-stream session direction for TAP-copied flows — the
// precondition for recruiting L7 parsers (and thus DLP/WAF). App/Server are
// left 0 (unknown): direction only needs the port present with listen=true
// (dpi_session.c:883-895); dp recruits the real parser and reports the true app
// itself. Reads /proc/<pid>/net/tcp{,6}, which already reflect pid's netns, so
// no setns dance is needed (same as hasMeshListener).
func listenPortApps(procRoot string, pid int) []protoPortApp {
	if procRoot == "" {
		procRoot = "/proc"
	}
	base := procRoot + "/" + strconv.Itoa(pid) + "/net/"
	seen := map[uint16]struct{}{}
	var out []protoPortApp
	for _, name := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(base + name)
		if err != nil {
			continue
		}
		for _, port := range parseListenPorts(b) {
			if _, dup := seen[port]; dup {
				continue
			}
			seen[port] = struct{}{}
			out = append(out, protoPortApp{Port: port, IPProto: 6}) // 6 = TCP
		}
	}
	return out
}

// parseListenPorts scans a /proc/<pid>/net/tcp table for LISTEN sockets
// (st == 0x0A) and returns their local ports. Column layout per proc(5):
// "sl local_address rem_address st ..." where local_address is "HEXIP:HEXPORT".
func parseListenPorts(table []byte) []uint16 {
	const tcpListen = "0A"
	var ports []uint16
	for _, ln := range strings.Split(string(table), "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 || f[3] != tcpListen {
			continue
		}
		colon := strings.LastIndexByte(f[1], ':')
		if colon < 0 {
			continue
		}
		port, err := strconv.ParseUint(f[1][colon+1:], 16, 16)
		if err != nil {
			continue
		}
		ports = append(ports, uint16(port))
	}
	return ports
}

// hasMeshListener reports whether the netns of pid has a proxy LISTEN socket on
// a known mesh port. It reads /proc/<pid>/net/tcp{,6}, which reflect that pid's
// network namespace, so no setns dance is needed.
func hasMeshListener(procRoot string, pid int) bool {
	if procRoot == "" {
		procRoot = "/proc"
	}
	base := procRoot + "/" + strconv.Itoa(pid) + "/net/"
	for _, name := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(base + name)
		if err != nil {
			continue
		}
		if parseMeshListen(b) {
			return true
		}
	}
	return false
}

// parseMeshListen scans a /proc/<pid>/net/tcp table for a LISTEN socket
// (st == 0x0A) whose local port is a known mesh port. Column layout per
// proc(5): "sl local_address rem_address st ..." where local_address is
// "HEXIP:HEXPORT"; we only need the port.
func parseMeshListen(table []byte) bool {
	const tcpListen = "0A"
	for _, ln := range strings.Split(string(table), "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 || f[3] != tcpListen {
			continue
		}
		colon := strings.LastIndexByte(f[1], ':')
		if colon < 0 {
			continue
		}
		port, err := strconv.ParseUint(f[1][colon+1:], 16, 32)
		if err != nil {
			continue
		}
		if _, ok := meshPorts[port]; ok {
			return true
		}
	}
	return false
}

// ContainerEnforceProvider adapts a ContainerTapProvider to the EnforceProvider
// interface: it returns an EnforceTarget for every eth0 target whose pod opted
// into inline enforcement (TapTarget.Enforce, set by the lister only when the
// agent enforce gate is on AND the pod carries the enforce label). The tap
// reconciler skips these same targets (taps.go reconcileOnce), so an Enforce
// workload is inline-ONLY — never both mirrored and NFQUEUE'd. Reuses the tap
// provider's container→veth resolution so there is a single source of truth.
//
// SAFETY: constructed by the agent ONLY when the enforce gate is on and the CNI
// is NFQUEUE-safe (see main.go selectEnforceProvider); nil otherwise, which
// leaves the whole inline path dormant (the default).
type ContainerEnforceProvider struct{ tap *ContainerTapProvider }

// NewContainerEnforceProvider wraps a ContainerTapProvider for the enforce path.
func NewContainerEnforceProvider(tap *ContainerTapProvider) *ContainerEnforceProvider {
	return &ContainerEnforceProvider{tap: tap}
}

// Desired returns the inline EnforceTargets: the Enforce-flagged eth0 taps. lo /
// proxymesh targets (PMAC set) are never enforced.
func (p *ContainerEnforceProvider) Desired(ctx context.Context) ([]EnforceTarget, error) {
	targets, err := p.tap.Desired(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]EnforceTarget, 0)
	for _, t := range targets {
		if t.Enforce && t.PMAC == "" && t.EPMAC != "" {
			// Carry the per-workload DPI opt-in onto the enforce path: an
			// inline-only workload is skipped by the tap reconciler, so this is
			// the only place its waf/dlp labels reach the DLP/WAF sync worker.
			out = append(out, EnforceTarget{NetNS: t.NetNS, Iface: t.Iface, EPMAC: t.EPMAC, WAF: t.WAF, DLP: t.DLP, Apps: t.Apps, PIPS: t.PIPS})
		}
	}
	return out, nil
}
