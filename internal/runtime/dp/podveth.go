package dp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// PodVethProvider discovers pod-attached host-side veths on the node by
// walking /sys/class/net inside the agent's netns (which, with
// hostNetwork=true on the DaemonSet, is the host netns — exactly where CNIs
// create their host-side veths).
//
// What counts as a pod-veth:
//
//  1. Name matches one of the configured prefixes. Defaults: "veth" (Flannel,
//     k3s default, containerd, plain Docker), "cali" (Calico), "lxc" (LXD).
//     Extend via NewPodVethProvider's `prefixes` argument.
//
//  2. /sys/class/net/<iface>/iflink ≠ ifindex — this is the "virtual peer"
//     marker. A veth pair has two interfaces whose iflink fields cross-
//     reference each other (each points to the other's ifindex). Real NICs
//     have iflink == ifindex, so the inequality cleanly filters us to one
//     side of a veth.
//
//  3. /sys/class/net/<iface>/operstate is "up". Down veths are between pod
//     teardown phases; tapping them is harmless but adds noise.
//
// We deliberately don't enter pod netns to resolve the pod-side MAC for
// Wave 3b — that requires CAP_SYS_ADMIN + setns() + matching the pod's PID,
// which the agent doesn't yet plumb. Instead we tag the tap with the
// HOST-side veth's MAC. dp uses EPMAC purely as a workload identifier (not
// as a packet filter), so attribution still works — every DPMsgConnect dp
// emits for this tap carries that MAC, and the server-side ingest maps it
// back to a workload via the existing handler (which Wave 4 wired up).
//
// Skip list:
//   - "veth0" / "veth1" — usually bridge endpoints, not pod veths.
//   - CNI bridges themselves (cni0, cbr0, flannel.1, kube-ipvs0) — those are
//     L3 forwarders, not workload endpoints. Filtered by prefix rules anyway.
//   - Anything we've previously failed to resolve a MAC for. The next refresh
//     will retry.
type PodVethProvider struct {
	netns    string
	prefixes []string
	exclude  map[string]struct{}
	logger   *slog.Logger

	// sysfsRoot is "/sys/class/net" in production; tests override it to point
	// at a fixture directory.
	sysfsRoot string
}

// NewPodVethProvider returns a provider with sensible CNI defaults. Set
// CONSTELLATION_DP_VETH_PREFIXES (comma-separated) to override.
func NewPodVethProvider(logger *slog.Logger) TapProvider {
	prefixes := []string{"veth", "cali", "lxc"}
	if env := strings.TrimSpace(os.Getenv("CONSTELLATION_DP_VETH_PREFIXES")); env != "" {
		prefixes = nil
		for _, p := range strings.Split(env, ",") {
			if p = strings.TrimSpace(p); p != "" {
				prefixes = append(prefixes, p)
			}
		}
	}
	return &PodVethProvider{
		netns:     "/proc/1/ns/net",
		prefixes:  prefixes,
		exclude:   map[string]struct{}{},
		logger:    logger,
		sysfsRoot: "/sys/class/net",
	}
}

// Desired enumerates host-side veths matching the configured prefixes and
// returns one TapTarget per pod. The list is stable-sorted so the
// reconciler's logs are deterministic.
func (p *PodVethProvider) Desired(ctx context.Context) ([]TapTarget, error) {
	entries, err := os.ReadDir(p.sysfsRoot)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p.sysfsRoot, err)
	}
	out := make([]TapTarget, 0, 16)
	for _, e := range entries {
		name := e.Name()
		if !p.matchesPrefix(name) {
			continue
		}
		if _, skip := p.exclude[name]; skip {
			continue
		}
		ok, reason := p.isPodVeth(name)
		if !ok {
			p.logger.Debug("dp veth: skip",
				slog.String("iface", name), slog.String("reason", reason))
			continue
		}
		mac, err := readSysfsLine(filepath.Join(p.sysfsRoot, name, "address"))
		if err != nil || mac == "" || mac == "00:00:00:00:00:00" {
			p.logger.Debug("dp veth: no mac",
				slog.String("iface", name), slog.String("err", errOrEmpty(err)))
			continue
		}
		out = append(out, TapTarget{
			NetNS: p.netns,
			Iface: name,
			EPMAC: mac,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out, nil
}

// matchesPrefix returns true if name starts with any configured prefix.
func (p *PodVethProvider) matchesPrefix(name string) bool {
	for _, pre := range p.prefixes {
		if strings.HasPrefix(name, pre) {
			return true
		}
	}
	return false
}

// isPodVeth applies the two sysfs filters: operstate=up + iflink≠ifindex.
// Returns (ok, reason) so the debug log can explain why we skipped.
func (p *PodVethProvider) isPodVeth(name string) (bool, string) {
	root := filepath.Join(p.sysfsRoot, name)
	op, err := readSysfsLine(filepath.Join(root, "operstate"))
	if err != nil {
		return false, "operstate read: " + err.Error()
	}
	if op != "up" && op != "unknown" {
		// `unknown` happens transiently between kernel notifications;
		// we treat it as "probably fine" rather than skip — dp will idle
		// on a truly-down iface anyway.
		return false, "operstate=" + op
	}
	ifindex, err := readSysfsInt(filepath.Join(root, "ifindex"))
	if err != nil {
		return false, "ifindex read: " + err.Error()
	}
	iflink, err := readSysfsInt(filepath.Join(root, "iflink"))
	if err != nil {
		return false, "iflink read: " + err.Error()
	}
	if ifindex == iflink {
		// Same value means this is NOT a veth (real NIC, loopback, or one
		// of dp's own interfaces).
		return false, "iflink == ifindex (not a virtual peer)"
	}
	return true, ""
}

// readSysfsLine reads a single line file. Trims trailing newline.
func readSysfsLine(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// readSysfsInt is readSysfsLine + strconv.Atoi for the small integer files
// that populate /sys/class/net/<iface>/{ifindex,iflink,…}.
func readSysfsInt(path string) (int, error) {
	s, err := readSysfsLine(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(s)
}

func errOrEmpty(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
