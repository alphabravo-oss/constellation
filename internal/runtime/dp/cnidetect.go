// Wave D1: CNI plugin detection.
//
// The runtime-agent uses this to decide which enforcement path is safe
// for the cluster it's running on. NeuVector's NFQUEUE plumbing assumes
// the iptables data plane that stock kube-proxy + Flannel / Calico
// provide; Cilium bypasses iptables in its default eBPF mode, so installing
// NFQUEUE rules there does nothing.
//
// Detection strategy mirrors what other agents do:
//
//   1. Walk /etc/cni/net.d/*.conf*. The filename and the JSON `type` field
//      uniquely identify every common CNI today.
//
//   2. Fall back to "unknown" if the directory is empty or unreadable.
//      The agent treats unknown as "stock iptables CNI" — safe default
//      since NFQUEUE on a Cilium cluster is a no-op, not a crash.
//
// The CNI string is reported once at startup + included in the heartbeat
// payload + emitted as a Prometheus gauge so operators can correlate
// enforcement behavior with detected platform.
package dp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CNIInfo is what the detector returns. Name is a stable identifier
// (flannel | calico | cilium | weave | aws-vpc | gke-cni | …); Source is
// the config file we matched on; Raw is the lower-cased plugin-type
// string when we have it.
type CNIInfo struct {
	Name   string `json:"name"`
	Source string `json:"source,omitempty"`
	Raw    string `json:"raw,omitempty"`
}

// CNI names we recognise. Stable strings; downstream code (Helm value
// gates, metrics, audit annotations) keys on these.
const (
	CNIUnknown  = "unknown"
	CNIFlannel  = "flannel"
	CNICalico   = "calico"
	CNICilium   = "cilium"
	CNIWeave    = "weave"
	CNIAWSVPC   = "aws-vpc"
	CNIGKE      = "gke-cni"
	CNIAzureCNI = "azure-cni"
	// CNIKindnet — kind's default CNI. Plugin type is "ptp" (point-to-point)
	// which is too generic to identify by content alone, so we match on
	// the filename pattern (10-kindnet.conflist) and the conflist's
	// `name: "kindnet"` field. Treated as iptables-compatible (NFQUEUE
	// works) since kindnet doesn't bypass iptables.
	CNIKindnet = "kindnet"
)

// CandidateCNIDirs lists the well-known CNI config locations across
// distributions in priority order. Mirrors NeuVector's approach: probe
// every known path so a single binary works on kubeadm/EKS/GKE/AKS and
// on k3s / RKE2 / OpenShift / microk8s without per-distro configuration.
//
// The first directory that contains at least one *.conf*/.json file wins.
// Override list with the explicit `dir` arg to DetectCNI for tests or for
// non-standard installs.
var CandidateCNIDirs = []string{
	"/etc/cni/net.d",                                  // kubeadm, EKS, GKE, AKS, kind, most upstream
	"/var/lib/rancher/k3s/agent/etc/cni/net.d",        // k3s
	"/var/lib/rancher/rke2/agent/etc/cni/net.d",       // RKE2
	"/etc/cni/multus/net.d",                           // OpenShift OVN-Kubernetes (multus delegates)
	"/etc/origin/openshift-sdn/net.d",                 // legacy OpenShift SDN
	"/var/snap/microk8s/current/args/cni-network",     // microk8s (snap)
	"/host/etc/cni/net.d",                             // when /etc is mounted under /host
}

// DetectCNI walks the well-known CNI config dirs (or the explicit override
// dir) and returns the best-effort identification. When called with an
// empty dir, it probes CandidateCNIDirs in order and uses the first one
// containing CNI configs. Multiple plugins coexist in some setups
// (eg. Cilium chaining Calico); we return the one that matters most for
// our enforcement decision: Cilium wins if present (because NFQUEUE is
// bypassed), otherwise the first match in the chosen dir.
func DetectCNI(dir string) CNIInfo {
	if dir != "" {
		return detectCNIInDir(dir)
	}
	for _, candidate := range CandidateCNIDirs {
		if !hasCNIConfig(candidate) {
			continue
		}
		info := detectCNIInDir(candidate)
		if info.Name != CNIUnknown {
			return info
		}
	}
	return CNIInfo{Name: CNIUnknown}
}

// hasCNIConfig is a cheap pre-check: does the dir exist AND contain at
// least one .conf/.conflist/.json file? Avoids reading misleading partial
// states (eg. a candidate path exists but is empty because that distro
// isn't installed).
func hasCNIConfig(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".conf") || strings.HasSuffix(n, ".conflist") || strings.HasSuffix(n, ".json") {
			return true
		}
	}
	return false
}

func detectCNIInDir(dir string) CNIInfo {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return CNIInfo{Name: CNIUnknown}
	}
	files := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".conf") || strings.HasSuffix(n, ".conflist") || strings.HasSuffix(n, ".json") {
			files = append(files, n)
		}
	}
	sort.Strings(files) // deterministic order
	var nonCiliumMatch CNIInfo
	for _, name := range files {
		info, ok := matchOne(filepath.Join(dir, name), name)
		if !ok {
			continue
		}
		// Cilium wins immediately because its eBPF policy plane bypasses
		// iptables NFQUEUE entirely — every other detection is moot for
		// our enforcement decision.
		if info.Name == CNICilium {
			return info
		}
		if nonCiliumMatch.Name == "" {
			nonCiliumMatch = info
		}
	}
	if nonCiliumMatch.Name != "" {
		return nonCiliumMatch
	}
	return CNIInfo{Name: CNIUnknown}
}

// matchOne reads a single CNI config and identifies the plugin. Cheap
// JSON parse: we only care about a couple of fields. We tolerate config
// errors (return ok=false) — a misformed conf file shouldn't fail
// detection for the whole agent.
func matchOne(path, name string) (CNIInfo, bool) {
	// Filename-based shortcut first — both for speed and because some
	// installers don't fully populate the type field on first run.
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "flannel"):
		return CNIInfo{Name: CNIFlannel, Source: name}, true
	case strings.Contains(lower, "calico"):
		return CNIInfo{Name: CNICalico, Source: name}, true
	case strings.Contains(lower, "cilium"):
		return CNIInfo{Name: CNICilium, Source: name}, true
	case strings.Contains(lower, "weave"):
		return CNIInfo{Name: CNIWeave, Source: name}, true
	case strings.Contains(lower, "kindnet"):
		return CNIInfo{Name: CNIKindnet, Source: name}, true
	case strings.Contains(lower, "aws-vpc-cni") || strings.Contains(lower, "aws-cni"):
		return CNIInfo{Name: CNIAWSVPC, Source: name}, true
	case strings.Contains(lower, "gke") || strings.Contains(lower, "gcp"):
		return CNIInfo{Name: CNIGKE, Source: name}, true
	case strings.Contains(lower, "azure"):
		return CNIInfo{Name: CNIAzureCNI, Source: name}, true
	}
	// Content-based fallback: parse the JSON, look at the top-level
	// "type" field or the plugins[].type chain for conflist files.
	b, err := os.ReadFile(path)
	if err != nil {
		return CNIInfo{}, false
	}
	types := pluginTypes(b)
	for _, t := range types {
		tl := strings.ToLower(t)
		for _, m := range []struct {
			needle string
			name   string
		}{
			{"cilium", CNICilium},
			{"calico", CNICalico},
			{"flannel", CNIFlannel},
			{"weave", CNIWeave},
			{"aws-vpc-cni", CNIAWSVPC},
			{"aws-cni", CNIAWSVPC},
			{"gke", CNIGKE},
			{"azure-cni", CNIAzureCNI},
		} {
			if strings.Contains(tl, m.needle) {
				return CNIInfo{Name: m.name, Source: name, Raw: tl}, true
			}
		}
	}
	// Last-ditch: kindnet's plugin type is the generic "ptp" but its
	// conflist's top-level `name` field is "kindnet". Match on that
	// before giving up — distinguishes kindnet from other ptp users.
	if topName := topLevelName(b); strings.ToLower(topName) == CNIKindnet {
		return CNIInfo{Name: CNIKindnet, Source: name, Raw: "ptp/kindnet"}, true
	}
	return CNIInfo{}, false
}

// topLevelName returns the conflist's `name` field — the human label
// (eg. "kindnet", "cbr0") that some CNIs use to distinguish themselves
// when their plugin type is generic. Returns empty on parse error.
func topLevelName(b []byte) string {
	var top struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		return ""
	}
	return top.Name
}

// pluginTypes returns every "type": "<x>" string found in the CNI config.
// Handles both single-plugin .conf (one type) and .conflist (plugins[]).
func pluginTypes(b []byte) []string {
	var top struct {
		Type    string `json:"type"`
		Plugins []struct {
			Type string `json:"type"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		return nil
	}
	out := make([]string, 0, 1+len(top.Plugins))
	if top.Type != "" {
		out = append(out, top.Type)
	}
	for _, p := range top.Plugins {
		if p.Type != "" {
			out = append(out, p.Type)
		}
	}
	return out
}

// SafeForNFQUEUE returns true when the detected CNI is one where our
// iptables NFQUEUE redirects actually take effect. False for Cilium (its
// eBPF datapath bypasses iptables). Used by main.go to decide whether
// to start the enforce manager.
func (i CNIInfo) SafeForNFQUEUE() bool {
	return i.Name != CNICilium
}
