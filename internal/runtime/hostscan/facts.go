// Package hostscan collects per-node host facts that the runtime-agent
// posts to the control plane.
//
// The shape of Facts is what /api/v1/host-facts:report accepts and what
// the host_facts.facts JSON column stores. Designed to mirror the
// information NeuVector's enforcer ships in share/system/system_linux.go
// (kernel / distro / cgroups / modules / CNI / CRI), plus the BTF and
// nfqueue-safe bits constellation needs for its eBPF + NFQUEUE path.
//
// All probes are best-effort: a single missing file or unreadable
// directory must NOT abort the snapshot. Fields default to their zero
// value when the probe can't answer.
package hostscan

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// Facts is the snapshot the agent uploads. JSON tags are the wire shape
// (snake_case, matching the rest of the API).
type Facts struct {
	Node         string    `json:"node"`
	ObservedAt   time.Time `json:"observed_at"`
	AgentVersion string    `json:"agent_version,omitempty"`

	OS     OSInfo     `json:"os"`
	Kernel KernelInfo `json:"kernel"`
	CGroup CGroupInfo `json:"cgroup"`
	BPF    BPFInfo    `json:"bpf"`
	Net    NetInfo    `json:"net"`
	CNI    CNIInfo    `json:"cni"`
	CRI    CRIInfo    `json:"cri"`

	// Capabilities visible to the agent process (effective set).
	Capabilities []string `json:"capabilities,omitempty"`

	// Container runtime sockets observed on the host (whether or not
	// they responded — full socket-talk happens in the container
	// inventory collector, Slice C). Useful as a discovery signal.
	CRISockets []string `json:"cri_sockets,omitempty"`
}

type OSInfo struct {
	ID         string `json:"id,omitempty"`      // os-release ID
	IDLike     string `json:"id_like,omitempty"` // os-release ID_LIKE
	Name       string `json:"name,omitempty"`    // os-release NAME
	PrettyName string `json:"pretty_name,omitempty"`
	Version    string `json:"version,omitempty"`    // os-release VERSION
	VersionID  string `json:"version_id,omitempty"` // os-release VERSION_ID
}

type KernelInfo struct {
	Release string `json:"release,omitempty"` // uname -r
	Version string `json:"version,omitempty"` // uname -v (build string)
	Arch    string `json:"arch,omitempty"`    // uname -m
	// Subset of /proc/modules: names of loaded modules that matter for
	// our enforcement / observability paths.
	LoadedModules []string `json:"loaded_modules,omitempty"`
	// Names of relevant modules available on disk under
	// /lib/modules/$release/, even if not currently loaded — they can
	// be brought up by modprobe at runtime.
	AvailableModules []string `json:"available_modules,omitempty"`
}

type CGroupInfo struct {
	Version int    `json:"version"` // 1 | 2 | 0=unknown
	Unified bool   `json:"unified,omitempty"`
	Path    string `json:"path,omitempty"` // mount point
}

type BPFInfo struct {
	FSMounted     bool   `json:"fs_mounted"`  // /sys/fs/bpf is a real bpf FS
	BTFPresent    bool   `json:"btf_present"` // /sys/kernel/btf/vmlinux readable
	BTFPath       string `json:"btf_path,omitempty"`
	HelperVersion string `json:"helper_version,omitempty"` // /proc/sys/kernel/bpf_stats_enabled etc.
}

type NetInfo struct {
	NFQueueLoaded   bool `json:"nfqueue_loaded"`   // xt_NFQUEUE or nfnetlink_queue in /proc/modules
	NFQueueOnDisk   bool `json:"nfqueue_on_disk"`  // module file present under /lib/modules
	NetfilterDir    bool `json:"netfilter_dir"`    // /proc/net/netfilter exists
	IPTablesNFQueue bool `json:"iptables_nfqueue"` // userspace iptables binary advertises NFQUEUE
}

type CNIInfo struct {
	Name        string `json:"name,omitempty"`   // 'cilium' | 'calico' | …
	Source      string `json:"source,omitempty"` // file the detector matched
	NFQueueSafe bool   `json:"nfqueue_safe"`     // detector verdict
}

type CRIInfo struct {
	Runtime string `json:"runtime,omitempty"` // 'containerd' | 'docker' | 'crio' | ''
	Socket  string `json:"socket,omitempty"`  // first matching socket path
	Version string `json:"version,omitempty"` // optional, may need socket talk
}

// Options controls the collector.
//
// Path prefix rules:
//   - /proc and /sys are read at their natural mount points in the
//     container; the chart already mounts /sys directly and /proc at
//     /host/proc, but the agent runs with hostPID so the kernel's
//     auto-mounted /proc inside the container is *also* the host's
//     view of /proc. So natural paths "just work".
//   - /etc/os-release, /lib/modules, /run, /var/run aren't part of
//     the runtime-agent's container image at the host's values; the
//     chart bind-mounts them under HostRoot (default /host) so the
//     collector reads them at HostRoot+path.
type Options struct {
	// HostRoot is the prefix where the chart bind-mounts host
	// directories that aren't otherwise present in the agent's
	// container rootfs (/etc, /lib/modules, /run, /var/run). Empty
	// means "read those paths directly" — useful in tests.
	HostRoot string

	// NodeName overrides $HOSTNAME / $CONSTELLATION_NODE_NAME.
	NodeName string

	// CNIDir, if set, pins CNI auto-discovery to a single directory.
	// Empty triggers full auto-discovery via dp.CandidateCNIDirs.
	CNIDir string

	// AgentVersion is stamped into every snapshot for UI display.
	AgentVersion string
}

// hostPath returns p prefixed by HostRoot when HostRoot is set. Used
// for paths the chart bind-mounts under /host (os-release, lib/modules,
// run sockets). /proc and /sys must NOT use this — they use natural
// paths in-container, see the type doc above.
func (o Options) hostPath(p string) string {
	if o.HostRoot == "" {
		return p
	}
	return filepath.Join(o.HostRoot, p)
}

// Modules we care about specifically. A loaded entry in this set is
// surfaced in Kernel.LoadedModules; an available entry on disk shows
// up in Kernel.AvailableModules. Anything outside this set is dropped
// to keep the payload small.
var modulesOfInterest = map[string]struct{}{
	"xt_NFQUEUE":      {},
	"nfnetlink_queue": {},
	"nfnetlink":       {},
	"bpf":             {},
	"overlay":         {},
	"br_netfilter":    {},
	"nf_tables":       {},
	"ip_tables":       {},
	"iptable_nat":     {},
	"xt_conntrack":    {},
}

// candidateCRISockets is checked in order; first existing socket wins.
// The names are also surfaced in Facts.CRISockets so the UI shows what
// runtimes were detected even if none became the primary.
//
// IMPORTANT: distro-specific paths come BEFORE the generic ones. k3s
// installs its own containerd at /run/k3s/containerd/containerd.sock
// AND leaves the host's stock /run/containerd/containerd.sock in
// place; if the generic path is checked first we end up talking to
// the empty stock containerd that has no Kubernetes containers in it.
// Same logic for cri-o paths and rke2.
var candidateCRISockets = []struct {
	Path    string
	Runtime string
}{
	// k3s embeds containerd at a non-standard path. Check first so we
	// don't get fooled by an empty stock containerd on the host.
	{Path: "/run/k3s/containerd/containerd.sock", Runtime: "containerd"},
	// rke2 same pattern.
	{Path: "/run/k3s/containerd/containerd.sock", Runtime: "containerd"},
	{Path: "/var/run/rke2/containerd/containerd.sock", Runtime: "containerd"},
	// Stock containerd (kubeadm, microk8s with containerd, kind).
	{Path: "/run/containerd/containerd.sock", Runtime: "containerd"},
	{Path: "/var/run/crio/crio.sock", Runtime: "crio"},
	{Path: "/run/crio/crio.sock", Runtime: "crio"},
	{Path: "/var/run/docker.sock", Runtime: "docker"},
	{Path: "/run/docker.sock", Runtime: "docker"},
}

// Collect runs every probe and returns a Facts snapshot. Never returns
// an error: best-effort by design. ctx is reserved for future subprocess
// probes (none today).
func Collect(ctx context.Context, opts Options) Facts {
	_ = ctx
	f := Facts{
		Node:         opts.NodeName,
		ObservedAt:   time.Now().UTC(),
		AgentVersion: opts.AgentVersion,
	}
	if f.Node == "" {
		if h, _ := os.Hostname(); h != "" {
			f.Node = h
		} else {
			f.Node = "unknown"
		}
	}

	f.OS = collectOS(opts)
	f.Kernel = collectKernel(opts)
	f.CGroup = collectCGroup()
	f.BPF = collectBPF()
	f.Net = collectNet(&f.Kernel)
	f.CNI = collectCNI(opts.CNIDir)
	f.CRI, f.CRISockets = collectCRI(opts)
	f.Capabilities = collectCapabilities()

	return f
}

// ---------------------------------------------------------------------------
// OS / kernel
// ---------------------------------------------------------------------------

func collectOS(opts Options) OSInfo {
	var o OSInfo
	// /etc/os-release on most distros is a symlink to ../usr/lib/os-release.
	// Inside the agent pod, /host/etc is bind-mounted but /usr is not, so
	// the symlink target resolves to a non-existent /host/usr/lib path.
	// /proc/1/root is the host's view (hostPID=true) and crosses the
	// symlink correctly without needing /usr to be bind-mounted. When
	// HostRoot is explicit, prefer it first so tests and alternate
	// deployments cannot accidentally read the runner/container OS. The
	// chart's /host mount keeps the /proc/1/root fallback because
	// /host/etc/os-release may be a symlink to /usr/lib/os-release, while
	// only /host/etc is mounted.
	candidates := []string{
		"/proc/1/root/etc/os-release",
		"/proc/1/root/usr/lib/os-release",
		opts.hostPath("/etc/os-release"),
		opts.hostPath("/usr/lib/os-release"),
	}
	if hostRoot := strings.TrimSpace(opts.HostRoot); hostRoot != "" {
		candidates = []string{
			opts.hostPath("/etc/os-release"),
			opts.hostPath("/usr/lib/os-release"),
		}
		if filepath.Clean(hostRoot) == "/host" {
			candidates = append(candidates,
				"/proc/1/root/etc/os-release",
				"/proc/1/root/usr/lib/os-release",
			)
		}
	}
	for _, candidate := range candidates {
		kv, ok := readKeyValueFile(candidate)
		if !ok {
			continue
		}
		o.ID = kv["ID"]
		o.IDLike = kv["ID_LIKE"]
		o.Name = kv["NAME"]
		o.PrettyName = kv["PRETTY_NAME"]
		o.Version = kv["VERSION"]
		o.VersionID = kv["VERSION_ID"]
		break
	}
	return o
}

func collectKernel(opts Options) KernelInfo {
	var k KernelInfo
	var u unix.Utsname
	if err := unix.Uname(&u); err == nil {
		k.Release = nulTrim(u.Release[:])
		k.Version = nulTrim(u.Version[:])
		k.Arch = nulTrim(u.Machine[:])
	}
	// /proc/version: container's procfs (host pids via hostPID) — natural path.
	if k.Version == "" {
		if b, err := os.ReadFile("/proc/version"); err == nil {
			k.Version = strings.TrimSpace(string(b))
		}
	}
	// /proc/modules — loaded modules of interest. Natural path (procfs).
	if b, err := os.ReadFile("/proc/modules"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			name, _, ok := strings.Cut(line, " ")
			if !ok {
				continue
			}
			if _, want := modulesOfInterest[name]; want {
				k.LoadedModules = append(k.LoadedModules, name)
			}
		}
	}
	// /lib/modules/$release/kernel/net/netfilter — available-on-disk
	// modules of interest. Bind-mounted by the chart under HostRoot.
	if k.Release != "" {
		base := filepath.Join(opts.hostPath("/lib/modules"), k.Release, "kernel/net/netfilter")
		if entries, err := os.ReadDir(base); err == nil {
			for _, e := range entries {
				name := e.Name()
				name = strings.TrimSuffix(name, ".zst")
				name = strings.TrimSuffix(name, ".xz")
				name = strings.TrimSuffix(name, ".ko")
				if _, want := modulesOfInterest[name]; want {
					k.AvailableModules = append(k.AvailableModules, name)
				}
			}
		}
	}
	return k
}

// ---------------------------------------------------------------------------
// cgroup / BPF / net
// ---------------------------------------------------------------------------

// /sys mounts are at natural paths in the agent container (the chart
// mounts host /sys at /sys); no HostRoot prefix.

func collectCGroup() CGroupInfo {
	var c CGroupInfo
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		c.Version = 2
		c.Unified = true
		c.Path = "/sys/fs/cgroup"
		return c
	}
	if _, err := os.Stat("/sys/fs/cgroup/cpu"); err == nil {
		c.Version = 1
		c.Path = "/sys/fs/cgroup"
		return c
	}
	return c
}

func collectBPF() BPFInfo {
	var b BPFInfo
	const btfPath = "/sys/kernel/btf/vmlinux"
	if st, err := os.Stat(btfPath); err == nil && st.Size() > 0 {
		b.BTFPresent = true
		b.BTFPath = btfPath
	}
	var stfs syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/bpf", &stfs); err == nil {
		// BPF_FS_MAGIC = 0xCAFE4A11. Literal because the syscall pkg
		// doesn't export it on all architectures.
		const bpfFSMagic int64 = 0xCAFE4A11
		if int64(stfs.Type) == bpfFSMagic {
			b.FSMounted = true
		}
	}
	return b
}

func collectNet(k *KernelInfo) NetInfo {
	var n NetInfo
	for _, m := range k.LoadedModules {
		if m == "xt_NFQUEUE" || m == "nfnetlink_queue" {
			n.NFQueueLoaded = true
			break
		}
	}
	for _, m := range k.AvailableModules {
		if m == "xt_NFQUEUE" || m == "nfnetlink_queue" {
			n.NFQueueOnDisk = true
			break
		}
	}
	if _, err := os.Stat("/proc/net/netfilter"); err == nil {
		n.NetfilterDir = true
	}
	// iptables -j NFQUEUE -h is the userspace-side probe. We don't run
	// it under hostscan in the agent pod — the agent's container image
	// may not ship iptables, and we already capture the kernel-side
	// signal above. The control-plane can derive iptables_nfqueue from
	// (nfqueue_loaded || nfqueue_on_disk) && netfilter_dir.
	n.IPTablesNFQueue = (n.NFQueueLoaded || n.NFQueueOnDisk) && n.NetfilterDir
	return n
}

// ---------------------------------------------------------------------------
// CNI / CRI / caps
// ---------------------------------------------------------------------------

func collectCNI(cniDir string) CNIInfo {
	c := dp.DetectCNI(cniDir)
	return CNIInfo{
		Name:        c.Name,
		Source:      c.Source,
		NFQueueSafe: c.SafeForNFQUEUE(),
	}
}

func collectCRI(opts Options) (CRIInfo, []string) {
	var primary CRIInfo
	var all []string
	for _, c := range candidateCRISockets {
		path := opts.hostPath(c.Path)
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		if st.Mode()&os.ModeSocket == 0 {
			continue
		}
		all = append(all, c.Path)
		if primary.Runtime == "" {
			primary.Runtime = c.Runtime
			primary.Socket = c.Path
		}
	}
	return primary, all
}

func collectCapabilities() []string {
	// /proc/self/status CapEff is a 16-hex-char bitfield. Cheap parse;
	// we map only the bits we use in the chart so the payload is small
	// and the UI rendering is stable. (No cgo, no libcap dep.)
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		bits, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			return nil
		}
		return decodeCaps(bits)
	}
	return nil
}

// Subset of <linux/capability.h>. The full list is 41 caps as of 6.8;
// we surface the ones the runtime-agent actually needs so the UI can
// flag a missing one. Add others as they become operationally relevant.
var capNames = map[uint]string{
	7:  "NET_BIND_SERVICE",
	12: "NET_ADMIN",
	13: "NET_RAW",
	14: "IPC_LOCK",
	19: "SYS_PTRACE",
	21: "SYS_ADMIN",
	22: "SYS_BOOT",
	28: "AUDIT_WRITE",
	38: "PERFMON",
	39: "BPF",
}

func decodeCaps(bits uint64) []string {
	var out []string
	for bit, name := range capNames {
		if bits&(1<<bit) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// nulTrim returns the bytes of a Utsname field up to the first NUL.
// unix.Utsname declares the fields as [65]byte across architectures.
func nulTrim(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

// readKeyValueFile parses simple KEY=value files (os-release style).
// Values may be quoted; quotes are stripped.
func readKeyValueFile(path string) (map[string]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		out[k] = v
	}
	return out, true
}
