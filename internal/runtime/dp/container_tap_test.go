package dp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"

)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func selfPID() int { return os.Getpid() }

// newTestProvider builds a ContainerTapProvider with the crictl lister and the
// setns-based MAC reader replaced by in-memory fakes, so the test never
// touches a real namespace.
func newTestProvider(
	containers []RunningContainer,
	listErr error,
	ifaces map[string]struct {
		iface string
		mac   string
		err   error
	},
	agentInode uint64,
) *ContainerTapProvider {
	p := &ContainerTapProvider{
		logger:          quietLogger(),
		procRoot:        "/proc",
		agentNetnsInode: agentInode,
		listContainers: func(ctx context.Context) ([]RunningContainer, error) {
			return containers, listErr
		},
		readIface: func(netnsPath string) (string, string, []string, error) {
			v, ok := ifaces[netnsPath]
			if !ok {
				return "", "", nil, errors.New("no iface fixture for " + netnsPath)
			}
			return v.iface, v.mac, nil, v.err
		},
	}
	// Override inode resolution for the host-net skip check via a package
	// indirection seam: the production code calls netnsInode directly, so for
	// the test we drive the skip purely through agentNetnsInode==0 (disabled)
	// unless the caller provides matching inodes. Tests that exercise the skip
	// path set agentNetnsInode and use netns paths whose real inode can't be
	// read (==0), so we instead assert skip via a dedicated test below using a
	// fake.
	return p
}

func ifaceFixture() map[string]struct {
	iface string
	mac   string
	err   error
} {
	return map[string]struct {
		iface string
		mac   string
		err   error
	}{}
}

func TestContainerTapDesiredHappyPath(t *testing.T) {
	containers := []RunningContainer{
		{ID: "a", PodName: "web", PID: 1000},
		{ID: "b", PodName: "db", PID: 2000},
	}
	fx := ifaceFixture()
	fx["/proc/1000/ns/net"] = struct {
		iface string
		mac   string
		err   error
	}{"eth0", "aa:bb:cc:00:00:01", nil}
	fx["/proc/2000/ns/net"] = struct {
		iface string
		mac   string
		err   error
	}{"eth0", "aa:bb:cc:00:00:02", nil}

	p := newTestProvider(containers, nil, fx, 0)
	got, err := p.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 targets, got %d: %+v", len(got), got)
	}
	// Sorted by netns path: /proc/1000 before /proc/2000.
	if got[0].NetNS != "/proc/1000/ns/net" || got[0].Iface != "eth0" || got[0].EPMAC != "aa:bb:cc:00:00:01" {
		t.Errorf("target0 wrong: %+v", got[0])
	}
	if got[1].NetNS != "/proc/2000/ns/net" || got[1].EPMAC != "aa:bb:cc:00:00:02" {
		t.Errorf("target1 wrong: %+v", got[1])
	}
}

func TestContainerTapSkipsBadIface(t *testing.T) {
	containers := []RunningContainer{
		{ID: "good", PID: 1000},
		{ID: "readerr", PID: 2000},
		{ID: "zeromac", PID: 3000},
		{ID: "emptyiface", PID: 4000},
	}
	fx := ifaceFixture()
	set := func(pid, iface, mac string, err error) {
		fx[pid] = struct {
			iface string
			mac   string
			err   error
		}{iface, mac, err}
	}
	set("/proc/1000/ns/net", "eth0", "aa:bb:cc:00:00:01", nil)
	set("/proc/2000/ns/net", "", "", errors.New("setns failed"))
	set("/proc/3000/ns/net", "eth0", "00:00:00:00:00:00", nil)
	set("/proc/4000/ns/net", "", "aa:bb:cc:00:00:04", nil)

	p := newTestProvider(containers, nil, fx, 0)
	got, err := p.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want only the good container, got %d: %+v", len(got), got)
	}
	if got[0].ID() != "/proc/1000/ns/net|eth0" {
		// key() is the dedup id; just sanity check the surviving entry.
		if got[0].NetNS != "/proc/1000/ns/net" {
			t.Errorf("survivor wrong: %+v", got[0])
		}
	}
}

// ID is a tiny shim so the test can reference key() without exporting it.
func (t TapTarget) ID() string { return t.key() }

func TestContainerTapDedupsSharedNetns(t *testing.T) {
	// Two containers in the same pod share one netns (same PID here for
	// simplicity of the fixture key). Should tap it exactly once.
	containers := []RunningContainer{
		{ID: "app", PodName: "p", PID: 1000},
		{ID: "sidecar", PodName: "p", PID: 1000},
	}
	fx := ifaceFixture()
	fx["/proc/1000/ns/net"] = struct {
		iface string
		mac   string
		err   error
	}{"eth0", "aa:bb:cc:00:00:01", nil}

	p := newTestProvider(containers, nil, fx, 0)
	got, err := p.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 deduped target, got %d: %+v", len(got), got)
	}
}

// TestContainerTapMultiNIC covers NET-46: a Multus / multi-CNI pod with two UP
// non-loopback interfaces must yield one TapTarget per NIC (both carrying the
// pod's identity), while a single-NIC pod still yields exactly one. It injects
// the readIfaces seam directly (the multi-NIC production path).
func TestContainerTapMultiNIC(t *testing.T) {
	const multiNS = "/proc/1000/ns/net"
	const singleNS = "/proc/2000/ns/net"
	ifaces := map[string][]netIface{
		multiNS: {
			{name: "eth0", mac: "aa:bb:cc:00:00:01", ips: []string{"10.1.0.5"}},
			{name: "net1", mac: "aa:bb:cc:00:00:99", ips: []string{"192.168.0.5"}},
		},
		singleNS: {
			{name: "eth0", mac: "aa:bb:cc:00:00:02", ips: []string{"10.1.0.6"}},
		},
	}
	p := &ContainerTapProvider{
		logger:   quietLogger(),
		procRoot: "/proc",
		listContainers: func(ctx context.Context) ([]RunningContainer, error) {
			return []RunningContainer{
				{ID: "multi", PodName: "mpod", Namespace: "ns", Labels: map[string]string{"app": "m"}, PID: 1000},
				{ID: "single", PodName: "spod", Namespace: "ns", PID: 2000},
			}, nil
		},
		readIfaces: func(netns string) ([]netIface, error) {
			v, ok := ifaces[netns]
			if !ok {
				return nil, errors.New("no fixture for " + netns)
			}
			return v, nil
		},
	}

	got, err := p.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	// 2 NICs for the multi pod + 1 for the single pod = 3 targets.
	if len(got) != 3 {
		t.Fatalf("want 3 targets (2 for multi-NIC pod + 1), got %d: %+v", len(got), got)
	}

	byKey := map[string]TapTarget{}
	for _, tt := range got {
		byKey[tt.NetNS+"|"+tt.Iface] = tt
	}
	eth0, ok := byKey[multiNS+"|eth0"]
	if !ok {
		t.Fatalf("missing multi-NIC pod eth0 target: %+v", got)
	}
	net1, ok := byKey[multiNS+"|net1"]
	if !ok {
		t.Fatalf("missing multi-NIC pod net1 (second NIC) target: %+v", got)
	}
	// Primary keeps its own canonical MAC/IP; secondary keeps its own.
	if eth0.EPMAC != "aa:bb:cc:00:00:01" || len(eth0.PIPS) != 1 || eth0.PIPS[0] != "10.1.0.5" {
		t.Errorf("primary NIC MAC/IP wrong: %+v", eth0)
	}
	if net1.EPMAC != "aa:bb:cc:00:00:99" || len(net1.PIPS) != 1 || net1.PIPS[0] != "192.168.0.5" {
		t.Errorf("secondary NIC MAC/IP wrong: %+v", net1)
	}
	// Pod identity is carried onto EVERY NIC's target.
	for _, tt := range []TapTarget{eth0, net1} {
		if tt.PodName != "mpod" || tt.Namespace != "ns" || tt.Labels["app"] != "m" {
			t.Errorf("NIC %s missing pod identity: %+v", tt.Iface, tt)
		}
	}

	// Single-NIC pod yields exactly one target.
	single := 0
	for _, tt := range got {
		if tt.NetNS == singleNS {
			single++
		}
	}
	if single != 1 {
		t.Fatalf("single-NIC pod must yield exactly one target, got %d", single)
	}
}

// TestAllInterfacesExcludesLoopback checks that the in-netns reader never
// returns the loopback interface (it filters FlagLoopback). Runs against the
// test process's own netns; skipped where there is no usable non-loopback NIC.
func TestAllInterfacesExcludesLoopback(t *testing.T) {
	ifaces, err := allInterfaces()
	if err != nil {
		t.Skipf("no up non-loopback interface in this environment: %v", err)
	}
	for _, ni := range ifaces {
		if ni.name == "lo" {
			t.Fatalf("loopback must be excluded, got %+v", ni)
		}
		for _, ip := range ni.ips {
			if ip == "127.0.0.1" {
				t.Fatalf("loopback address must be excluded, got %+v", ni)
			}
		}
	}
}

func TestContainerTapListError(t *testing.T) {
	p := newTestProvider(nil, errors.New("no CRI socket"), ifaceFixture(), 0)
	if _, err := p.Desired(context.Background()); err == nil {
		t.Fatal("want error when lister fails")
	}
}

func TestContainerTapSkipsHostNetwork(t *testing.T) {
	// Host-network skip: when a container's netns inode equals the agent's
	// netns inode, it's skipped. We exercise this through netnsInode on a
	// real path: both the agent inode and the container netns path point at
	// /proc/self/ns/net, so the inode matches and the entry is dropped.
	self := "/proc/self/ns/net"
	agentInode := netnsInode(self)
	if agentInode == 0 {
		t.Skip("cannot read /proc/self/ns/net inode in this environment")
	}
	p := &ContainerTapProvider{
		logger:          quietLogger(),
		procRoot:        "/proc",
		agentNetnsInode: agentInode,
		listContainers: func(ctx context.Context) ([]RunningContainer, error) {
			// PID "self" so netnsPath -> /proc/self/ns/net == agent netns.
			return []RunningContainer{{ID: "hostnet", PID: selfPID()}}, nil
		},
		readIface: func(netnsPath string) (string, string, []string, error) {
			t.Fatalf("readIface must not be called for a host-network container (netns=%s)", netnsPath)
			return "", "", nil, nil
		},
	}
	got, err := p.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("host-network container should be skipped, got %d: %+v", len(got), got)
	}
}
