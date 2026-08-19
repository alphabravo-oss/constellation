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
