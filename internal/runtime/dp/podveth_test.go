package dp

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// fakeSysfs builds a tree under tempDir that looks like /sys/class/net for
// the test cases below. Each spec creates one iface dir with files:
//
//	address    — MAC string ("aa:bb:cc:dd:ee:ff")
//	operstate  — "up" / "down"
//	ifindex    — integer
//	iflink     — integer (≠ ifindex marks a veth peer)
type ifaceSpec struct {
	name      string
	mac       string
	operstate string
	ifindex   int
	iflink    int
}

func writeIface(t *testing.T, root string, s ifaceSpec) {
	t.Helper()
	dir := filepath.Join(root, s.name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("address", s.mac)
	write("operstate", s.operstate)
	write("ifindex", itoa10(s.ifindex))
	write("iflink", itoa10(s.iflink))
}

// itoa10 — small helper so we don't import strconv just for this.
func itoa10(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// newSilentLogger returns a slog.Logger that discards output, so tests don't
// spam the test runner with the provider's debug lines.
func newSilentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestPodVethProvider_FiltersCorrectly verifies the three rules in concert:
// (1) prefix match (veth/cali/lxc) (2) operstate up (3) iflink != ifindex.
func TestPodVethProvider_FiltersCorrectly(t *testing.T) {
	root := t.TempDir()
	writeIface(t, root, ifaceSpec{
		name: "eth0", mac: "11:22:33:44:55:66", // real NIC: not a veth prefix → filtered
		operstate: "up", ifindex: 2, iflink: 2,
	})
	writeIface(t, root, ifaceSpec{
		name: "veth-up-pod", mac: "aa:aa:aa:aa:aa:01", // qualifies
		operstate: "up", ifindex: 100, iflink: 99,
	})
	writeIface(t, root, ifaceSpec{
		name: "veth-down-pod", mac: "aa:aa:aa:aa:aa:02", // down → skip
		operstate: "down", ifindex: 101, iflink: 98,
	})
	writeIface(t, root, ifaceSpec{
		name: "veth-not-veth", mac: "aa:aa:aa:aa:aa:03", // iflink == ifindex → skip
		operstate: "up", ifindex: 102, iflink: 102,
	})
	writeIface(t, root, ifaceSpec{
		name: "cali12345", mac: "aa:aa:aa:aa:aa:04", // calico prefix
		operstate: "up", ifindex: 200, iflink: 201,
	})
	writeIface(t, root, ifaceSpec{
		name: "lxc-pod-3", mac: "aa:aa:aa:aa:aa:05", // lxc prefix
		operstate: "up", ifindex: 300, iflink: 301,
	})
	writeIface(t, root, ifaceSpec{
		name: "veth-zero-mac", mac: "00:00:00:00:00:00", // zero mac → skip
		operstate: "up", ifindex: 400, iflink: 401,
	})

	p := &PodVethProvider{
		netns:     "/proc/1/ns/net",
		prefixes:  []string{"veth", "cali", "lxc"},
		exclude:   map[string]struct{}{},
		logger:    newSilentLogger(),
		sysfsRoot: root,
	}
	got, err := p.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	gotNames := make([]string, 0, len(got))
	for _, t := range got {
		gotNames = append(gotNames, t.Iface)
	}
	want := []string{"cali12345", "lxc-pod-3", "veth-up-pod"}
	if len(gotNames) != len(want) {
		t.Fatalf("got ifaces %v, want %v", gotNames, want)
	}
	for i, w := range want {
		if gotNames[i] != w {
			t.Errorf("got[%d]=%q want %q", i, gotNames[i], w)
		}
	}
	// Verify EPMAC came through.
	for _, target := range got {
		if target.EPMAC == "" {
			t.Errorf("target %s has empty EPMAC", target.Iface)
		}
		if target.NetNS != "/proc/1/ns/net" {
			t.Errorf("target %s netns=%q want /proc/1/ns/net", target.Iface, target.NetNS)
		}
	}
}

// TestPodVethProvider_Exclude verifies the per-name exclude map.
func TestPodVethProvider_Exclude(t *testing.T) {
	root := t.TempDir()
	writeIface(t, root, ifaceSpec{name: "veth-keep", mac: "aa:aa:aa:aa:aa:01", operstate: "up", ifindex: 100, iflink: 99})
	writeIface(t, root, ifaceSpec{name: "veth-skip", mac: "aa:aa:aa:aa:aa:02", operstate: "up", ifindex: 101, iflink: 102})
	p := &PodVethProvider{
		netns: "/proc/1/ns/net", prefixes: []string{"veth"},
		exclude: map[string]struct{}{"veth-skip": {}},
		logger:  newSilentLogger(), sysfsRoot: root,
	}
	got, err := p.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Iface != "veth-keep" {
		t.Fatalf("got %+v, want only veth-keep", got)
	}
}

// TestPodVethProvider_UnknownOperstateOK confirms operstate="unknown" is
// treated as keep — kernel reports this transiently on freshly-created
// veths; a strict "must be up" filter loses pod startup observability.
func TestPodVethProvider_UnknownOperstateOK(t *testing.T) {
	root := t.TempDir()
	writeIface(t, root, ifaceSpec{name: "veth-fresh", mac: "aa:aa:aa:aa:aa:01", operstate: "unknown", ifindex: 100, iflink: 99})
	p := &PodVethProvider{netns: "", prefixes: []string{"veth"}, exclude: map[string]struct{}{}, logger: newSilentLogger(), sysfsRoot: root}
	got, err := p.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d ifaces, want 1", len(got))
	}
}
