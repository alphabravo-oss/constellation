package dp

import (
	"context"
	"testing"
)

// TestMeshLoTapAttributesToApp asserts that when the (default-off) mesh lo-tap
// flag is set and a pod is detected as meshed, Desired() emits an extra "lo"
// TapTarget in that pod's netns carrying the app container's (pod eth0) EPMAC —
// so a synthesized loopback flow attributes to the app, not the sidecar. It
// also checks the flag gate and the /proc/net/tcp mesh-port parser.
func TestMeshLoTapAttributesToApp(t *testing.T) {
	t.Setenv("CONSTELLATION_MESH_LO_TAP", "1")

	const netns = "/proc/1000/ns/net"
	const appMAC = "aa:bb:cc:00:00:01"
	p := &ContainerTapProvider{
		logger:   quietLogger(),
		procRoot: "/proc",
		listContainers: func(ctx context.Context) ([]RunningContainer, error) {
			// One pod, two containers sharing the netns: the app and its sidecar.
			return []RunningContainer{
				{ID: "app", PodName: "meshed", PID: 1000},
				{ID: "istio-proxy", PodName: "meshed", PID: 1000},
			}, nil
		},
		readIface:  func(string) (string, string, []string, error) { return "eth0", appMAC, []string{"10.1.2.3"}, nil },
		meshDetect: func(pid int) bool { return pid == 1000 },
	}

	got, err := p.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	var lo *TapTarget
	var haveEth0 bool
	for i := range got {
		switch got[i].Iface {
		case "lo":
			lo = &got[i]
		case "eth0":
			haveEth0 = true
		}
	}
	if !haveEth0 {
		t.Fatalf("north-south eth0 tap missing: %+v", got)
	}
	if lo == nil {
		t.Fatalf("no lo tap emitted for meshed pod: %+v", got)
	}
	// dp only attributes all-zero-L2-MAC loopback packets via its proxymesh
	// branch, which fires ONLY when the tap's EP MAC carries the "lkst" prefix
	// (dpi_entry.c:493). So the lo tap's EPMAC must be the synthetic proxymesh
	// MAC (lkst + the low two octets of the real eth0 MAC), NOT the eth0 MAC
	// itself — which would make dp drop every loopback packet. The real eth0
	// MAC rides in PMAC so the flow still attributes to the app container.
	wantEP := proxyMeshMAC(appMAC)
	if lo.NetNS != netns || lo.EPMAC != wantEP {
		t.Fatalf("lo tap EPMAC not the proxymesh identity: got netns=%s epmac=%s want netns=%s epmac=%s",
			lo.NetNS, lo.EPMAC, netns, wantEP)
	}
	if lo.EPMAC == appMAC {
		t.Fatalf("lo EPMAC must NOT be the real eth0 MAC (dp would drop all lo packets)")
	}
	if lo.PMAC != appMAC {
		t.Fatalf("lo PMAC must carry the real eth0 MAC for app attribution: got %q want %q", lo.PMAC, appMAC)
	}
	// PIPS carries the pod's eth0 IPs + loopback so dp can xff-match 127.0.0.x.
	var haveEth0IP, haveLoopback bool
	for _, ip := range lo.PIPS {
		switch ip {
		case "10.1.2.3":
			haveEth0IP = true
		case "127.0.0.1":
			haveLoopback = true
		}
	}
	if !haveEth0IP || !haveLoopback {
		t.Fatalf("lo PIPS must include eth0 IP and loopback: got %v", lo.PIPS)
	}
	// The synthetic identity must actually carry dp's proxymesh prefix.
	if wantEP[:11] != "6c:6b:73:74" {
		t.Fatalf("proxymesh MAC missing lkst prefix: %s", wantEP)
	}

	// Flag off => no lo tap (monitor-only path stays dark by default).
	t.Setenv("CONSTELLATION_MESH_LO_TAP", "0")
	got2, err := p.Desired(context.Background())
	if err != nil {
		t.Fatalf("Desired (flag off): %v", err)
	}
	for _, tt := range got2 {
		if tt.Iface == "lo" {
			t.Fatalf("lo tap must not appear when flag off: %+v", got2)
		}
	}

	// Parser: a LISTEN (st=0A) socket on Istio inbound 15006 (=0x3A9E) is a
	// mesh signature; a LISTEN on a non-mesh port (80 = 0x0050) is not.
	meshTable := []byte("  sl  local_address rem_address   st\n" +
		"   0: 0100007F:3A9E 00000000:0000 0A 00000000:00000000\n")
	if !parseMeshListen(meshTable) {
		t.Fatalf("parseMeshListen: expected mesh port 15006 to be detected")
	}
	plainTable := []byte("  sl  local_address rem_address   st\n" +
		"   0: 0100007F:0050 00000000:0000 0A 00000000:00000000\n" +
		"   1: 0100007F:3A9E 00000000:0000 01 00000000:00000000\n") // 15006 but ESTABLISHED, not LISTEN
	if parseMeshListen(plainTable) {
		t.Fatalf("parseMeshListen: non-listening / non-mesh ports must not match")
	}
}
