package dp

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeTapProvider returns a fixed desired set.
type fakeTapProvider struct{ targets []TapTarget }

func (f *fakeTapProvider) Desired(context.Context) ([]TapTarget, error) { return f.targets, nil }

// A veth the inline-enforce path owns must never be tapped, even when the tap
// provider reports it with Enforce=false (a container-list race). dp keys the ep
// by MAC and tap+nfq share one io_ep: a competing tap registration would reset
// ep->tap=true and convert the inline DENY into ACCEPT. Regression for the
// live-canary double-registration bug.
func TestTapManager_SkipsEnforceOwnedMAC(t *testing.T) {
	srv := newCaptureServer(t)
	client := newClientPointedAt(t, srv)

	enfMAC := "16:e6:fe:e8:ec:be"
	// Provider reports the enforce veth with Enforce=false (the flap) + a normal one.
	prov := &fakeTapProvider{targets: []TapTarget{
		{NetNS: "/proc/1/ns/net", Iface: "vethENF", EPMAC: enfMAC, Enforce: false},
		{NetNS: "/proc/2/ns/net", Iface: "vethOK", EPMAC: "aa:aa:aa:aa:aa:aa", Enforce: false},
	}}
	m := newTapManager(client, prov, newSilentLogger(), 10*time.Millisecond)
	m.isEnforcedMAC = func(mac string) bool { return mac == enfMAC }

	m.reconcileOnce(context.Background())

	// Only the non-enforce veth should be tapped.
	macs := m.currentMACs()
	for _, mac := range macs {
		if mac == enfMAC {
			t.Fatalf("enforce-owned MAC %s was tapped; currentMACs=%v", enfMAC, macs)
		}
	}
	if len(macs) != 1 || macs[0] != "aa:aa:aa:aa:aa:aa" {
		t.Fatalf("currentMACs=%v, want only the non-enforce veth", macs)
	}
	// No AddTapPort datagram should carry the enforce iface.
	for _, dg := range srv.drain(8) {
		s := string(dg)
		if strings.Contains(s, "ctrl_add_tap_port") && strings.Contains(s, "vethENF") {
			t.Fatalf("tap manager sent AddTapPort for the enforce veth: %s", s)
		}
	}
}

// If a veth is already tapped and then becomes enforce-owned, the tap manager
// tears down its tap PORT but must NOT DelMAC (that shared ep now belongs to the
// nfq path; DelMAC would wipe its policy_hdl and re-arm ep->tap).
func TestTapManager_RemoveEnforced_KeepsMAC(t *testing.T) {
	srv := newCaptureServer(t)
	client := newClientPointedAt(t, srv)

	enfMAC := "16:e6:fe:e8:ec:be"
	prov := &fakeTapProvider{targets: []TapTarget{
		{NetNS: "/proc/1/ns/net", Iface: "vethENF", EPMAC: enfMAC, Enforce: false},
	}}
	m := newTapManager(client, prov, newSilentLogger(), 10*time.Millisecond)

	// First reconcile: no enforce owner yet → it gets tapped.
	m.reconcileOnce(context.Background())
	if len(m.currentMACs()) != 1 {
		t.Fatalf("expected the veth to be tapped initially; currentMACs=%v", m.currentMACs())
	}
	_ = srv.drain(8) // clear add datagrams

	// Now the enforce path claims it. Next reconcile must drop the tap.
	m.isEnforcedMAC = func(mac string) bool { return mac == enfMAC }
	m.reconcileOnce(context.Background())

	if len(m.currentMACs()) != 0 {
		t.Fatalf("enforce-owned veth still tapped after reconcile; currentMACs=%v", m.currentMACs())
	}
	sawDelTap, sawDelMAC := false, false
	for _, dg := range srv.drain(8) {
		s := string(dg)
		if strings.Contains(s, "ctrl_del_tap_port") {
			sawDelTap = true
		}
		if strings.Contains(s, "ctrl_del_mac") {
			sawDelMAC = true
		}
	}
	if !sawDelTap {
		t.Errorf("expected DelTapPort for the handed-off veth")
	}
	if sawDelMAC {
		t.Errorf("tap manager sent DelMAC for an enforce-owned veth — that wipes the shared ep's policy_hdl")
	}
}
