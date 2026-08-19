package dp

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// TestEnforceManager_isEnforcedMAC checks the pure predicate the tap reconciler
// consults to avoid clobbering ep->tap=false on an inline enforce target.
func TestEnforceManager_isEnforcedMAC(t *testing.T) {
	m := newEnforceManager(nil, nil, newSilentLogger(), 0, &ipt{}, nil)
	m.current["k1"] = EnforceTarget{Iface: "veth-a", EPMAC: "aa:aa:aa:aa:aa:aa"}
	m.current["k2"] = EnforceTarget{Iface: "veth-b", EPMAC: ""} // no MAC → never matches

	if !m.isEnforcedMAC("aa:aa:aa:aa:aa:aa") {
		t.Errorf("isEnforcedMAC(present) = false, want true")
	}
	if m.isEnforcedMAC("bb:bb:bb:bb:bb:bb") {
		t.Errorf("isEnforcedMAC(absent) = true, want false")
	}
	if m.isEnforcedMAC("") {
		t.Errorf("isEnforcedMAC(\"\") = true, want false")
	}
}

// TestEnforceManager_ReassertsTapFalse verifies the load-bearing self-heal: on a
// second reconcile with an unchanged target, the manager RE-ASSERTS
// ConfigMAC(tap=false). Without this, a lost oneway or a competing tap=true
// leaves ep->tap stuck true and the NFQUEUE verdict never fires.
func TestEnforceManager_ReassertsTapFalse(t *testing.T) {
	srv := newCaptureServer(t)
	client := newClientPointedAt(t, srv)
	provider := &fakeEnforceProvider{}
	provider.set(EnforceTarget{NetNS: "/proc/1/ns/net", Iface: "veth-a", EPMAC: "aa:aa:aa:aa:aa:aa"})

	m := newEnforceManager(client, provider, newSilentLogger(),
		10*time.Millisecond, &ipt{runner: newFakeRunner()}, NewQnumAllocator(4000, 100))

	// First reconcile: add + drain everything it emits (AddNfqPort, AddMAC,
	// ConfigMAC add-loop, ConfigMAC re-assert).
	m.reconcileOnce(context.Background())
	srv.drain(8)

	// Second reconcile: nothing changed, but tap=false MUST be re-asserted.
	m.reconcileOnce(context.Background())
	msgs := srv.drain(8)

	wantTapFalse := []byte(`"tap":false`)
	found := false
	for _, b := range msgs {
		if bytes.Contains(b, []byte("ctrl_cfg_mac")) && bytes.Contains(b, wantTapFalse) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("second reconcile did not re-assert ConfigMAC(tap=false); got %d msgs: %s",
			len(msgs), msgs)
	}
}
