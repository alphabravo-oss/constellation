package dp

import "testing"

// TestEnforceDPIScopeMACs is the self-check for the inline DPI opt-in accessor:
// a WAF-opted enforce target's MAC must surface in the waf set and a DLP-opted
// one in the dlp set, targets with no MAC are skipped (dp can't key a detector
// on an empty MAC), and a non-opted enforce target binds no detector at all.
// This is what lets ENFORCE drop/reset bind to the inline (verdict-capable) ep.
func TestEnforceDPIScopeMACs(t *testing.T) {
	m := &enforceManager{current: map[string]EnforceTarget{
		"ns|veth0": {NetNS: "ns", Iface: "veth0", EPMAC: "aa:bb:cc:00:11:22", WAF: true},
		"ns|veth1": {NetNS: "ns", Iface: "veth1", EPMAC: "aa:bb:cc:00:11:33", DLP: true},
		"ns|veth2": {NetNS: "ns", Iface: "veth2", EPMAC: "aa:bb:cc:00:11:44", WAF: true, DLP: true},
		"ns|veth3": {NetNS: "ns", Iface: "veth3", EPMAC: "aa:bb:cc:00:11:55"}, // opted into nothing
		"ns|veth4": {NetNS: "ns", Iface: "veth4", EPMAC: "", WAF: true},       // no MAC → excluded
	}}

	waf, dlp := m.enforceDPIScopeMACs()

	if !waf["aa:bb:cc:00:11:22"] {
		t.Fatalf("enforceDPIScopeMACs: WAF-opted enforce target missing from waf set: %v", waf)
	}
	if !dlp["aa:bb:cc:00:11:33"] {
		t.Fatalf("enforceDPIScopeMACs: DLP-opted enforce target missing from dlp set: %v", dlp)
	}
	if !waf["aa:bb:cc:00:11:44"] || !dlp["aa:bb:cc:00:11:44"] {
		t.Fatalf("enforceDPIScopeMACs: waf+dlp target missing from a set: waf=%v dlp=%v", waf, dlp)
	}
	if waf["aa:bb:cc:00:11:55"] || dlp["aa:bb:cc:00:11:55"] {
		t.Fatalf("enforceDPIScopeMACs: non-opted enforce target bound a detector: waf=%v dlp=%v", waf, dlp)
	}
	if waf[""] || dlp[""] {
		t.Fatalf("enforceDPIScopeMACs: empty-MAC target leaked into a set: waf=%v dlp=%v", waf, dlp)
	}
	if len(waf) != 2 || len(dlp) != 2 {
		t.Fatalf("enforceDPIScopeMACs: want 2 waf + 2 dlp, got waf=%v dlp=%v", waf, dlp)
	}
}
