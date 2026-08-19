package main

import "testing"

// TestDLPSyncSignatureCoversWAF guards the unified sync signature: DLP and WAF
// are now one combined dp push (a single shared detector), so dlpSyncSignature
// alone must gate both. The built-in CRS pack is static and varies only by the
// tap-MAC set and the fleet enforce gate, so the signature must change when a
// MAC is added/dropped or the enforce gate flips (else a WAF-relevant change
// would be silently de-duped) and stay order-independent otherwise.
func TestDLPSyncSignatureCoversWAF(t *testing.T) {
	rules := []dlpRuleWire{{DPRuleID: 9001, Name: "a", Mode: "monitor", Version: 1}}

	a := dlpSyncSignature(rules, []string{"aa:bb", "cc:dd"}, false)
	b := dlpSyncSignature(rules, []string{"cc:dd", "aa:bb"}, false) // reordered → same
	if a != b {
		t.Fatalf("signature not order-independent over MACs: %q vs %q", a, b)
	}
	if a == dlpSyncSignature(rules, []string{"aa:bb", "cc:dd"}, true) {
		t.Fatal("enforce flip must change signature (WAF pack re-push)")
	}
	if a == dlpSyncSignature(rules, []string{"aa:bb"}, false) {
		t.Fatal("dropping a MAC must change signature")
	}
	if a == dlpSyncSignature(rules, []string{"aa:bb", "cc:dd", "ee:ff"}, false) {
		t.Fatal("adding a MAC must change signature (WAF must reach the new workload)")
	}
}
