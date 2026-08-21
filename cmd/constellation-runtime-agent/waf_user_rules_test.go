package main

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/runtime"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// TestSplitDLPWAFRules_RoutesByCategory guards NET-42's partition: only
// category='waf' rows go to the WAF path; "dlp", "signature", and "" (older
// server that omits the field) stay on the DLP path.
func TestSplitDLPWAFRules_RoutesByCategory(t *testing.T) {
	rules := []dlpRuleWire{
		{DPRuleID: 9001, Name: "exfil", Category: "dlp"},
		{DPRuleID: 9002, Name: "sig", Category: "signature"},
		{DPRuleID: 9003, Name: "legacy", Category: ""},
		{DPRuleID: 9004, Name: "sqli", Category: "waf"},
	}
	dlp, waf := splitDLPWAFRules(rules)
	if len(waf) != 1 || waf[0].DPRuleID != 9004 {
		t.Fatalf("want only the waf row (9004) on the WAF path, got %+v", waf)
	}
	if len(dlp) != 3 {
		t.Fatalf("want 3 rows on the DLP path (dlp/signature/legacy), got %d", len(dlp))
	}
	for _, r := range dlp {
		if r.Category == string(runtime.CategoryWAF) {
			t.Fatalf("waf row leaked onto the DLP path: %+v", r)
		}
	}
}

// TestUserWAFRules_ConvertsToWAFContextRules is the core NET-42 assertion: a
// user WAF rule reaches the wafRules build set as a real dp.WAFRule with a
// sig id in dp's WAF range (40000-49999), scanned across all three HTTP
// contexts, so it enforces as WAF (RESET) not DLP (DROP).
func TestUserWAFRules_ConvertsToWAFContextRules(t *testing.T) {
	wire := []dlpRuleWire{{
		DPRuleID: 9042, Name: "Block /etc/passwd", Mode: "enforce",
		Patterns: []string{"/etc/passwd", "  "}, // blank pattern must be dropped
		Category: "waf",
	}}

	// Enforce gate OFF → the rule ships monitor (alert-only, ALLOW action).
	off := userWAFRules(wire, false)
	if len(off) != 1 {
		t.Fatalf("want 1 converted WAF rule, got %d", len(off))
	}
	r := off[0]
	if r.ID < 40000 || r.ID > 49999 {
		t.Fatalf("WAF sig id %d out of dp WAF range 40000-49999", r.ID)
	}
	if r.ID != dp.UserWAFSigID(9042) {
		t.Fatalf("sig id = %d, want UserWAFSigID(9042)=%d", r.ID, dp.UserWAFSigID(9042))
	}
	if len(r.Patterns) != 3 { // one non-blank pattern × url/head/body
		t.Fatalf("want 3 context patterns (url/head/body), got %d: %+v", len(r.Patterns), r.Patterns)
	}
	gotCtx := map[string]bool{}
	for _, p := range r.Patterns {
		gotCtx[p.Context] = true
		if p.Value != "/etc/passwd" {
			t.Fatalf("pattern value mangled: %q", p.Value)
		}
	}
	for _, want := range []string{dp.WAFCtxURL, dp.WAFCtxHead, dp.WAFCtxBody} {
		if !gotCtx[want] {
			t.Fatalf("missing WAF context %q in %+v", want, r.Patterns)
		}
	}
	if act := dp.WAFModeAction(r.Mode); act != dp.DPIActionAllow {
		t.Fatalf("enforce gate OFF must be alert-only (ALLOW), got action %d (mode %q)", act, r.Mode)
	}

	// Enforce gate ON → the rule RESETs (WAF enforce action), distinct from the
	// DLP DROP action — proving it lands on the WAF path.
	on := userWAFRules(wire, true)
	if act := dp.WAFModeAction(on[0].Mode); act != dp.WAFModeAction("enforce") {
		t.Fatalf("enforce gate ON must yield the WAF RESET action, got %d (mode %q)", act, on[0].Mode)
	}
	if dp.WAFModeAction(on[0].Mode) == dp.DPIActionDrop {
		t.Fatal("user WAF rule must RESET (WAF), not DROP (DLP)")
	}
}

// TestUserWAFRules_SigIDsDisjointFromCRS makes sure user WAF sig ids never
// collide with the built-in CRS pack (which starts at 40000 via WAFSigID).
func TestUserWAFRules_SigIDsDisjointFromCRS(t *testing.T) {
	crs := runtime.WAFRuleTable(false)
	crsIDs := map[uint32]bool{}
	for _, r := range crs {
		crsIDs[r.ID] = true
	}
	user := userWAFRules([]dlpRuleWire{
		{DPRuleID: 9000, Name: "a", Patterns: []string{"x"}, Category: "waf"},
		{DPRuleID: 9500, Name: "b", Patterns: []string{"y"}, Category: "waf"},
	}, false)
	for _, r := range user {
		if crsIDs[r.ID] {
			t.Fatalf("user WAF sig id %d collides with the built-in CRS pack", r.ID)
		}
	}
}
