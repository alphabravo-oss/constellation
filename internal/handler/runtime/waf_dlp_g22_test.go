package runtime

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// G2.2 self-check: the WAF rule builder must emit a non-empty dp pattern entry
// for the XSS "script tag" CRS rule, tagged with an HTTP context, and escalate
// it to enforce (RESET) only when the fleet enforce gate is on. The rule is
// identified by its sanitized name (dp rejects the raw "XSS Attempt (script
// tag)" and its CRS id 941100 is out of dp's sig-id range, so both are rewritten).
func TestWAFRuleTable_XSSHasContextAndEnforce(t *testing.T) {
	xssName := dp.SanitizeSigName("XSS Attempt (script tag)")

	var xss *dp.WAFRule
	for _, r := range WAFRuleTable(true) {
		if r.Name == xssName {
			xss = r
		}
	}
	if xss == nil {
		t.Fatalf("WAFRuleTable(true) missing XSS rule %q", xssName)
	}
	// dp requires WAF sig ids in 40000-49999.
	if xss.ID < 40000 || xss.ID > 49999 {
		t.Fatalf("XSS rule %q sig id %d out of dp WAF range 40000-49999", xssName, xss.ID)
	}
	if len(xss.Patterns) == 0 {
		t.Fatalf("XSS rule %q emitted no dp pattern entries", xssName)
	}
	if xss.Patterns[0].Value == "" {
		t.Fatalf("XSS rule %q pattern has empty PCRE value", xssName)
	}
	// XSS targets ARGS, which live in dp's URI_ORIGIN ("url") buffer, not the header block.
	if got := xss.Patterns[0].Context; got != dp.WAFCtxURL {
		t.Fatalf("XSS rule %q context = %q, want %q (ARGS/query live in URL buffer)", xssName, got, dp.WAFCtxURL)
	}
	if xss.Mode != "enforce" {
		t.Fatalf("XSS rule %q (Action=block) under enforce gate: Mode = %q, want enforce", xssName, xss.Mode)
	}
	// enforce action must be RESET, not a silent DROP.
	if a := dp.WAFModeAction(xss.Mode); a != dp.DPIActionReset {
		t.Fatalf("enforce WAF action = %d, want DPIActionReset (%d)", a, dp.DPIActionReset)
	}

	// enforce=false: same rule downgrades to monitor (alert-only) parity w/ DLP.
	for _, r := range WAFRuleTable(false) {
		if r.Name == xssName && r.Mode != "monitor" {
			t.Fatalf("XSS rule %q without enforce gate: Mode = %q, want monitor", xssName, r.Mode)
		}
	}
}
