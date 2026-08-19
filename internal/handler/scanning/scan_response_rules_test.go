package scanning

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// TestScanResponseRuleEventFiresOnMatch proves the E1 EventScan ingest seam: a "scan" rule
// fires its action when the folded scan event matches its conditions, and does NOT fire when
// the conditions do not match — the exact gap E1b closes (admission/scan rules that previously
// never fired). It exercises the real folding (scanResponseRuleEvent) feeding the real matcher
// (responserule.MatchRules), so a regression in field names or rank derivation is caught.
func TestScanResponseRuleEventFiresOnMatch(t *testing.T) {
	target := handler.ScanTarget{
		Type:       "image",
		Ref:        "ghcr.io/acme/api:1.2.3",
		SourceType: "registry",
	}
	identity := scanImageIdentity{
		Ref:        "ghcr.io/acme/api:1.2.3",
		Repository: "ghcr.io/acme/api",
		Digest:     "sha256:abc",
	}

	// A scan whose worst finding is HIGH (not critical), one of which is fixable.
	highFindings := []scanner.Finding{
		{VulnerabilityID: "CVE-2024-1", Severity: "medium"},
		{VulnerabilityID: "CVE-2024-2", Severity: "high", FixedVersion: "1.2.4"},
	}
	// A scan that includes a CRITICAL finding.
	critFindings := []scanner.Finding{
		{VulnerabilityID: "CVE-2024-9", Severity: "critical"},
		{VulnerabilityID: "CVE-2024-2", Severity: "high"},
	}

	// Folding sanity: max severity + counts are what conditions reference.
	highEv := scanResponseRuleEvent(target, identity, highFindings)
	if got := highEv.Fields["severity"]; got != "high" {
		t.Fatalf("max severity = %q, want high", got)
	}
	if got := highEv.Fields["cve_count"]; got != "2" {
		t.Fatalf("cve_count = %q, want 2", got)
	}
	if got := highEv.Fields["fixable_count"]; got != "1" {
		t.Fatalf("fixable_count = %q, want 1", got)
	}
	if got := highEv.Fields["image_repository"]; got != "ghcr.io/acme/api" {
		t.Fatalf("image_repository = %q", got)
	}

	// Rule: quarantine any image whose scan has a CRITICAL finding.
	rule := responserule.ResponseRule{
		Name:      "block-critical-images",
		Enabled:   true,
		EventType: responserule.EventScan,
		Conditions: []responserule.Condition{
			{Field: "severity", Op: responserule.OpEq, Value: "critical"},
		},
		Actions: []responserule.Action{{Type: responserule.ActionQuarantine}},
	}
	rules := []responserule.ResponseRule{rule}

	// Non-match: worst severity is "high", rule wants "critical" -> must NOT fire.
	if acts := responserule.Match(rules, scanResponseRuleEvent(target, identity, highFindings)); len(acts) != 0 {
		t.Fatalf("rule fired on non-matching scan (max=high): got %d actions, want 0", len(acts))
	}

	// Match: scan contains a "critical" finding -> rule fires its quarantine action.
	critEv := scanResponseRuleEvent(target, identity, critFindings)
	if got := critEv.Fields["severity"]; got != "critical" {
		t.Fatalf("max severity = %q, want critical", got)
	}
	acts := responserule.Match(rules, critEv)
	if len(acts) != 1 || acts[0].Type != responserule.ActionQuarantine {
		t.Fatalf("rule did not fire on matching scan: got %#v, want one quarantine action", acts)
	}

	// Org-scope sanity: a disabled rule never fires even on a match.
	disabled := rule
	disabled.Enabled = false
	if acts := responserule.Match([]responserule.ResponseRule{disabled}, critEv); len(acts) != 0 {
		t.Fatalf("disabled rule fired: got %d actions, want 0", len(acts))
	}
}
