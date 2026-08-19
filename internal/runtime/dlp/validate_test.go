package dlp

import (
	"strings"
	"testing"
)

// TestCompilePatternRejectsInvalid is the core fail-open regression (P1-03): an
// unparseable pattern must be rejected at authoring time, not stored and shown
// "enforce" while dp silently drops it.
func TestCompilePatternRejectsInvalid(t *testing.T) {
	for _, bad := range []string{
		`(unclosed`, // unbalanced paren — the classic typo
		`[a-`,       // unterminated class
		`a{2,1}`,    // inverted quantifier
		`*abc`,      // dangling quantifier
	} {
		if err := CompilePattern(bad); err == nil {
			t.Errorf("CompilePattern(%q) = nil, want error (fail-open: dp would drop this sig)", bad)
		}
	}
}

// TestCompilePatternAcceptsLookaround pins the dialect fix: PCRE lookaround /
// atomic-group constructs that dp's pcre2 engine accepts must NOT be rejected.
// This is exactly what plain stdlib regexp.Compile (RE2) would fail-closed on,
// so it fails if someone swaps CompilePattern back to RE2.
func TestCompilePatternAcceptsLookaround(t *testing.T) {
	for _, ok := range []string{
		`foo(?=bar)`,  // positive lookahead
		`foo(?!bar)`,  // negative lookahead
		`(?<=bar)foo`, // positive lookbehind
		`(?<!bar)foo`, // negative lookbehind
		`(?>foo)bar`,  // atomic group
		`password=(?=.{8,})\S+`,
		`AKIA[0-9A-Z]{16}`, // ordinary secret pattern still compiles
	} {
		if err := CompilePattern(ok); err != nil {
			t.Errorf("CompilePattern(%q) = %v, want nil (dp/pcre2 accepts this)", ok, err)
		}
	}
}

func TestValidatePatterns(t *testing.T) {
	// Empty set: NeuVector requires >=1 pattern.
	if err := ValidatePatterns(nil); err == nil {
		t.Error("ValidatePatterns(nil) = nil, want error (>=1 pattern required)")
	}

	// Wildcard-only: matches all traffic — rejected like NeuVector's regPattern.
	for _, w := range []string{`*`, `.*`, `..*`} {
		if err := ValidatePatterns([]string{w}); err == nil {
			t.Errorf("ValidatePatterns([%q]) = nil, want wildcard-only rejection", w)
		}
	}

	// Too many patterns.
	many := make([]string, MaxPatternNum+1)
	for i := range many {
		many[i] = "abc"
	}
	if err := ValidatePatterns(many); err == nil {
		t.Errorf("ValidatePatterns(%d patterns) = nil, want count-cap rejection", len(many))
	}

	// Per-pattern length cap.
	if err := ValidatePatterns([]string{strings.Repeat("a", MaxPatternLen+1)}); err == nil {
		t.Error("over-length pattern accepted, want per-pattern length rejection")
	}

	// Total length cap: three patterns each just under the per-pattern cap sum
	// past the total cap.
	big := strings.Repeat("a", MaxPatternLen)
	if err := ValidatePatterns([]string{big, big, big}); err == nil {
		t.Error("over-total-length pattern set accepted, want total-length rejection")
	}

	// Invalid regex inside an otherwise fine set is rejected.
	if err := ValidatePatterns([]string{"abc", "(oops"}); err == nil {
		t.Error("set containing an unparseable pattern accepted, want rejection")
	}

	// A realistic valid set passes.
	if err := ValidatePatterns([]string{`AKIA[0-9A-Z]{16}`, `password=\S+`}); err != nil {
		t.Errorf("valid pattern set rejected: %v", err)
	}
}
