package dlp

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
)

// Authoring-time caps mirroring NeuVector's DLP/signature limits
// (neuvector/controller/api/apis.go:143-145). NeuVector rejects a rule at
// authoring time when it violates these; otherwise dp silently drops the
// offending signature at compile time (neuvector/dp/dpi/sig/dpi_sig.c:66-77) —
// a fail-open we prevent by validating before the rule is stored and shown
// "active"/"enforce".
const (
	MaxPatternNum      = 16   // DlpRulePatternMaxNum
	MaxPatternLen      = 512  // DlpRulePatternMaxLen
	MaxPatternTotalLen = 1024 // DlpRulePatternTotalMaxLen
)

// wildcardOnly matches a pattern consisting solely of leading dots and a single
// trailing '*' ("*", ".*", "..*"). NeuVector rejects these because a
// match-everything rule fires on all traffic
// (regPattern = ^\.*\*$, neuvector/controller/rest/dlp_rule.go:298).
var wildcardOnly = regexp.MustCompile(`^\.*\*$`)

// pcreLookaround matches the lookahead/lookbehind/atomic-group openers that
// PCRE (and dp's pcre2 engine) accept but Go's RE2 parser rejects:
// (?=  (?!  (?<=  (?<!  (?>. CompilePattern rewrites them to a plain
// non-capturing group "(?:" for the compile CHECK ONLY, so a valid PCRE
// lookaround pattern is not falsely rejected. The rewrite is never persisted —
// the original pattern is stored and shipped to dp verbatim.
var pcreLookaround = regexp.MustCompile(`\(\?<?[=!]|\(\?>`)

// CompilePattern reports whether pat is a compilable regular expression using a
// PCRE-tolerant proxy. It is NOT a full pcre2 compile (the build carries no
// libpcre2 dependency): it catches the structural errors a typo produces —
// unbalanced parentheses/brackets, dangling quantifiers, malformed char
// classes — while tolerating the PCRE-only lookaround constructs dp accepts.
// This closes the fail-open where an unparseable pattern is stored, shown
// "enforce", then silently dropped by dp with zero operator feedback.
//
// Prefer this over the stdlib regexp.Compile / regexp.MustCompile for
// user-authored DLP/signature patterns: RE2 rejects lookaheads that dp accepts,
// which would fail-closed on legitimate NeuVector-grade patterns.
func CompilePattern(pat string) error {
	probe := pcreLookaround.ReplaceAllString(pat, "(?:")
	if _, err := syntax.Parse(probe, syntax.Perl); err != nil {
		return err
	}
	return nil
}

// ValidatePattern enforces the per-pattern authoring checks: non-empty, within
// the per-pattern length cap, not wildcard-only, and compilable.
func ValidatePattern(pat string) error {
	s := strings.TrimSpace(pat)
	if s == "" {
		return fmt.Errorf("pattern is empty")
	}
	if len(pat) > MaxPatternLen {
		return fmt.Errorf("pattern length %d exceeds max %d", len(pat), MaxPatternLen)
	}
	if wildcardOnly.MatchString(s) {
		return fmt.Errorf("wildcard-only pattern %q matches all traffic", s)
	}
	if err := CompilePattern(s); err != nil {
		return fmt.Errorf("invalid regex %q: %w", s, err)
	}
	return nil
}

// ValidatePatterns enforces the rule-level authoring checks NeuVector applies in
// validateDlpRuleConfig (neuvector/controller/rest/dlp_rule.go:347-397): at
// least one pattern, the pattern-count cap, the total-length cap, and every
// per-pattern check in ValidatePattern.
func ValidatePatterns(patterns []string) error {
	if len(patterns) == 0 {
		return fmt.Errorf("at least one pattern is required")
	}
	if len(patterns) > MaxPatternNum {
		return fmt.Errorf("too many patterns: %d (max %d)", len(patterns), MaxPatternNum)
	}
	total := 0
	for i, p := range patterns {
		if err := ValidatePattern(p); err != nil {
			return fmt.Errorf("pattern %d: %w", i, err)
		}
		total += len(p)
		if total > MaxPatternTotalLen {
			return fmt.Errorf("total pattern length %d exceeds max %d", total, MaxPatternTotalLen)
		}
	}
	return nil
}
