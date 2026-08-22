package dlp

import (
	"bytes"
	"encoding/json"
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

// PatternSpec is one authored DLP pattern in the NET-40 rule schema. The
// patterns JSONB column stores an array whose elements are EITHER a bare string
// (legacy, op/context empty) OR an object {pattern, op, context}; ParsePatternSpecs
// normalises both into this shape. Op mirrors NeuVector's criteria op
// ("regex"/"not_regex"); Context is the dp match buffer (uri|header|body|packet).
type PatternSpec struct {
	Pattern string `json:"pattern"`
	Op      string `json:"op,omitempty"`
	Context string `json:"context,omitempty"`
}

// ParsePatternSpecs decodes a patterns JSONB value into PatternSpecs, accepting
// both the legacy bare-string form and the {pattern, op, context} object form in
// the same array. A nil/empty/"null" input returns nil specs (no error) so an
// unset list stays unset.
func ParsePatternSpecs(raw []byte) ([]PatternSpec, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil, nil
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, fmt.Errorf("decode patterns: %w", err)
	}
	out := make([]PatternSpec, 0, len(elems))
	for _, e := range elems {
		t := bytes.TrimSpace(e)
		if len(t) > 0 && t[0] == '"' {
			var str string
			if err := json.Unmarshal(t, &str); err != nil {
				return nil, fmt.Errorf("decode patterns: %w", err)
			}
			out = append(out, PatternSpec{Pattern: str})
			continue
		}
		var sp PatternSpec
		if err := json.Unmarshal(t, &sp); err != nil {
			return nil, fmt.Errorf("decode patterns: %w", err)
		}
		out = append(out, sp)
	}
	return out, nil
}

// ValidPatternContext reports whether ctx is a DLP match context the dataplane
// accepts (NET-40). Empty is valid — it means "use the body default". Tokens
// mirror the schema: uri|header|body|packet (plus "url" as an alias for uri).
func ValidPatternContext(ctx string) bool {
	switch strings.ToLower(strings.TrimSpace(ctx)) {
	case "", "uri", "url", "header", "body", "packet":
		return true
	}
	return false
}

// ValidPatternOp reports whether op is a supported per-pattern operator (NET-40).
// Empty defaults to a plain regex match; "not_regex"/"not" negate it.
func ValidPatternOp(op string) bool {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "", "regex", "not_regex", "not":
		return true
	}
	return false
}

// ValidateSpecs runs the rule-level + per-pattern authoring checks over the
// structured NET-40 spec list: every pattern's regex/length/wildcard checks
// (via ValidatePatterns) plus a valid per-pattern op and context. Used by the
// store on create/update so an unknown context — which would make dp reject the
// whole compiled rule — is caught at authoring time rather than failing open.
func ValidateSpecs(specs []PatternSpec) error {
	pats := make([]string, len(specs))
	for i, sp := range specs {
		pats[i] = sp.Pattern
		if !ValidPatternOp(sp.Op) {
			return fmt.Errorf("pattern %d: invalid op %q (want regex|not_regex)", i, sp.Op)
		}
		if !ValidPatternContext(sp.Context) {
			return fmt.Errorf("pattern %d: invalid context %q (want uri|header|body|packet)", i, sp.Context)
		}
	}
	return ValidatePatterns(pats)
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
