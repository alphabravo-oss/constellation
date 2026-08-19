package dp

import (
	"regexp/syntax"
	"strings"
	"testing"
)

// TestNormalizePCREPattern feeds every real built-in DLP/WAF regex through
// NormalizePCREPattern and asserts the output is the full dp value NeuVector's
// agent emits: "[!]/<regex>/is; context body". It must carry a context clause
// (dp segfaults on a context-less pattern), be correctly delimited, have an
// inner regex that still compiles, and be idempotent.
func TestNormalizePCREPattern(t *testing.T) {
	builtins := []string{
		`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011|65\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b`,
		`AKIA[0-9A-Z]{16}`,
		`gh[pousr]_[A-Za-z0-9]{36,}`,
		`xox[abprs]-[A-Za-z0-9-]{10,}`,
		`sk_(test|live)_[A-Za-z0-9]{24,}`,
		`(?i)union.+select`,
		`(?i)\$\{jndi:(ldaps?|rmi|dns|nis|iiop|corba|nds|http)://`,
		`(?i)\$\{(lower|upper|env|sys|date|main|java):`,
	}

	for _, raw := range builtins {
		out := NormalizePCREPattern(raw)

		// (1) context clause present — the crash fixer. Without it dp builds the
		// pattern in the packet_opts path and segfaults.
		if !strings.HasSuffix(out, "; context "+defaultDLPContext) {
			t.Fatalf("%q: output %q missing \"; context %s\"", raw, out, defaultDLPContext)
		}

		// (2) the pcre value (before "; context") is a valid dp literal opener.
		pcreVal := strings.TrimSuffix(out, "; context "+defaultDLPContext)
		if pcreVal == "" || (pcreVal[0] != '/' && pcreVal[0] != 'm' && pcreVal[0] != '!') {
			t.Fatalf("%q: pcre value %q must start with '/', 'm', or '!'", raw, pcreVal)
		}

		// (3) inner regex still compiles (gross-error gate).
		inner, ok := extractInner(pcreVal)
		if !ok {
			t.Fatalf("%q: value %q has no locatable closing delimiter", raw, pcreVal)
		}
		if _, err := syntax.Parse(inner, syntax.Perl); err != nil {
			t.Fatalf("%q: inner regex %q does not compile: %v", raw, inner, err)
		}

		// (4) idempotent.
		if again := NormalizePCREPattern(out); again != out {
			t.Fatalf("%q: not idempotent: f(f(x))=%q, f(x)=%q", raw, again, out)
		}

		// (5) an inline (?i) is lifted (never left in the body) and the "is" flags
		// are applied.
		if strings.Contains(inner, "(?i)") {
			t.Fatalf("%q: inner %q still carries an inline (?i)", raw, inner)
		}
		if !strings.HasSuffix(pcreVal, "/is") {
			t.Fatalf("%q: value %q must carry the NeuVector \"is\" flags", raw, pcreVal)
		}
	}

	// (6) the Log4Shell "://" survives intact in the inner regex.
	log4 := `(?i)\$\{jndi:(ldaps?|rmi|dns|nis|iiop|corba|nds|http)://`
	val := strings.TrimSuffix(NormalizePCREPattern(log4), "; context "+defaultDLPContext)
	if inner, ok := extractInner(val); !ok || !strings.Contains(inner, "://") {
		t.Fatalf("log4shell: inner %q lost the \"://\" (ok=%v)", inner, ok)
	}

	// Empty / whitespace input is skipped, never panics.
	if got := NormalizePCREPattern("   "); got != "" {
		t.Fatalf("whitespace input: want \"\", got %q", got)
	}
}

// TestNormalizePCREFormat pins the exact NeuVector wire format for representative
// inputs, including the negate prefix and the already-formed passthrough.
func TestNormalizePCREFormat(t *testing.T) {
	cases := []struct{ raw, want string }{
		{`AKIA[0-9A-Z]{16}`, `/AKIA[0-9A-Z]{16}/is; context body`},
		{`(?i)union.+select`, `/union.+select/is; context body`}, // (?i) stripped, is applied
		{`!secret`, `!/secret/is; context body`},                 // negate prefix preserved
		{`/foo/i`, `/foo/i; context body`},                       // pre-wrapped literal: keep, add context
		{`(?i)`, ``},                                             // empty after lifting: skipped
		{`   `, ``},                                              // whitespace: skipped
		// idempotent: our own output already carries "; context " → unchanged.
		{`/AKIA[0-9A-Z]{16}/is; context body`, `/AKIA[0-9A-Z]{16}/is; context body`},
	}
	for _, c := range cases {
		if got := NormalizePCREPattern(c.raw); got != c.want {
			t.Fatalf("NormalizePCREPattern(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// extractInner mirrors dp's parser for the '/regex/flags' form: the closing
// delimiter is the LAST '/'. Returns the inner regex between the opening and
// closing delimiter. Handles an optional leading '!' (negate).
func extractInner(v string) (string, bool) {
	if strings.HasPrefix(v, "!") {
		v = v[1:]
	}
	if len(v) < 2 || v[0] != '/' {
		return "", false
	}
	i := strings.LastIndexByte(v, '/')
	if i <= 0 {
		return "", false
	}
	return v[1:i], true
}
