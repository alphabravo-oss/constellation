package dp

import (
	"strings"
	"testing"
)

// TestDLPPerPatternContext verifies NET-40: a DLPRule's per-pattern Contexts are
// folded into each pattern's dp wire string ("...; context <ctx>") instead of the
// forced "body" default, and that a missing/empty context still defaults to body
// (backward compatibility for legacy rows).
func TestDLPPerPatternContext(t *testing.T) {
	r := &DLPRule{
		Name: "pii", ID: 20001,
		Patterns: []string{`AKIA[0-9A-Z]{16}`, `secret`, `token`, `sig`},
		Contexts: []string{"uri", "header", "packet", ""}, // last empty ⇒ body
	}
	out := normalizeDLPPatterns([]*DLPRule{r})
	if len(out) != 1 {
		t.Fatalf("want 1 rule, got %d", len(out))
	}
	got := out[0].Patterns
	want := []string{"url", "header", "packet", "body"}
	if len(got) != len(want) {
		t.Fatalf("want %d patterns, got %d: %v", len(want), len(got), got)
	}
	for i, ctx := range want {
		suffix := "; context " + ctx
		if !strings.HasSuffix(got[i], suffix) {
			t.Errorf("pattern %d = %q, want suffix %q", i, got[i], suffix)
		}
	}
	// The caller's rule must be untouched (normalizeDLPPatterns copies).
	if r.Patterns[0] != `AKIA[0-9A-Z]{16}` {
		t.Errorf("source rule mutated: %q", r.Patterns[0])
	}
}

// TestDLPContextDefaultsBody verifies a rule with no Contexts slice reproduces
// the pre-NET-40 behaviour: every pattern body-scoped.
func TestDLPContextDefaultsBody(t *testing.T) {
	out := normalizeDLPPatterns([]*DLPRule{{Name: "x", ID: 20002, Patterns: []string{"a", "b"}}})
	for i, p := range out[0].Patterns {
		if !strings.HasSuffix(p, "; context body") {
			t.Errorf("pattern %d = %q, want body context", i, p)
		}
	}
}

// TestDPDLPContextMapping pins the schema-token → dp-context mapping, including
// the "uri"→"url" alias and the unknown→body fallback that keeps dp from
// rejecting a whole rule over a bad context.
func TestDPDLPContextMapping(t *testing.T) {
	cases := map[string]string{
		"uri": "url", "url": "url", "header": "header",
		"body": "body", "packet": "packet",
		"": "body", "bogus": "body", "URI": "url",
	}
	for in, want := range cases {
		if got := dpDLPContext(in); got != want {
			t.Errorf("dpDLPContext(%q) = %q, want %q", in, got, want)
		}
	}
}
