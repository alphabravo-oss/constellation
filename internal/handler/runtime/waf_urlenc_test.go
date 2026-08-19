package runtime

import (
	"regexp"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/internal/runtime/waf"
)

// mustMatch compiles the transformed pattern (Go RE2 as a well-formedness +
// matching proxy for dp's hyperscan) and asserts match == want against input.
func mustMatch(t *testing.T, transformed, input string, want bool) {
	t.Helper()
	re, err := regexp.Compile(transformed)
	if err != nil {
		t.Fatalf("transformed pattern does not compile: %q: %v", transformed, err)
	}
	if got := re.MatchString(input); got != want {
		t.Errorf("match(%q, %q) = %v, want %v\n  transformed: %s", transformed, input, got, want, transformed)
	}
}

func TestUrlEncodeTolerant_SQLiUnionSelect(t *testing.T) {
	got := urlEncodeTolerant(`(?i)\bunion\b.+\bselect\b`)
	t.Logf("transformed: %s", got)
	// encoded on-the-wire form
	mustMatch(t, got, `id=1%27%20UNION%20SELECT%20pw`, true)
	// decoded form still matches
	mustMatch(t, got, `id=1' union select pw`, true)
	// FP guard: leading letter must still defeat the boundary
	mustMatch(t, got, `communion selection`, false)
}

func TestUrlEncodeTolerant_XSSScriptTag(t *testing.T) {
	got := urlEncodeTolerant(`<\s*script[\s>]`)
	mustMatch(t, got, `%3Cscript%3E`, true)
	mustMatch(t, got, `%3C%20script%3E`, true)
	mustMatch(t, got, `<script>`, true)
	mustMatch(t, got, `describe topic`, false) // FP guard
}

func TestUrlEncodeTolerant_JavascriptURI(t *testing.T) {
	got := urlEncodeTolerant(`javascript\s*:`)
	mustMatch(t, got, `javascript%3A`, true)
	mustMatch(t, got, `javascript:`, true)
	mustMatch(t, got, `java script`, false) // FP guard
}

func TestUrlEncodeTolerant_PathTraversal(t *testing.T) {
	got := urlEncodeTolerant(`(\.\./|\.\.\\)`)
	mustMatch(t, got, `..%2F`, true)
	mustMatch(t, got, `%2E%2E/`, true)
	mustMatch(t, got, `../`, true)
	mustMatch(t, got, `a.b.c/d`, false) // FP guard
}

// TestUrlEncodeTolerant_AllCRSCompile transforms every url-context, urlDecode
// CRS pattern and asserts the result is a valid regex (RE2 proxy for hyperscan
// well-formedness).
func TestUrlEncodeTolerant_AllCRSCompile(t *testing.T) {
	transformed := 0
	for _, r := range waf.BuiltinCRS().Rules {
		pcre := wafOpToPattern(r.Operator)
		if pcre == "" {
			continue
		}
		if wafTargetContext(r.Target) != dp.WAFCtxURL || !hasTransform(r.Transformations, "urlDecode") {
			continue
		}
		out := urlEncodeTolerant(pcre)
		if _, err := regexp.Compile(out); err != nil {
			t.Errorf("rule %d (%s): transformed pattern won't compile: %v\n  in:  %s\n  out: %s",
				r.ID, r.Msg, err, pcre, out)
		}
		transformed++
	}
	if transformed == 0 {
		t.Fatal("no url-context urlDecode CRS rules exercised — wiring/regression check failed")
	}
	t.Logf("transformed %d url-context CRS patterns", transformed)
}

// TestUrlEncodeTolerant_LeavesStructureIntact spot-checks that group openers and
// quantifier braces are copied verbatim (never rewritten).
func TestUrlEncodeTolerant_StructureIntact(t *testing.T) {
	// ponytail self-check: (?i) flag, (?:...) group and {0,8} brace survive.
	got := urlEncodeTolerant(`(?i)(\bor\b|\band\b).{0,8}`)
	if _, err := regexp.Compile(got); err != nil {
		t.Fatalf("won't compile: %v (%s)", err, got)
	}
	for _, must := range []string{`(?i)`, `{0,8}`} {
		if !regexp.MustCompile(regexp.QuoteMeta(must)).MatchString(got) {
			t.Errorf("expected %q preserved verbatim in %q", must, got)
		}
	}
}
