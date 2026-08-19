package runtime

import (
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// TestBuiltinPCREGate is the regression gate: every pattern the seeder ships in
// AllBuiltinPacks() (DLP + WAF: dlp.DefaultCatalog, waf.BuiltinCRS,
// log4ShellSpring4ShellPatterns), once run through dp.NormalizePCREPattern, must
// satisfy dp's Snort pcre grammar (dp/dpi/sig/dpi_sigopt_pcre.c). If a future
// built-in ships a pattern dp would reject, this test fails at BUILD time
// instead of dp rejecting it and segfaulting on the empty hyperscan DB.
//
// dp's parser (dpi_sigopt_pcre_parser) requires, after we hand it the value:
//   - the value starts with a delimiter form: '/' , 'm<delim>' , or '!' (negate),
//   - there is a distinct CLOSING delimiter (strrchr finds the LAST one),
//   - the chars AFTER the closing delimiter are a subset of the flag letters
//     "imsxAEG",
//   - the inner regex actually compiles (pcre2 — approximated here with the
//     stdlib regexp/syntax Perl parser, which is a strict-enough proxy).
const pcreFlagSet = "imsxAEG"

func TestBuiltinPCREGate(t *testing.T) {
	packs := AllBuiltinPacks()
	if len(packs) == 0 {
		t.Fatal("AllBuiltinPacks() returned no packs — the seeder ships nothing")
	}

	covered := 0
	for _, pack := range packs {
		for i, raw := range pack.Patterns {
			if strings.TrimSpace(raw) == "" {
				continue // seeder skips empties too; not a gate violation
			}
			covered++
			v := dp.NormalizePCREPattern(raw)
			if v == "" {
				t.Errorf("pack %q pattern[%d] %q: normalized to empty (dp would drop it)", pack.Name, i, raw)
				continue
			}

			// dp REQUIRES a context option per pattern; a context-less pattern
			// crashes the hyperscan tree build. The pcre value is everything
			// before the "; context <ctx>" clause.
			pcreVal, ctx, hasCtx := strings.Cut(v, "; context ")
			if !hasCtx || strings.TrimSpace(ctx) == "" {
				t.Errorf("pack %q pattern[%d] %q -> %q: missing \"; context <ctx>\" clause (dp would segfault)", pack.Name, i, raw, v)
				continue
			}

			// dp splits the signature on ';', so a literal ';' in the pcre value
			// would truncate the pattern and get it rejected. NormalizePCREPattern
			// must have escaped it to \x3b.
			if strings.Contains(pcreVal, ";") {
				t.Errorf("pack %q pattern[%d] %q -> %q: pcre value contains a literal ';' (dp would split+reject it)", pack.Name, i, raw, pcreVal)
			}

			inner, flags, ok := splitPCREValue(pcreVal)
			if !ok {
				t.Errorf("pack %q pattern[%d] %q -> %q: no valid delimiter/closing-delimiter form", pack.Name, i, raw, v)
				continue
			}
			for j := 0; j < len(flags); j++ {
				if !strings.ContainsRune(pcreFlagSet, rune(flags[j])) {
					t.Errorf("pack %q pattern[%d] %q -> %q: trailing flag %q not in %q", pack.Name, i, raw, v, string(flags[j]), pcreFlagSet)
				}
			}
			if _, err := syntax.Parse(inner, syntax.Perl); err != nil {
				t.Errorf("pack %q pattern[%d] %q -> inner %q: does not compile: %v", pack.Name, i, raw, inner, err)
			}
		}
	}

	if covered == 0 {
		t.Fatal("gate covered 0 patterns — enumeration is broken")
	}
	t.Logf("built-in PCRE gate covered %d patterns across %d packs", covered, len(packs))

	// Self-check: the gate's own delimiter parser must agree with dp on the
	// canonical shapes — a wrapped slash literal, an alt-delim 'm' literal, a
	// negated literal, and interior "://" (Log4Shell) must all parse, while a
	// bare regex (no delimiter) must not.
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{`/AKIA[0-9A-Z]{16}/`, true},
		{`/(ldaps?|rmi):\/\//i`, true},
		{`/a\$\{jndi:(ldap):\/\//i`, true},
		{`m#a/b#i`, true},
		{`!/secret/`, true},
		{`AKIA[0-9]`, false}, // no delimiter — dp rejects this shape
	} {
		if _, _, ok := splitPCREValue(tc.in); ok != tc.want {
			t.Errorf("splitPCREValue self-check %q: got ok=%v want %v", tc.in, ok, tc.want)
		}
	}
}

// splitPCREValue mirrors dpi_sigopt_pcre_parser: given the VALUE dp receives
// after "pcre ", it returns the inner regex, the trailing flag string, and
// whether the value is a well-formed delimiter literal. The closing delimiter
// is the LAST occurrence of the delimiter char (strrchr), so interior
// delimiters (e.g. "://") are preserved in inner.
func splitPCREValue(v string) (inner, flags string, ok bool) {
	if v == "" {
		return "", "", false
	}
	if v[0] == '!' { // optional negate
		v = v[1:]
		if v == "" {
			return "", "", false
		}
	}
	var delim byte
	switch {
	case v[0] == 'm': // m<delim>...<delim><flags>
		if len(v) < 2 {
			return "", "", false
		}
		delim = v[1]
		v = v[2:]
	case v[0] == '/': // /...<flags>, delimiter is '/'
		delim = '/'
		v = v[1:]
	default:
		return "", "", false // no leading delimiter form — dp rejects
	}
	i := strings.LastIndexByte(v, delim)
	if i < 0 {
		return "", "", false // no closing delimiter
	}
	return v[:i], v[i+1:], true
}
