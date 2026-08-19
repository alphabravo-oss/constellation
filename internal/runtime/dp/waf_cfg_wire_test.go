package dp

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestWAFBuildPatternsAreStrings is the regression guard for the dp segfault at
// ctrl.c:2184: dp reads each ctrl_bld_dlp pattern with json_string_value, so a
// pattern MUST serialize as a JSON string. A struct WAFPattern serialized as a
// JSON object made json_string_value return NULL -> strlcpy(NULL) -> SIGSEGV.
func TestWAFBuildPatternsAreStrings(t *testing.T) {
	rules := []*WAFRule{{
		Name: "waf-test", ID: 9002,
		Patterns: []WAFPattern{
			{Context: WAFCtxBody, Value: `(?i)union.+select`},
			{Context: WAFCtxHead, Value: `sqlmap`},
		},
	}}
	wire := wafRulesToWire(rules)
	if len(wire) != 1 || len(wire[0].Patterns) != 2 {
		t.Fatalf("wire = %+v, want 1 rule with 2 string patterns", wire)
	}
	// Head context maps to dp "header"; body stays "body".
	if !strings.HasSuffix(wire[0].Patterns[0], "; context body") {
		t.Fatalf("body pattern %q missing '; context body'", wire[0].Patterns[0])
	}
	if !strings.HasSuffix(wire[0].Patterns[1], "; context header") {
		t.Fatalf("head pattern %q missing '; context header'", wire[0].Patterns[1])
	}
	// The wire payload's patterns must be a JSON array of STRINGS, not objects.
	b, err := json.Marshal(&wafBuildPayload{WafRules: wire})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		DlpRules []struct {
			Patterns []json.RawMessage `json:"patterns"`
		} `json:"dlp_rules"`
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, p := range decoded.DlpRules[0].Patterns {
		if len(p) == 0 || p[0] != '"' { // '{' would be an object -> the crash
			t.Fatalf("pattern serialized as non-string %s (dp json_string_value would return NULL and segfault)", p)
		}
	}
}
