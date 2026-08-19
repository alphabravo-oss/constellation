package reachability

import (
	"strings"
	"testing"
)

// govulncheck-2-line fixture: one OSV record + one finding with a trace + one finding
// for the same OSV without a trace (import only). The parser should emit a single
// reachable verdict with the trace.
const fixtureGovulnJSON = `
{"osv":{"id":"GO-2024-9999","aliases":["CVE-2024-9999","GHSA-aaaa-bbbb-cccc"],"affected":[{"package":{"name":"golang.org/x/example"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/example/badpkg","symbols":["BadFunc"]}]}}]}}
{"finding":{"osv":"GO-2024-9999","trace":[{"function":"BadFunc","package":"golang.org/x/example/badpkg","module":"golang.org/x/example"},{"function":"main","package":"main","module":"."}]}}
{"finding":{"osv":"GO-2024-9999","trace":[]}}
{"osv":{"id":"GO-2024-1111","aliases":["CVE-2024-1111"],"affected":[{"package":{"name":"golang.org/x/imported-only"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/imported-only","symbols":["Unused"]}]}}]}}
{"finding":{"osv":"GO-2024-1111","trace":[]}}
`

func TestParseGovulncheckJSON_ReachableAndImportOnly(t *testing.T) {
	verdicts, err := parseGovulncheckJSON([]byte(strings.TrimSpace(fixtureGovulnJSON)))
	if err != nil {
		t.Fatal(err)
	}
	if len(verdicts) != 2 {
		t.Fatalf("expected 2 verdicts, got %d", len(verdicts))
	}
	byCVE := map[string]Verdict{}
	for _, v := range verdicts {
		byCVE[v.VulnerabilityID] = v
	}
	reach, ok := byCVE["CVE-2024-9999"]
	if !ok {
		t.Fatal("expected CVE-2024-9999 verdict")
	}
	if !reach.Reachable {
		t.Fatalf("9999 should be reachable: %+v", reach)
	}
	if reach.Confidence != 1.0 {
		t.Fatalf("9999 confidence: %v", reach.Confidence)
	}
	if len(reach.CallStack) == 0 {
		t.Fatal("9999 should have a call stack")
	}
	if reach.Symbol != "golang.org/x/example/badpkg.BadFunc" {
		t.Fatalf("9999 symbol: %q", reach.Symbol)
	}
	if reach.Module != "golang.org/x/example" {
		t.Fatalf("9999 module: %q", reach.Module)
	}

	imp, ok := byCVE["CVE-2024-1111"]
	if !ok {
		t.Fatal("expected CVE-2024-1111 verdict (import only)")
	}
	if imp.Reachable {
		t.Fatal("1111 should NOT be reachable (import only)")
	}
	if imp.Confidence != 0.5 {
		t.Fatalf("1111 confidence: %v", imp.Confidence)
	}
	if len(imp.CallStack) != 0 {
		t.Fatal("1111 should have no call stack")
	}
}

func TestPickCVE_PrefersCVEAlias(t *testing.T) {
	got := pickCVE([]string{"GHSA-x", "CVE-2024-1", "GHSA-y"}, "GO-2024-1")
	if got != "CVE-2024-1" {
		t.Fatalf("got %q", got)
	}
	if got := pickCVE([]string{}, "GO-2024-2"); got != "GO-2024-2" {
		t.Fatalf("fallback got %q", got)
	}
}
