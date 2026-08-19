package handler

// WS-G G1 (delete path): the /waf/groups + /waf/rules CRUD surface was removed
// because it never reached the dataplane (no agent bundle endpoint, no sync
// worker, no DP consumer). DPI Signatures (runtime_signatures.go, backed by
// runtime_dlp_rules + Supervisor.BuildDLPRules) are the single authoritative
// DPI/L7 ruleset. These tests are the DoD "grep check that no orphan /waf
// routes/pages remain" — they fail if anyone re-introduces the orphan surface.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWAFGroupsHandlerRemoved asserts the WAF CRUD handler type and its routes
// are gone from the server source tree. We grep source rather than spin up a
// router so the test needs no DB.
func TestWAFGroupsHandlerRemoved(t *testing.T) {
	// repo root is two dirs up from internal/handler.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	// Forbidden tokens → the file(s) they must not appear in.
	type check struct {
		token string
		rel   string
	}
	checks := []check{
		{"NewWAFRules", "internal/handler/runtime/waf_dlp.go"},
		{`"/waf/groups"`, "internal/server/server.go"},
		{`"/waf/rules"`, "internal/server/server.go"},
		{"wafRules.", "internal/server/server.go"},
	}
	for _, c := range checks {
		b, err := os.ReadFile(filepath.Join(root, c.rel))
		if err != nil {
			t.Fatalf("read %s: %v", c.rel, err)
		}
		if strings.Contains(string(b), c.token) {
			t.Errorf("orphan WAF surface: %q still present in %s; the /waf CRUD was removed in WS-G G1, use DPI Signatures instead", c.token, c.rel)
		}
	}
}

// TestWAFCRUDStoreRemoved asserts the CRUD store types (WafGroup/WafRule/
// LoadPack) that backed waf_groups are gone. The in-process L7 engine
// (Engine/BuiltinCRS in waf.go) is intentionally kept and not checked here.
func TestWAFCRUDStoreRemoved(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal", "runtime", "waf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"store.go", "compile.go"} {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			t.Errorf("orphan WAF CRUD file still present: internal/runtime/waf/%s (removed in WS-G G1)", f)
		}
	}
}
