package server

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler"
)

// updateOpenAPI regenerates the checked-in spec instead of asserting against it.
// Run: go test ./internal/server -run TestGenerateOpenAPI -update-openapi
var updateOpenAPI = flag.Bool("update-openapi", false, "regenerate internal/handler/openapi.json from the live router")

// specPath is the embedded spec the server serves (internal/handler/openapi.json),
// resolved relative to this test package's directory.
func specPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// internal/server -> internal/handler/openapi.json
	return filepath.Clean(filepath.Join(wd, "..", "handler", "openapi.json"))
}

// TestGenerateOpenAPI mechanically (re)generates the OpenAPI spec from the live
// chi router. With -update-openapi it writes the file; otherwise it asserts the
// checked-in file already equals the generated output, so a route added without
// regenerating fails CI. Hand-written summaries/descriptions/schemas are
// preserved by MergeOpenAPI; only stubs for new routes are added.
func TestGenerateOpenAPI(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatalf("newSpecServer: %v", err)
	}
	routes, err := s.RouteList()
	if err != nil {
		t.Fatalf("RouteList: %v", err)
	}

	current, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	gen, err := handler.MergeOpenAPI(current, routes)
	if err != nil {
		t.Fatalf("MergeOpenAPI: %v", err)
	}

	if *updateOpenAPI {
		if err := os.WriteFile(specPath(t), gen, 0o644); err != nil {
			t.Fatalf("write spec: %v", err)
		}
		t.Logf("regenerated %s (%d routes)", specPath(t), len(routes))
		return
	}

	if !bytes.Equal(bytes.TrimSpace(current), bytes.TrimSpace(gen)) {
		t.Errorf("internal/handler/openapi.json is stale or hand-edited away from the generated form.\n" +
			"Run: go test ./internal/server -run TestGenerateOpenAPI -update-openapi")
	}
}

// TestOpenAPICompleteness is the I1 CI gate. It walks the live router and fails
// if any registered route+method lacks a spec entry. Adding a route without a
// corresponding spec operation is therefore a build failure.
func TestOpenAPICompleteness(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatalf("newSpecServer: %v", err)
	}
	routes, err := s.RouteList()
	if err != nil {
		t.Fatalf("RouteList: %v", err)
	}
	documented, err := handler.DocumentedRoutes()
	if err != nil {
		t.Fatalf("DocumentedRoutes: %v", err)
	}

	var missing []string
	for _, rt := range routes {
		key := rt.Method + " " + rt.Path
		if !documented[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)

	stubs, err := handler.StubRoutes()
	if err != nil {
		t.Fatalf("StubRoutes: %v", err)
	}
	documentedCount := len(routes) - len(missing)
	t.Logf("OpenAPI coverage: %d/%d route+method operations have a spec entry "+
		"(%d real, %d content-free stubs)",
		documentedCount, len(routes), documentedCount-len(stubs), len(stubs))

	if len(missing) > 0 {
		t.Errorf("%d registered route(s) have no OpenAPI spec entry:\n  %s\n\n"+
			"Every route must be documented. Regenerate the spec with:\n"+
			"  go test ./internal/server -run TestGenerateOpenAPI -update-openapi",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// maxOpenAPIStubs is the ratchet baseline: the number of content-free stub
// operations the checked-in spec is allowed to carry. It exists so the I1 gate
// is REAL, not presence-only — a new route may not ship as a bare stub (that
// would push the count above the baseline), and backfilling docs lowers it. When
// you replace stubs with real documentation, ratchet this DOWN to lock the gain
// in. It must never be raised.
const maxOpenAPIStubs = 230

// TestOpenAPINoNewStubs enforces the stub ratchet. A presence-only stub (summary
// + a lone 200 response, no requestBody/parameters/error responses/schemas) does
// not count as real documentation; this test fails if the spec carries more
// stubs than the baseline, so adding an undocumented route or regressing a
// real operation back to a stub fails CI even though the completeness gate
// (presence-only) would still pass.
func TestOpenAPINoNewStubs(t *testing.T) {
	stubs, err := handler.StubRoutes()
	if err != nil {
		t.Fatalf("StubRoutes: %v", err)
	}
	if len(stubs) > maxOpenAPIStubs {
		list := make([]string, 0, len(stubs))
		for k := range stubs {
			list = append(list, k)
		}
		sort.Strings(list)
		t.Errorf("OpenAPI stub count %d exceeds baseline %d: a new route must ship with a real "+
			"operation (requestBody for write methods and/or non-2xx responses), not a stub.\n"+
			"Document the new route(s) in internal/handler/openapi.json, then regenerate:\n"+
			"  go test ./internal/server -run TestGenerateOpenAPI -update-openapi\n"+
			"Current stub operations:\n  %s",
			len(stubs), maxOpenAPIStubs, strings.Join(list, "\n  "))
	}
}
