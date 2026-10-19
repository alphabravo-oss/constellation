package scanner

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

// Opt-in acceptance against the exact tools packaged in a candidate image.
// The fixture must contain Go binaries and known vulnerabilities.
func TestGoSymbolsActualTools(t *testing.T) {
	ref := os.Getenv("CONSTELLATION_TEST_GO_SYMBOL_IMAGE")
	if ref == "" {
		t.Skip("set CONSTELLATION_TEST_GO_SYMBOL_IMAGE for actual-tool proof")
	}
	opts := ScanOptions{Timeout: 3 * time.Minute}
	inventory, err := (&SyftEngine{}).Scan(t.Context(), ref, opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Artifacts []struct {
			Metadata struct {
				Symbols map[string][]string `json:"symbols"`
			} `json:"metadata"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(inventory.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	symbols := 0
	for _, a := range doc.Artifacts {
		symbols += len(a.Metadata.Symbols)
	}
	if symbols == 0 {
		t.Fatal("fixture has no captured Go symbols")
	}
	direct, err := (&GrypeEngine{}).Scan(t.Context(), ref, opts)
	if err != nil {
		t.Fatal(err)
	}
	native, err := (&GrypePackageMatcher{}).MatchSBOM(t.Context(), ref, inventory.Raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	keys := func(fs []EngineFinding) []string {
		seen := map[string]bool{}
		for _, f := range fs {
			seen[f.VulnerabilityID+"|"+f.Package.Name+"|"+f.Package.Version] = true
		}
		out := []string{}
		for k := range seen {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if len(direct.Findings) == 0 {
		t.Fatal("known-vulnerable fixture unexpectedly clean")
	}
	if !reflect.DeepEqual(keys(direct.Findings), keys(native.Findings)) {
		t.Fatalf("direct=%v native=%v", keys(direct.Findings), keys(native.Findings))
	}
	broad, err := (&GrypePackageMatcher{}).MatchPackages(t.Context(), ref, inventory.Packages, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys(broad.Findings)) <= len(keys(native.Findings)) {
		t.Fatal("fixture no longer distinguishes module-only matching; update acceptance fixture")
	}
	t.Logf("captured symbol packages=%d; direct/native unique findings=%d; module-only unique findings=%d", symbols, len(keys(native.Findings)), len(keys(broad.Findings)))
}
