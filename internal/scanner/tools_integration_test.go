package scanner

import (
	"context"
	"os"
	"testing"
	"time"
)

// Run against the binaries destined for the scanner image and preloaded DBs:
// CONSTELLATION_TEST_SCANNER_IMAGE=<local image with known vulnerabilities>
// CONSTELLATION_SCANNER_OFFLINE_DB=true go test ./internal/scanner -run TestBundledTools
// Tool caches and PATH are supplied by the caller; this test never refreshes DBs.
func TestBundledTools(t *testing.T) {
	ref := os.Getenv("CONSTELLATION_TEST_SCANNER_IMAGE")
	if ref == "" {
		t.Skip("set CONSTELLATION_TEST_SCANNER_IMAGE for real-tool acceptance")
	}
	t.Setenv("CONSTELLATION_SCANNER_OFFLINE_DB", "true")
	t.Setenv("GRYPE_DB_AUTO_UPDATE", "false")
	ctx := context.Background()
	opts := ScanOptions{Timeout: 3 * time.Minute}
	inventory, err := (&SyftEngine{}).Scan(ctx, ref, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Packages) == 0 {
		t.Fatal("Syft returned an empty inventory")
	}
	for _, engine := range []Engine{&TrivyEngine{}, &GrypeEngine{}} {
		t.Run(engine.Name()+"_image", func(t *testing.T) {
			result, err := engine.Scan(ctx, ref, opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) == 0 {
				t.Fatal("known-vulnerable fixture returned no findings")
			}
			for _, f := range result.Findings {
				if f.VulnerabilityID == "" || f.Package.Name == "" {
					t.Fatalf("incomplete finding: %+v", f)
				}
			}
		})
	}
	for _, matcher := range []PackageMatcher{&TrivyPackageMatcher{}, &GrypePackageMatcher{}} {
		t.Run(matcher.Name()+"_packages", func(t *testing.T) {
			result, err := matcher.MatchPackages(ctx, ref, inventory.Packages, opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) == 0 {
				t.Fatal("known-vulnerable inventory returned no findings")
			}
		})
	}
}
