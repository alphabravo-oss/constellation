package scanner

import (
	"crypto/sha256"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// Run the compiled test in a container with --network none and isolated copies
// of preloaded engine caches. Restart that container with the same private caches
// to qualify process replacement separately from the default unit suite.
func TestBundledPackageMatchersOffline(t *testing.T) {
	if os.Getenv("CONSTELLATION_TEST_OFFLINE_MATCHERS") != "true" {
		t.Skip("set CONSTELLATION_TEST_OFFLINE_MATCHERS=true with real tools and isolated preloaded caches")
	}
	t.Setenv("CONSTELLATION_SCANNER_OFFLINE_DB", "true")
	t.Setenv("GRYPE_DB_AUTO_UPDATE", "false")
	for _, key := range []string{"TRIVY_CACHE_DIR", "GRYPE_DB_CACHE_DIR"} {
		if os.Getenv(key) == "" {
			t.Fatalf("explicit isolated %s required", key)
		}
	}
	packages := []Package{{Name: "lodash", Version: "4.17.19", Ecosystem: "npm", Purl: "pkg:npm/lodash@4.17.19"}}
	for _, matcher := range []PackageMatcher{&TrivyPackageMatcher{}, &GrypePackageMatcher{}} {
		t.Run(matcher.Name(), func(t *testing.T) {
			var baseline string
			for pass := range 2 {
				started := time.Now()
				result, err := matcher.MatchPackages(t.Context(), "offline-cache-fixture", packages, ScanOptions{Timeout: 3 * time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				if len(result.Findings) == 0 {
					t.Fatal("known-vulnerable offline fixture produced no findings")
				}
				ids := make([]string, 0, len(result.Findings))
				for _, finding := range result.Findings {
					if finding.VulnerabilityID == "" || finding.Package.Name != "lodash" {
						t.Fatal("offline matcher returned incomplete or unrelated findings")
					}
					ids = append(ids, finding.VulnerabilityID+":"+finding.Package.Name+"@"+finding.Package.Version)
				}
				slices.Sort(ids)
				digest := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(ids, "\n"))))
				if pass > 0 && digest != baseline {
					t.Fatal("offline repeat changed findings with the same database")
				}
				baseline = digest
				t.Logf("engine=%s pass=%d findings=%d digest=%s elapsed=%s", matcher.Name(), pass, len(ids), digest, time.Since(started))
			}
			key := "TRIVY_CACHE_DIR"
			if matcher.Name() == "grype" {
				key = "GRYPE_DB_CACHE_DIR"
			}
			t.Setenv(key, t.TempDir())
			if _, err := matcher.MatchPackages(t.Context(), "offline-cache-fixture", packages, ScanOptions{Timeout: time.Minute}); err == nil {
				t.Fatal("missing offline database reported a successful scan")
			}
		})
	}
}
