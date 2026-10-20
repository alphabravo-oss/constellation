package scanner

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// Exercise the actual engine JSON adapters before reconciliation. Directly
// populating EngineFinding.Aliases would hide the parser omission this fixes.
func TestEngineReportsReconcileGoLabelsAndDeclaredAliases(t *testing.T) {
	var grype grypeReport
	if err := json.Unmarshal([]byte(`{"matches":[
 {"vulnerability":{"id":"GHSA-pxq6-2prw-chj9","severity":"Medium"},"relatedVulnerabilities":[{"id":"CVE-2026-33997"}],"artifact":{"type":"go-module","name":"github.com/docker/docker","version":"v28.5.2+incompatible"}},
 {"vulnerability":{"id":"GO-2026-5932","severity":"Unknown"},"artifact":{"type":"go-module","name":"golang.org/x/crypto","version":"v0.57.0"}}
 ]}`), &grype); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"gobinary", "gomod"} {
		t.Run(kind, func(t *testing.T) {
			var trivy trivyReport
			raw := `{"Results":[{"Type":"` + kind + `","Class":"lang-pkgs","Vulnerabilities":[
    {"VulnerabilityID":"CVE-2026-33997","PkgName":"github.com/docker/docker","InstalledVersion":"v28.5.2+incompatible","Severity":"HIGH","FixedVersion":"29.3.1"},
    {"VulnerabilityID":"GO-2026-5932","PkgName":"golang.org/x/crypto","InstalledVersion":"v0.57.0","Severity":"UNKNOWN"}
   ]}]}`
			if err := json.Unmarshal([]byte(raw), &trivy); err != nil {
				t.Fatal(err)
			}
			engines := []EngineResult{{Engine: "trivy", Findings: findingsFromTrivyReport(trivy, "")}, {Engine: "grype", Findings: findingsFromGrypeReport(grype, "")}}
			for _, reverse := range []bool{false, true} {
				if reverse {
					engines[0], engines[1] = engines[1], engines[0]
				}
				findings := dedupe(engines)
				if len(findings) != 2 {
					t.Fatalf("expected two distinct advisories, got %+v", findings)
				}
				for _, finding := range findings {
					if len(finding.Engines) != 2 {
						t.Fatalf("lost engine provenance: %+v", finding)
					}
					if finding.Package.Name == "github.com/docker/docker" {
						ids := vulnIDSet(finding.VulnerabilityID, finding.Aliases)
						sort.Strings(ids)
						if !reflect.DeepEqual(ids, []string{"CVE-2026-33997", "GHSA-PXQ6-2PRW-CHJ9"}) {
							t.Fatalf("lost advisory identity: %v", ids)
						}
						if finding.Severity != "high" || finding.FixedVersion != "29.3.1" {
							t.Fatalf("lost severity or fix evidence: %+v", finding)
						}
					}
				}
			}
		})
	}
}

func TestGrypeAliasesDoNotCollapseGroupedOrAmbiguousAdvisories(t *testing.T) {
	cases := []struct {
		primary string
		related []string
		want    []string
	}{
		{"GO-2026-4887", []string{"CVE-2026-34040", "GHSA-x744-4wpc-v9h2", "cve-2026-34040", "", "https://example.test/CVE-2026-0001"}, []string{"CVE-2026-34040", "GHSA-X744-4WPC-V9H2"}},
		{"RHSA-2026:1234", []string{"CVE-2026-0001", "CVE-2026-0002"}, nil},
		{"GHSA-aaaa-bbbb-cccc", []string{"CVE-2026-0001", "CVE-2026-0002"}, nil},
		{"CVE-2026-0001", []string{"CVE-2026-0002"}, nil},
		{"GO-2026-4887", []string{"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"}, nil},
	}
	for _, tc := range cases {
		related := make([]grypeVuln, 0, len(tc.related))
		for _, id := range tc.related {
			related = append(related, grypeVuln{ID: id})
		}
		if got := grypeAliases(tc.primary, related); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s aliases = %v, want %v", tc.primary, got, tc.want)
		}
	}
}

func TestAliasReconciliationPreservesPackageAndAdvisoryBoundaries(t *testing.T) {
	base := EngineFinding{Engine: "grype", VulnerabilityID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-0001"}, Package: Package{Ecosystem: "go-module", Name: "example.test/module", Version: "v1.0.0"}}
	all := []EngineFinding{base}
	for _, change := range []func(*EngineFinding){
		func(f *EngineFinding) { f.Package.Version = "v2.0.0" },
		func(f *EngineFinding) { f.Package.Name = "example.test/other" },
		func(f *EngineFinding) { f.Package.Ecosystem = "npm" },
		func(f *EngineFinding) { f.VulnerabilityID = "CVE-2026-0002"; f.Aliases = nil },
	} {
		f := base
		change(&f)
		all = append(all, f)
	}
	if got := dedupe([]EngineResult{{Engine: "grype", Findings: all}}); len(got) != 5 {
		t.Fatalf("distinct evidence collapsed: %+v", got)
	}
}
