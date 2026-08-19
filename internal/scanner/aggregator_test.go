package scanner

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// fakeEngine returns canned findings synchronously — lets the aggregator be tested
// without the real syft/trivy/grype CLIs being on PATH.
type fakeEngine struct {
	name    string
	results *EngineResult
	err     error
}

func (f *fakeEngine) Name() string { return f.name }
func (f *fakeEngine) Scan(_ context.Context, _ string, _ ScanOptions) (*EngineResult, error) {
	return f.results, f.err
}

type fakePackageMatcher struct {
	name    string
	results *EngineResult
	err     error
	got     []Package
}

func (f *fakePackageMatcher) Name() string { return f.name }
func (f *fakePackageMatcher) MatchPackages(_ context.Context, _ string, packages []Package, _ ScanOptions) (*EngineResult, error) {
	f.got = append([]Package{}, packages...)
	return f.results, f.err
}

func TestNewDefaultWithConfigSelectsEngines(t *testing.T) {
	defaultAgg := NewDefaultWithConfig(AggregatorConfig{})
	if got, want := engineNames(defaultAgg.Engines), []string{"syft", "trivy", "grype"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default engines = %v, want %v", got, want)
	}
	// The vulndb bundle matcher was removed; Grype's package matcher now fills the
	// canonical package-match slot.
	if got, want := matcherNames(defaultAgg.PackageMatchers), []string{"grype"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default matchers = %v, want %v", got, want)
	}

	// With Grype disabled there is no package matcher at all.
	withoutGrype := NewDefaultWithConfig(AggregatorConfig{DisableGrype: true})
	if got := matcherNames(withoutGrype.PackageMatchers); len(got) != 0 {
		t.Fatalf("matchers with grype disabled = %v, want none", got)
	}
}

func TestScanPackagesRunsMatchersWithoutImageEngines(t *testing.T) {
	packages := []Package{{
		Ecosystem:        "deb",
		Name:             "openssl",
		Version:          "3.0.13-0ubuntu3.5",
		NamespaceKind:    "os",
		NamespaceName:    "ubuntu",
		NamespaceVersion: "24.04",
	}}
	matcher := &fakePackageMatcher{name: "vulndb", results: &EngineResult{
		Engine: "vulndb",
		Findings: []EngineFinding{{
			Engine:          "vulndb",
			VulnerabilityID: "CVE-2026-0101",
			Severity:        "high",
			Package:         packages[0],
			Confidence:      0.95,
		}},
		Confidence: 0.95,
	}}
	a := &Aggregator{PackageMatchers: []PackageMatcher{matcher}}

	res, err := a.ScanPackages(context.Background(), "node-a", packages, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(matcher.got) != 1 || matcher.got[0].Name != "openssl" {
		t.Fatalf("matcher packages = %+v", matcher.got)
	}
	if len(res.Packages) != 1 || res.Packages[0].NamespaceName != "ubuntu" {
		t.Fatalf("result packages = %+v", res.Packages)
	}
	if len(res.Findings) != 1 || res.Findings[0].VulnerabilityID != "CVE-2026-0101" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Findings[0].CanonicalEngine != "vulndb" {
		t.Fatalf("canonical engine = %q", res.Findings[0].CanonicalEngine)
	}
	if len(res.Engines) == 0 || res.Engines[0].Engine != "package-evidence" {
		t.Fatalf("engines = %+v", res.Engines)
	}
}

func engineNames(engines []Engine) []string {
	out := make([]string, 0, len(engines))
	for _, engine := range engines {
		out = append(out, engine.Name())
	}
	return out
}

func matcherNames(matchers []PackageMatcher) []string {
	out := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		out = append(out, matcher.Name())
	}
	return out
}

func TestDedupe_MergesAgreeingEngines(t *testing.T) {
	a := &Aggregator{Engines: []Engine{
		&fakeEngine{name: "trivy", results: &EngineResult{
			Engine: "trivy", Confidence: 0.85,
			Findings: []EngineFinding{{
				Engine: "trivy", VulnerabilityID: "CVE-2024-0001",
				Severity: "high", CVSSBase: 7.5,
				Title:        "from trivy",
				Description:  "trivy description",
				References:   []string{"https://nvd/CVE-2024-0001"},
				Package:      Package{Ecosystem: "alpine", Name: "apk-tools", Version: "2.14.0-r0"},
				FixedVersion: "2.14.1-r0",
				Confidence:   0.85,
			}},
		}},
		&fakeEngine{name: "grype", results: &EngineResult{
			Engine: "grype", Confidence: 0.85,
			Findings: []EngineFinding{{
				Engine: "grype", VulnerabilityID: "cve-2024-0001",
				Severity: "critical", CVSSBase: 9.8,
				Description:  "grype description",
				Package:      Package{Ecosystem: "ALPINE", Name: "apk-tools", Version: "2.14.0-r0"},
				FixedVersion: "2.14.1-r0",
				Confidence:   0.85,
				References:   []string{"https://github.com/advisory/CVE-2024-0001"},
			}},
		}},
		&fakeEngine{name: "syft", results: &EngineResult{
			Engine: "syft", Confidence: 1.0,
			Packages: []Package{{Ecosystem: "alpine", Name: "apk-tools", Version: "2.14.0-r0"}},
		}},
	}}

	res, err := a.Scan(context.Background(), "test:latest", ScanOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(res.Findings))
	}
	got := res.Findings[0]
	if got.VulnerabilityID != "CVE-2024-0001" {
		t.Fatalf("cve id: %q", got.VulnerabilityID)
	}
	// Severity = max(high, critical)
	if got.Severity != "critical" {
		t.Fatalf("severity: %q (expected critical)", got.Severity)
	}
	// CVSS = max(7.5, 9.8)
	if got.CVSSBase != 9.8 {
		t.Fatalf("cvss: %f", got.CVSSBase)
	}
	// Title comes from trivy (it set Title first)
	if got.Title != "from trivy" {
		t.Fatalf("title: %q", got.Title)
	}
	// References from both engines merged dedup'd
	if len(got.References) != 2 {
		t.Fatalf("references count: %d (expected 2)", len(got.References))
	}
	// Engines provenance lists both (sorted by name)
	if len(got.Engines) != 2 || got.Engines[0].Engine != "grype" || got.Engines[1].Engine != "trivy" {
		t.Fatalf("engines provenance: %+v", got.Engines)
	}
	if got.CanonicalEngine != "aggregate" {
		t.Fatalf("canonical engine = %q, want aggregate", got.CanonicalEngine)
	}
	if got.Engines[0].Role != EngineRoleCanonical || got.Engines[1].Role != EngineRoleCanonical {
		t.Fatalf("engine roles: %+v", got.Engines)
	}
	// Packages from syft preserved
	if len(res.Packages) != 1 || res.Packages[0].Name != "apk-tools" {
		t.Fatalf("packages: %+v", res.Packages)
	}
}

func TestDedupe_PrefersVulnDBCanonicalFields(t *testing.T) {
	findings := dedupe([]EngineResult{
		{
			Engine: "trivy",
			Findings: []EngineFinding{{
				Engine:          "trivy",
				VulnerabilityID: "CVE-2026-0002",
				Severity:        "critical",
				CVSSBase:        9.8,
				CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Title:           "trivy title",
				Description:     "trivy description",
				References:      []string{"https://scanner.example/CVE-2026-0002"},
				Package:         Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.0"},
				FixedVersion:    "3.0.3",
				AffectedRange: &AffectedRange{
					Source:            "trivy",
					NamespaceKind:     "os",
					NamespaceName:     "ubuntu",
					NamespaceVersion:  "24.04",
					VersionScheme:     "deb",
					RangeType:         "introduced_fixed",
					IntroducedVersion: "0",
					FixedVersion:      "3.0.3",
					FixState:          "fixed",
				},
				Confidence: 0.85,
			}},
		},
		{
			Engine: "vulndb",
			Findings: []EngineFinding{{
				Engine:          "vulndb",
				VulnerabilityID: "CVE-2026-0002",
				Aliases:         []string{"USN-0002-1"},
				Severity:        "high",
				CVSSBase:        7.5,
				CVSSVector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Title:           "vulndb advisory",
				Description:     "vulndb description",
				References:      []string{"https://vulndb.example/CVE-2026-0002"},
				Package: Package{
					Ecosystem:        "deb",
					Name:             "openssl",
					Version:          "3.0.0",
					NamespaceKind:    "os",
					NamespaceName:    "ubuntu",
					NamespaceVersion: "24.04",
				},
				FixedVersion: "3.0.2",
				AffectedRange: &AffectedRange{
					Source:            "ubuntu",
					NamespaceKind:     "os",
					NamespaceName:     "ubuntu",
					NamespaceVersion:  "24.04",
					VersionScheme:     "deb",
					RangeType:         "introduced_fixed",
					IntroducedVersion: "0",
					FixedVersion:      "3.0.2",
					FixState:          "fixed",
				},
				Confidence: 0.99,
			}},
		},
	})

	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.CanonicalEngine != "vulndb" {
		t.Fatalf("canonical engine = %q, want vulndb", got.CanonicalEngine)
	}
	if got.Severity != "high" || got.CVSSBase != 7.5 || got.Title != "vulndb advisory" || got.FixedVersion != "3.0.2" {
		t.Fatalf("canonical fields came from wrong source: %+v", got)
	}
	if got.Package.NamespaceName != "ubuntu" || got.Package.NamespaceVersion != "24.04" {
		t.Fatalf("package namespace = %+v, want vulndb namespace", got.Package)
	}
	if got.AffectedRange == nil || got.AffectedRange.Source != "ubuntu" || got.AffectedRange.FixedVersion != "3.0.2" {
		t.Fatalf("affected range = %+v, want canonical vulndb range", got.AffectedRange)
	}
	if len(got.References) != 2 {
		t.Fatalf("references = %+v, want vulndb plus evidence references", got.References)
	}
	if len(got.Engines) != 2 {
		t.Fatalf("provenance = %+v, want two engines", got.Engines)
	}
	if got.Engines[0].Engine != "vulndb" || got.Engines[0].Role != EngineRoleCanonical {
		t.Fatalf("first provenance = %+v, want canonical vulndb", got.Engines[0])
	}
	if got.Engines[1].Engine != "trivy" || got.Engines[1].Role != EngineRoleEvidence {
		t.Fatalf("second provenance = %+v, want trivy evidence", got.Engines[1])
	}
	wantSignals := map[string]string{
		"severity":       "high/critical",
		"cvss_base":      "7.5/9.8",
		"fixed_version":  "3.0.2/3.0.3",
		"affected_range": "ubuntu:introduced_fixed:introduced=0,fixed=3.0.2/trivy:introduced_fixed:introduced=0,fixed=3.0.3",
	}
	for _, signal := range got.Reconciliation {
		if signal.Engine != "trivy" {
			t.Fatalf("reconciliation engine = %q, want trivy: %+v", signal.Engine, got.Reconciliation)
		}
		want, ok := wantSignals[signal.Field]
		if !ok {
			t.Fatalf("unexpected reconciliation signal: %+v", signal)
		}
		if gotValue := signal.Canonical + "/" + signal.Evidence; gotValue != want {
			t.Fatalf("reconciliation %s = %s, want %s", signal.Field, gotValue, want)
		}
		delete(wantSignals, signal.Field)
	}
	if len(wantSignals) != 0 {
		t.Fatalf("missing reconciliation signals: %v in %+v", wantSignals, got.Reconciliation)
	}
}

func TestAggregator_RunsPackageMatchersAfterSyft(t *testing.T) {
	matcher := &fakePackageMatcher{
		name: "vulndb",
		results: &EngineResult{
			Engine: "vulndb",
			Findings: []EngineFinding{{
				Engine:          "vulndb",
				VulnerabilityID: "CVE-2026-0001",
				Severity:        "high",
				Package:         Package{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
				Confidence:      0.95,
			}},
		},
	}
	a := &Aggregator{
		Engines: []Engine{
			&fakeEngine{name: "syft", results: &EngineResult{
				Engine:   "syft",
				Packages: []Package{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}},
			}},
		},
		PackageMatchers: []PackageMatcher{matcher},
	}
	res, err := a.Scan(context.Background(), "x:y", ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(matcher.got) != 1 || matcher.got[0].Name != "left-pad" {
		t.Fatalf("matcher packages: %+v", matcher.got)
	}
	if len(res.Findings) != 1 || res.Findings[0].VulnerabilityID != "CVE-2026-0001" {
		t.Fatalf("findings: %+v", res.Findings)
	}
	if len(res.Findings[0].Engines) != 1 || res.Findings[0].Engines[0].Engine != "vulndb" {
		t.Fatalf("provenance: %+v", res.Findings[0].Engines)
	}
	if res.Findings[0].CanonicalEngine != "vulndb" || res.Findings[0].Engines[0].Role != EngineRoleCanonical {
		t.Fatalf("canonical provenance: %+v", res.Findings[0])
	}
}

func TestDedupe_SortsBySeverityThenCVSS(t *testing.T) {
	a := &Aggregator{Engines: []Engine{
		&fakeEngine{name: "trivy", results: &EngineResult{Findings: []EngineFinding{
			{VulnerabilityID: "CVE-A", Severity: "low", CVSSBase: 9.0, Package: Package{Name: "a", Version: "1"}},
			{VulnerabilityID: "CVE-B", Severity: "critical", CVSSBase: 7.5, Package: Package{Name: "b", Version: "1"}},
			{VulnerabilityID: "CVE-C", Severity: "high", CVSSBase: 8.5, Package: Package{Name: "c", Version: "1"}},
		}}},
	}}
	res, err := a.Scan(context.Background(), "x:y", ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{res.Findings[0].VulnerabilityID, res.Findings[1].VulnerabilityID, res.Findings[2].VulnerabilityID}; got[0] != "CVE-B" || got[1] != "CVE-C" || got[2] != "CVE-A" {
		t.Fatalf("sort order: %v", got)
	}
}

func TestAggregator_EngineFailureNonFatal(t *testing.T) {
	a := &Aggregator{Engines: []Engine{
		&fakeEngine{name: "trivy", err: errAlways("trivy unreachable")},
		&fakeEngine{name: "syft", results: &EngineResult{Engine: "syft", Packages: []Package{{Name: "ok", Version: "1"}}}},
	}}
	res, err := a.Scan(context.Background(), "x:y", ScanOptions{})
	if err != nil {
		t.Fatalf("expected non-fatal failure with usable syft output: %v", err)
	}
	if len(res.Packages) != 1 {
		t.Fatalf("expected syft packages to survive trivy failure: %+v", res.Packages)
	}
}

// VLN-1: a missing/corrupt VulnDB store must fail the scan when require-vulndb is
// set, even though syft (and evidence-only engines) returned usable output —
// otherwise an evidence-only "success" overwrites the prior good scan.
func TestAggregator_RequireVulnDB_FailsOnVulnDBMatcherError(t *testing.T) {
	build := func() *Aggregator {
		return &Aggregator{
			Engines: []Engine{
				&fakeEngine{name: "syft", results: &EngineResult{
					Engine:   "syft",
					Packages: []Package{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}},
				}},
				&fakeEngine{name: "trivy", results: &EngineResult{Findings: []EngineFinding{
					{VulnerabilityID: "CVE-2026-0009", Severity: "high", Package: Package{Name: "left-pad", Version: "1.0.0"}},
				}}},
			},
			PackageMatchers: []PackageMatcher{
				&fakePackageMatcher{name: "vulndb", err: errAlways("vulndb: open /tmp/x.bbolt: corrupt")},
			},
		}
	}

	// require-vulndb set: must fail despite syft packages + trivy evidence.
	res, err := build().Scan(context.Background(), "x:y", ScanOptions{RequireVulnDB: true})
	if err == nil {
		t.Fatalf("expected scan to fail when require-vulndb set and vulndb matcher errored; got findings=%d", len(res.Findings))
	}
	if len(res.Packages) != 1 {
		t.Fatalf("expected syft packages preserved on the degraded result: %+v", res.Packages)
	}

	// require-vulndb clear: unchanged behavior, evidence-only success is fine.
	if _, err := build().Scan(context.Background(), "x:y", ScanOptions{}); err != nil {
		t.Fatalf("expected success when require-vulndb unset: %v", err)
	}
}

// VLN-2: a non-fatal Syft failure leaves the SBOM empty, so the package-matcher loop
// is skipped and the vulndb matcher never runs. Under require-vulndb that MUST fail
// rather than record a Trivy/Grype-only "success" that overwrites a prior good scan.
func TestAggregator_RequireVulnDB_FailsOnEmptySBOM(t *testing.T) {
	build := func() *Aggregator {
		return &Aggregator{
			Engines: []Engine{
				// Syft "succeeded" but produced no inventory (e.g. a tolerated failure).
				&fakeEngine{name: "syft", results: &EngineResult{Engine: "syft"}},
				&fakeEngine{name: "trivy", results: &EngineResult{Findings: []EngineFinding{
					{VulnerabilityID: "CVE-2026-0042", Severity: "critical", Package: Package{Name: "openssl", Version: "3.0.0"}},
				}}},
			},
			PackageMatchers: []PackageMatcher{
				&fakePackageMatcher{name: "vulndb", results: &EngineResult{Engine: "vulndb"}},
			},
		}
	}

	res, err := build().Scan(context.Background(), "x:y", ScanOptions{RequireVulnDB: true})
	if err == nil {
		t.Fatalf("expected scan to fail: require-vulndb set, empty SBOM, vulndb matcher never ran; got findings=%d", len(res.Findings))
	}

	// require-vulndb clear: an evidence-only result is acceptable (unchanged behavior).
	if _, err := build().Scan(context.Background(), "x:y", ScanOptions{}); err != nil {
		t.Fatalf("expected success when require-vulndb unset: %v", err)
	}

	// No vulndb matcher attached: require-vulndb has nothing to enforce -> no failure.
	noVulnDB := &Aggregator{
		Engines: []Engine{
			&fakeEngine{name: "syft", results: &EngineResult{Engine: "syft"}},
			&fakeEngine{name: "trivy", results: &EngineResult{Findings: []EngineFinding{
				{VulnerabilityID: "CVE-2026-0042", Severity: "high", Package: Package{Name: "openssl", Version: "3.0.0"}},
			}}},
		},
	}
	if _, err := noVulnDB.Scan(context.Background(), "x:y", ScanOptions{RequireVulnDB: true}); err != nil {
		t.Fatalf("require-vulndb with no vulndb matcher attached must not fail: %v", err)
	}
}

// VLN-3: a VulnDB GHSA finding (alias CVE-X) and a Trivy CVE-X for the SAME package
// must collapse into ONE finding via the alias set, with VulnDB canonical and Trivy
// demoted to evidence — not double-counted in two buckets.
func TestDedupe_MergesAliasEquivalentFindings(t *testing.T) {
	pkg := Package{Ecosystem: "go", Name: "golang.org/x/net", Version: "0.17.0"}
	findings := dedupe([]EngineResult{
		{
			Engine: "trivy",
			Findings: []EngineFinding{{
				Engine:          "trivy",
				VulnerabilityID: "CVE-2024-1234",
				Severity:        "high",
				CVSSBase:        7.5,
				Package:         pkg,
				Confidence:      0.85,
			}},
		},
		{
			Engine: "vulndb",
			Findings: []EngineFinding{{
				Engine:          "vulndb",
				VulnerabilityID: "GHSA-aaaa-bbbb-cccc",
				Aliases:         []string{"CVE-2024-1234"},
				Severity:        "critical",
				CVSSBase:        9.1,
				Package:         pkg,
				Confidence:      0.99,
			}},
		},
	})

	if len(findings) != 1 {
		t.Fatalf("alias-equivalent findings must merge into one bucket, got %d: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.CanonicalEngine != "vulndb" {
		t.Fatalf("canonical engine = %q, want vulndb", got.CanonicalEngine)
	}
	if got.VulnerabilityID != "GHSA-aaaa-bbbb-cccc" {
		t.Fatalf("canonical id = %q, want the VulnDB GHSA id", got.VulnerabilityID)
	}
	// The CVE alias is retained for cross-referencing.
	foundCVE := false
	for _, a := range got.Aliases {
		if a == "CVE-2024-1234" {
			foundCVE = true
		}
	}
	if !foundCVE {
		t.Fatalf("merged finding must retain the CVE alias, aliases=%v", got.Aliases)
	}
	if len(got.Engines) != 2 {
		t.Fatalf("both engines must appear in provenance, got %+v", got.Engines)
	}
	var trivyRole string
	for _, e := range got.Engines {
		if e.Engine == "trivy" {
			trivyRole = e.Role
		}
	}
	if trivyRole != EngineRoleEvidence {
		t.Fatalf("trivy must be demoted to evidence, role=%q", trivyRole)
	}
}

type errAlways string

func (e errAlways) Error() string { return string(e) }
