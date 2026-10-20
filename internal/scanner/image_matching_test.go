package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type imageFallbackStub struct {
	fakePackageMatcher
	raw []byte
}

func (m *imageFallbackStub) ImageEngineName() string { return m.name }
func (m *imageFallbackStub) MatchSBOM(_ context.Context, _ string, raw []byte, _ ScanOptions) (*EngineResult, error) {
	m.raw = append([]byte{}, raw...)
	return m.results, m.err
}

func TestImageMatchingKeepsPreciseResultsAndFallbackEvidence(t *testing.T) {
	for _, tc := range []struct {
		name         string
		image        bool
		imageErr     error
		payloadErr   string
		raw          []byte
		wantFallback bool
	}{
		{name: "clean image", image: true},
		{name: "failed image uses native SBOM", image: true, imageErr: errors.New("pull failed"), raw: []byte(`{"artifacts":[{"metadata":{"symbols":{"pkg":["Func"]}}}]}`), wantFallback: true},
		{name: "absent image uses native SBOM", raw: []byte(`{"artifacts":[]}`), wantFallback: true},
		{name: "missing native evidence uses packages", wantFallback: true},
		{name: "error payload is not success", image: true, payloadErr: "incomplete", wantFallback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := Package{Name: "golang.org/x/crypto", Version: "v1", Ecosystem: "go-module"}
			broad := EngineFinding{Engine: "grype", VulnerabilityID: "GO-2026-5932", Package: pkg}
			fallback := &imageFallbackStub{fakePackageMatcher: fakePackageMatcher{name: "grype", results: &EngineResult{Engine: "grype", Findings: []EngineFinding{broad}}}}
			a := Aggregator{Engines: []Engine{&fakeEngine{name: "syft", results: &EngineResult{Engine: "syft", Packages: []Package{pkg}, Raw: tc.raw}}}, PackageMatchers: []PackageMatcher{fallback}}
			if tc.image {
				a.Engines = append(a.Engines, &fakeEngine{name: "grype", results: &EngineResult{Engine: "grype", Error: tc.payloadErr}, err: tc.imageErr})
			}
			r, err := a.Scan(t.Context(), "registry.test/app:1", ScanOptions{})
			if err != nil {
				t.Fatal(err)
			}
			called := fallback.raw != nil || fallback.got != nil
			if called != tc.wantFallback {
				t.Fatalf("fallback=%v want %v", called, tc.wantFallback)
			}
			if tc.wantFallback {
				if len(r.Findings) != 1 {
					t.Fatalf("fallback findings lost: %+v", r.Findings)
				}
				if len(tc.raw) > 0 && string(fallback.raw) != string(tc.raw) {
					t.Fatal("native evidence changed")
				}
				if len(tc.raw) == 0 && len(fallback.got) != 1 {
					t.Fatal("missing evidence did not retain conservative package matching")
				}
			} else if len(r.Findings) != 0 {
				t.Fatal("broad package match overrode clean image result")
			}
		})
	}
}

func TestImageMatchingDoesNotSkipIndependentMatcherOrHostEvidence(t *testing.T) {
	pkg := Package{Name: "lib", Version: "1", Ecosystem: "go-module"}
	result := &EngineResult{Engine: "grype", Findings: []EngineFinding{{Engine: "grype", VulnerabilityID: "CVE-2026-12345", Package: pkg}}}
	independent := &fakePackageMatcher{name: "grype", results: result}
	a := Aggregator{Engines: []Engine{&fakeEngine{name: "syft", results: &EngineResult{Engine: "syft", Packages: []Package{pkg}}}, &fakeEngine{name: "grype", results: &EngineResult{Engine: "grype"}}}, PackageMatchers: []PackageMatcher{independent}}
	if _, err := a.Scan(t.Context(), "image", ScanOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(independent.got) != 1 {
		t.Fatal("independent matcher skipped by name alone")
	}
	fallback := &imageFallbackStub{fakePackageMatcher: fakePackageMatcher{name: "grype", results: result}}
	a.PackageMatchers = []PackageMatcher{fallback}
	r, err := a.ScanPackages(t.Context(), "host", []Package{pkg}, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fallback.got) != 1 || len(r.Findings) != 1 {
		t.Fatal("host package matching changed")
	}
}

func TestGrypeNativeSBOMPassesSymbolsUnchanged(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "captured.json")
	bin := filepath.Join(dir, "grype")
	t.Setenv("CAPTURE", capture)
	script := "#!/bin/sh\nset -eu\ncat \"${1#sbom:}\" > \"$CAPTURE\"\nprintf '%s' '{\"matches\":[]}'\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"artifacts":[{"metadata":{"symbols":{"golang.org/x/crypto/ssh":["ParsePrivateKey"]}}}],"schema":{"version":"16.1.11"}}`)
	if _, err := (&GrypePackageMatcher{Binary: bin}).MatchSBOM(t.Context(), "image", raw, ScanOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(capture)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("SBOM changed: %s %v", got, err)
	}
	if _, err := (&GrypePackageMatcher{Binary: bin}).MatchSBOM(t.Context(), "image", []byte("invalid"), ScanOptions{}); err == nil {
		t.Fatal("invalid SBOM accepted")
	}
}

func TestSyftCapturesGoSymbolsDespiteAmbientOverride(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "syft")
	script := "#!/bin/sh\nset -eu\ntest \"$SYFT_GOLANG_CAPTURE_SYMBOLS\" = all\nprintf '%s' '{\"artifacts\":[]}'\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYFT_GOLANG_CAPTURE_SYMBOLS", "none")
	if _, err := (&SyftEngine{Binary: bin}).Scan(t.Context(), "image", ScanOptions{}); err != nil {
		t.Fatal(err)
	}
}
