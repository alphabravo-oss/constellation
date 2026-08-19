package scanner

import (
	"encoding/json"
	"testing"
	"time"
)

// TestMatchersThreadPublishedDate asserts each matcher carries the CVE/advisory
// publish date onto EngineFinding.Published (source date form for grype/trivy)
// and omits it — leaving Published empty — when the matcher
// supplies no date. This is the value the aggregator promotes onto the canonical
// Finding and that scannerFindingDetail persists into
// image_scan_findings.detail_json->>'published', which the admission grace-window
// reads (missing => "count it", the safe default).
func TestMatchersThreadPublishedDate(t *testing.T) {
	t.Run("trivy", func(t *testing.T) {
		doc := trivyReport{Results: []trivyResult{{
			Type: "ubuntu",
			Vulnerabilities: []trivyVulnerability{{
				VulnerabilityID: "CVE-2026-3000",
				PkgName:         "openssl",
				PublishedDate:   "2026-01-02T15:04:05Z",
			}, {
				VulnerabilityID: "CVE-2026-3001",
				PkgName:         "left-pad",
			}},
		}}}
		findings := findingsFromTrivyReport(doc, "")
		withDate := findingByPackage(findings, "openssl")
		if withDate == nil || withDate.Published != "2026-01-02T15:04:05Z" {
			t.Fatalf("trivy published = %+v", withDate)
		}
		noDate := findingByPackage(findings, "left-pad")
		if noDate == nil || noDate.Published != "" {
			t.Fatalf("trivy published should be empty when absent: %+v", noDate)
		}
	})

	t.Run("grype", func(t *testing.T) {
		var doc grypeReport
		doc.Matches = append(doc.Matches, struct {
			Vulnerability grypeVuln     `json:"vulnerability"`
			Artifact      grypeArtifact `json:"artifact"`
		}{
			Vulnerability: grypeVuln{ID: "CVE-2026-4000", Published: "2026-02-03T00:00:00Z"},
			Artifact:      grypeArtifact{Name: "openssl", Version: "3.0.13", Type: "deb"},
		}, struct {
			Vulnerability grypeVuln     `json:"vulnerability"`
			Artifact      grypeArtifact `json:"artifact"`
		}{
			Vulnerability: grypeVuln{ID: "CVE-2026-4001"},
			Artifact:      grypeArtifact{Name: "left-pad", Version: "1.0.0", Type: "npm"},
		})
		findings := findingsFromGrypeReport(doc, "")
		withDate := findingByPackage(findings, "openssl")
		if withDate == nil || withDate.Published != "2026-02-03T00:00:00Z" {
			t.Fatalf("grype published = %+v", withDate)
		}
		noDate := findingByPackage(findings, "left-pad")
		if noDate == nil || noDate.Published != "" {
			t.Fatalf("grype published should be empty when absent: %+v", noDate)
		}
	})

}

// TestDedupePromotesPublishedOntoCanonicalFinding asserts the aggregator carries
// the matcher's publish date onto the canonical Finding (preferring VulnDB), so it
// survives into detail_json, and that the persisted value is the RFC3339-shaped
// string the grace-window SQL expects (its regex anchors on ^YYYY-MM-DD).
func TestDedupePromotesPublishedOntoCanonicalFinding(t *testing.T) {
	pkg := Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.13"}
	engines := []EngineResult{
		{Engine: "trivy", Findings: []EngineFinding{{
			Engine: "trivy", VulnerabilityID: "CVE-2026-6000", Package: pkg,
			Published: "2026-05-06T00:00:00Z", Confidence: 0.85,
		}}},
		{Engine: "vulndb", Findings: []EngineFinding{{
			Engine: "vulndb", VulnerabilityID: "CVE-2026-6000", Package: pkg,
			Published: "2026-06-07T08:09:10Z", Confidence: 0.95,
		}}},
	}
	findings := dedupe(engines)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	got := findings[0]
	// VulnDB is canonical, so its publish date wins.
	if got.Published != "2026-06-07T08:09:10Z" {
		t.Fatalf("canonical published = %q, want vulndb date", got.Published)
	}

	// The persisted detail_json shape: scannerFindingDetail emits the key only when
	// non-empty, mirrored here to prove the value lands under "published" and is
	// parseable as the grace-window's timestamptz.
	detail := map[string]any{}
	if got.Published != "" {
		detail["published"] = got.Published
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back["published"] != "2026-06-07T08:09:10Z" {
		t.Fatalf("detail_json published = %v", back["published"])
	}
	if _, err := time.Parse(time.RFC3339, back["published"].(string)); err != nil {
		t.Fatalf("published not RFC3339: %v", err)
	}
}
