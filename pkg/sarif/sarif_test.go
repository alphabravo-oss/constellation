package sarif

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestFromScanResult(t *testing.T) {
	res := &scanner.ScanResult{
		ImageRef:  "ghcr.io/test/image:v1",
		StartedAt: time.Now(),
		EndedAt:   time.Now(),
		Findings: []scanner.Finding{
			{
				VulnerabilityID: "CVE-2024-0001",
				Severity:        "critical",
				CVSSBase:        9.8,
				Title:           "glibc heap overflow",
				Description:     "Heap buffer overflow.",
				References:      []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
				Package:         scanner.Package{Ecosystem: "alpine", Name: "glibc", Version: "2.39"},
				FixedVersion:    "2.40",
				KEVListed:       true,
				Engines:         []scanner.EngineProvenance{{Engine: "trivy", Confidence: 0.9}, {Engine: "grype", Confidence: 0.85}},
			},
			{
				VulnerabilityID: "CVE-2024-0002",
				Severity:        "medium",
				CVSSBase:        5.5,
				Title:           "openssl side-channel",
				Package:         scanner.Package{Ecosystem: "alpine", Name: "openssl", Version: "3.0", Purl: "pkg:apk/alpine/openssl@3.0"},
				Engines:         []scanner.EngineProvenance{{Engine: "trivy", Confidence: 0.85}},
			},
		},
	}

	doc := FromScanResult("v0.1.0", res)
	if doc.Version != Version {
		t.Fatalf("version: %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs: %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != ToolName {
		t.Fatalf("driver name: %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules count: %d (expected 2)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("results count: %d", len(run.Results))
	}

	// Critical -> error level
	if run.Results[0].Level != "error" {
		t.Fatalf("critical → level: %q", run.Results[0].Level)
	}
	// Medium -> warning
	if run.Results[1].Level != "warning" {
		t.Fatalf("medium → level: %q", run.Results[1].Level)
	}
	// PURL was preserved
	if run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI != "pkg:apk/alpine/openssl@3.0" {
		t.Fatalf("purl: %q", run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}

	// Schema URI is set and JSON serializes cleanly.
	b, err := MarshalIndent(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"$schema":`) {
		t.Fatalf("missing $schema in marshaled output")
	}
	// Round-trip parses.
	var roundtrip Doc
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
}
