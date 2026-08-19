package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestSPDX2_3(t *testing.T) {
	res := &scanner.ScanResult{
		ImageRef: "ghcr.io/test/img:1",
		Packages: []scanner.Package{
			{
				Ecosystem: "alpine",
				Name:      "apk-tools",
				Version:   "2.14.1",
				Licenses:  []string{"MIT"},
				Purl:      "pkg:apk/alpine/apk-tools@2.14.1",
				Locations: []scanner.PackageLocation{{
					Path:        "/lib/apk/db/installed",
					LayerDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				}},
			},
			{Ecosystem: "alpine", Name: "musl", Version: "1.2.5"},
		},
	}
	doc := SPDX2_3("v0.1.0", res)

	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("spdx version: %v", doc["spdxVersion"])
	}
	pkgs := doc["packages"].([]map[string]interface{})
	if len(pkgs) != 3 { // root image + 2 pkgs
		t.Fatalf("packages count: %d", len(pkgs))
	}
	rel := doc["relationships"].([]map[string]interface{})
	if len(rel) != 3 { // DESCRIBES + 2 CONTAINS
		t.Fatalf("relationships count: %d", len(rel))
	}
	if pkgs[1]["licenseConcluded"] != "MIT" {
		t.Fatalf("license: %v", pkgs[1]["licenseConcluded"])
	}
	annotations, ok := pkgs[1]["annotations"].([]map[string]interface{})
	if !ok || len(annotations) != 1 {
		t.Fatalf("annotations: %#v", pkgs[1]["annotations"])
	}
	if comment, _ := annotations[0]["comment"].(string); !strings.Contains(comment, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("annotation comment = %q", comment)
	}
	// Round-trip JSON.
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip map[string]interface{}
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatal(err)
	}
}

func TestCycloneDX1_6(t *testing.T) {
	res := &scanner.ScanResult{
		ImageRef: "ghcr.io/test/img:1",
		Packages: []scanner.Package{
			{
				Ecosystem: "go",
				Name:      "stdlib",
				Version:   "1.26.0",
				Locations: []scanner.PackageLocation{{
					Path:        "/usr/local/go/VERSION",
					LayerDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				}},
			},
		},
		Findings: []scanner.Finding{
			{
				VulnerabilityID: "CVE-2024-9999",
				Severity:        "high",
				CVSSBase:        7.5,
				CVSSVector:      "CVSS:3.1/AV:N",
				Description:     "demo",
				Package:         scanner.Package{Ecosystem: "go", Name: "stdlib", Version: "1.26.0"},
			},
		},
	}
	doc := CycloneDX1_6("v0.1.0", res)
	if doc["bomFormat"] != "CycloneDX" {
		t.Fatalf("bomFormat: %v", doc["bomFormat"])
	}
	if doc["specVersion"] != "1.6" {
		t.Fatalf("specVersion: %v", doc["specVersion"])
	}
	if len(doc["components"].([]map[string]interface{})) != 1 {
		t.Fatalf("components")
	}
	props, ok := doc["components"].([]map[string]interface{})[0]["properties"].([]map[string]string)
	if !ok || len(props) == 0 {
		t.Fatalf("component properties: %#v", doc["components"].([]map[string]interface{})[0]["properties"])
	}
	foundLayerDigest := false
	for _, prop := range props {
		if prop["name"] == "constellation:package:location:0:layer_digest" && prop["value"] == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
			foundLayerDigest = true
		}
	}
	if !foundLayerDigest {
		t.Fatalf("component properties missing layer digest: %#v", props)
	}
	if len(doc["vulnerabilities"].([]map[string]interface{})) != 1 {
		t.Fatalf("vulnerabilities")
	}
	// Round-trip JSON.
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip map[string]interface{}
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatal(err)
	}
}
