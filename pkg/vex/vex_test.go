package vex

import (
	"encoding/json"
	"testing"
	"time"
)

func TestOpenVEX_StatusMapping(t *testing.T) {
	findings := []Finding{
		{VulnerabilityID: "CVE-2024-0001", Lifecycle: "open", Product: "pkg:apk/alpine/openssl@3.0", UpdatedAt: time.Now()},
		{VulnerabilityID: "CVE-2024-0002", Lifecycle: "suppressed", Product: "pkg:apk/alpine/openssl@3.0", Rationale: "compensating WAF rule", UpdatedAt: time.Now()},
		{VulnerabilityID: "CVE-2024-0003", Lifecycle: "accepted", Product: "pkg:apk/alpine/openssl@3.0", Approver: "alice@example", UpdatedAt: time.Now()},
		{VulnerabilityID: "CVE-2024-0004", Lifecycle: "resolved", Product: "pkg:apk/alpine/openssl@3.0", UpdatedAt: time.Now()},
	}
	doc := OpenVEX("Constellation", findings)
	if doc["@context"] != "https://openvex.dev/ns/v0.2.0" {
		t.Fatalf("@context: %v", doc["@context"])
	}
	stmts := doc["statements"].([]map[string]interface{})
	if len(stmts) != 4 {
		t.Fatalf("statements: %d", len(stmts))
	}
	wantStatus := map[string]string{
		"CVE-2024-0001": "under_investigation",
		"CVE-2024-0002": "not_affected",
		"CVE-2024-0003": "affected",
		"CVE-2024-0004": "fixed",
	}
	for _, s := range stmts {
		vuln := s["vulnerability"].(map[string]string)
		if want := wantStatus[vuln["name"]]; want != s["status"] {
			t.Fatalf("status for %s: got %v want %s", vuln["name"], s["status"], want)
		}
	}
	// Round-trip JSON.
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var rt map[string]interface{}
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatal(err)
	}
}

func TestCycloneDXVEX_ShapeAndAnalysisState(t *testing.T) {
	findings := []Finding{
		{VulnerabilityID: "CVE-2024-1111", Lifecycle: "suppressed", Product: "pkg:apk/alpine/openssl@3.0", Rationale: "not exploitable", UpdatedAt: time.Now()},
	}
	doc := CycloneDXVEX("Constellation", findings)
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.6" {
		t.Fatalf("shape: %v / %v", doc["bomFormat"], doc["specVersion"])
	}
	vulns := doc["vulnerabilities"].([]map[string]interface{})
	if len(vulns) != 1 {
		t.Fatalf("vulns: %d", len(vulns))
	}
	analysis := vulns[0]["analysis"].(map[string]interface{})
	if analysis["state"] != "not_affected" {
		t.Fatalf("state: %v", analysis["state"])
	}
	if analysis["justification"] != "code_not_present" {
		t.Fatalf("justification: %v", analysis["justification"])
	}
	// Round-trip.
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var rt map[string]interface{}
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatal(err)
	}
}

func TestVulnURI_RoutesByIDPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"CVE-2024-1":      "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
		"GHSA-aaaa-bbbb":  "https://github.com/advisories/GHSA-aaaa-bbbb",
		"GO-2024-1":       "https://pkg.go.dev/vuln/GO-2024-1",
		"unknown-format":  "unknown-format",
	} {
		if got := vulnURI(in); got != want {
			t.Fatalf("%s → %s (want %s)", in, got, want)
		}
	}
}
