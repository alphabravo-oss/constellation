package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindingsFromTrivyReportFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "trivy", "ubuntu-24.04.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc trivyReport
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	findings := findingsFromTrivyReport(doc, "")
	if len(findings) != 2 {
		t.Fatalf("findings count = %d, want 2: %+v", len(findings), findings)
	}

	openssl := findingByPackage(findings, "openssl")
	if openssl == nil {
		t.Fatalf("openssl finding not found: %+v", findings)
	}
	if openssl.Engine != "trivy" || openssl.VulnerabilityID != "CVE-2026-1000" {
		t.Fatalf("identity = engine:%q vuln:%q", openssl.Engine, openssl.VulnerabilityID)
	}
	if openssl.Severity != "high" || openssl.Title != "openssl test advisory" {
		t.Fatalf("severity/title = %q/%q", openssl.Severity, openssl.Title)
	}
	if openssl.Package.Ecosystem != "ubuntu" || openssl.Package.Name != "openssl" || openssl.Package.Version != "3.0.13-0ubuntu3.1" {
		t.Fatalf("package = %+v", openssl.Package)
	}
	if openssl.FixedVersion != "3.0.13-0ubuntu3.2" {
		t.Fatalf("fixed version = %q", openssl.FixedVersion)
	}
	if openssl.CVSSBase != 9.8 || openssl.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("cvss = %f %q", openssl.CVSSBase, openssl.CVSSVector)
	}
	if !containsString(openssl.References, "https://avd.aquasec.com/nvd/cve-2026-1000") ||
		!containsString(openssl.References, "https://ubuntu.com/security/CVE-2026-1000") {
		t.Fatalf("references = %#v", openssl.References)
	}
	if openssl.AffectedRange != nil {
		t.Fatalf("affected range = %+v, want nil until scanner output exposes a comparable range", openssl.AffectedRange)
	}

	leftPad := findingByPackage(findings, "left-pad")
	if leftPad == nil {
		t.Fatalf("left-pad finding not found: %+v", findings)
	}
	if leftPad.Title != "CVE-2026-1001" {
		t.Fatalf("title fallback = %q", leftPad.Title)
	}
	if leftPad.CVSSBase != 5.0 || leftPad.CVSSVector != "AV:N/AC:L/Au:N/C:P/I:N/A:N" {
		t.Fatalf("v2 cvss fallback = %f %q", leftPad.CVSSBase, leftPad.CVSSVector)
	}
}

func TestSecretsFromTrivyReportFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "trivy", "ubuntu-24.04.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc trivyReport
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	secrets := secretsFromTrivyReport(doc, "")
	if len(secrets) != 1 {
		t.Fatalf("secret count = %d, want 1: %+v", len(secrets), secrets)
	}
	secret := secrets[0]
	if secret.Engine != "trivy" || secret.RuleID != "aws-access-key-id" || secret.Severity != "high" {
		t.Fatalf("secret identity = %+v", secret)
	}
	if secret.Target != "app/config.py" || secret.Path != "app/config.py" || secret.StartLine != 12 || secret.EndLine != 12 {
		t.Fatalf("secret location = %+v", secret)
	}
	if secret.MatchSHA256 != secretMatchSHA256("AKIA1234567890TEST") {
		t.Fatalf("secret fingerprint = %q", secret.MatchSHA256)
	}
	if secret.MatchRedacted != "[redacted:18]" {
		t.Fatalf("secret redaction = %q", secret.MatchRedacted)
	}
	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "AKIA1234567890TEST") {
		t.Fatalf("secret output contains raw match: %s", encoded)
	}
}

func TestFindingsFromGrypeReportFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "grype", "ubuntu-24.04.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc grypeReport
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	findings := findingsFromGrypeReport(doc, "")
	if len(findings) != 2 {
		t.Fatalf("findings count = %d, want 2: %+v", len(findings), findings)
	}

	openssl := findingByPackage(findings, "openssl")
	if openssl == nil {
		t.Fatalf("openssl finding not found: %+v", findings)
	}
	if openssl.Engine != "grype" || openssl.VulnerabilityID != "CVE-2026-2000" {
		t.Fatalf("identity = engine:%q vuln:%q", openssl.Engine, openssl.VulnerabilityID)
	}
	if openssl.Severity != "high" || openssl.Title != "Representative Grype vulnerability fixture for parser validation." {
		t.Fatalf("severity/title = %q/%q", openssl.Severity, openssl.Title)
	}
	if openssl.Package.Ecosystem != "deb" || openssl.Package.Name != "openssl" ||
		openssl.Package.Version != "3.0.13-0ubuntu3.1" ||
		openssl.Package.Purl != "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.1?arch=amd64" {
		t.Fatalf("package = %+v", openssl.Package)
	}
	if openssl.FixedVersion != "3.0.13-0ubuntu3.2" {
		t.Fatalf("fixed version = %q", openssl.FixedVersion)
	}
	if openssl.CVSSBase != 9.8 || openssl.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("cvss = %f %q", openssl.CVSSBase, openssl.CVSSVector)
	}
	if !containsString(openssl.References, "https://nvd.nist.gov/vuln/detail/CVE-2026-2000") ||
		!containsString(openssl.References, "https://security-tracker.debian.org/tracker/CVE-2026-2000") {
		t.Fatalf("references = %#v", openssl.References)
	}
	if openssl.AffectedRange != nil {
		t.Fatalf("affected range = %+v, want nil until scanner output exposes a comparable range", openssl.AffectedRange)
	}

	leftPad := findingByPackage(findings, "left-pad")
	if leftPad == nil {
		t.Fatalf("left-pad finding not found: %+v", findings)
	}
	if leftPad.Package.Ecosystem != "npm" || leftPad.FixedVersion != "1.0.1" {
		t.Fatalf("language package = %+v fixed=%q", leftPad.Package, leftPad.FixedVersion)
	}
}

func findingByPackage(findings []EngineFinding, name string) *EngineFinding {
	for i := range findings {
		if findings[i].Package.Name == name {
			return &findings[i]
		}
	}
	return nil
}
