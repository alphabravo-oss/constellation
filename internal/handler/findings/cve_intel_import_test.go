package findings

import (
	"strings"
	"testing"
)

func TestParseKEV(t *testing.T) {
	const fixture = `{
      "catalogVersion": "2026.08.19",
      "count": 2,
      "vulnerabilities": [
        {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","vulnerabilityName":"Log4Shell","dateAdded":"2021-12-10","shortDescription":"JNDI RCE."},
        {"cveID":"CVE-2014-0160","vendorProject":"OpenSSL","product":"OpenSSL","vulnerabilityName":"Heartbleed","dateAdded":"2022-05-04","shortDescription":"Memory disclosure."}
      ]
    }`
	f, err := parseKEV([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if f.CatalogVersion != "2026.08.19" || len(f.Vulnerabilities) != 2 {
		t.Fatalf("bad parse: %+v", f)
	}
	if f.Vulnerabilities[0].CveID != "CVE-2021-44228" || f.Vulnerabilities[0].VulnerabilityName != "Log4Shell" {
		t.Fatalf("bad first entry: %+v", f.Vulnerabilities[0])
	}
	if f.Vulnerabilities[0].DateAdded != "2021-12-10" {
		t.Fatalf("bad dateAdded: %q", f.Vulnerabilities[0].DateAdded)
	}
}

func TestParseEPSS(t *testing.T) {
	const fixture = `#model_version:v2025.03.14,score_date:2026-08-19T00:00:00+0000
cve,epss,percentile
CVE-2021-44228,0.94500,0.99990
CVE-2014-0160,0.80000,0.98000
cve-1999-0001,0.00100,0.10000
`
	scores, date, err := parseEPSS(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if date != "2026-08-19" {
		t.Fatalf("score_date=%q want 2026-08-19", date)
	}
	if len(scores) != 3 {
		t.Fatalf("want 3 scores, got %d", len(scores))
	}
	if s := scores["CVE-2021-44228"]; s.prob < 0.9449 || s.prob > 0.9451 {
		t.Fatalf("log4shell prob=%v", s.prob)
	}
	// lower-case cve id is normalized to upper-case.
	if _, ok := scores["CVE-1999-0001"]; !ok {
		t.Fatal("expected lower-case cve id normalized to upper-case")
	}
	// comment + header lines must not become rows.
	if _, ok := scores["cve"]; ok {
		t.Fatal("header row leaked into scores")
	}
}
