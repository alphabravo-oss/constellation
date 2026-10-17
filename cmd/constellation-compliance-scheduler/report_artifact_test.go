package main

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/report"
)

func TestReportArtifactCSVRoundTripsActualEvidence(t *testing.T) {
	check := report.ComplianceCheck{ControlID: "a,1", Title: `Quoted "control"`, Status: "fail", Severity: "high", Evidence: "{\"pod\":\"api\"}\nUnicode 雪, slash \\"}
	body, ext, err := renderArtifact("csv", report.ComplianceData{Checks: []report.ComplianceCheck{check}})
	if err != nil || ext != "csv" {
		t.Fatalf("render %s %v", ext, err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("CSV parse %v %s", err, body)
	}
	want := []string{check.ControlID, check.Title, check.Status, check.Severity, check.Evidence}
	for i, value := range want {
		if rows[1][i] != value {
			t.Fatalf("CSV changed field%d got%q want%q", i, rows[1][i], value)
		}
	}
}
func TestReportArtifactPDFMissingToolKeepsActualHTMLIdentity(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	body, ext, err := renderArtifact("pdf", report.ComplianceData{FrameworkName: "CIS", OrgName: "Actual Org"})
	if err != nil || ext != "html" || !strings.Contains(string(body), "Actual Org") || report.ArtifactMediaType(ext) != "text/html; charset=utf-8" {
		t.Fatalf("fallback %s %v", ext, err)
	}
}
func TestReportArtifactJSONIncludesSourceAndUngradedCounts(t *testing.T) {
	data := report.ComplianceData{OrgName: "Actual Org", Summary: report.FrameworkSummary{Total: 5, Pass: 1, Fail: 1, Manual: 1, Exempted: 1, NotApplicable: 1}, SourceLabel: "retained scope", SourceTotal: 5, SourceReturned: 2, SourceTruncated: true}
	body, ext, err := renderArtifact("json", data)
	if err != nil || ext != "json" {
		t.Fatal(err)
	}
	var value struct {
		Summary report.FrameworkSummary
		Source  struct {
			Total, Returned int
			Truncated       bool
			Label           string
		}
	}
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	if value.Summary.Pass != 1 || value.Summary.Exempted != 1 || value.Summary.PassPct() != 50 || value.Source.Total != 5 || value.Source.Returned != 2 || !value.Source.Truncated {
		t.Fatalf("JSON source %s", body)
	}
}
