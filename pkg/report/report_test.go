package report

import (
	"strings"
	"testing"
	"time"
)

func TestComplianceHTML(t *testing.T) {
	t.Parallel()
	html, err := ComplianceHTML(ComplianceData{
		OrgName: "Demo", FrameworkName: "CIS Kubernetes 1.9", Framework: "cis-k8s-1.9",
		GeneratedAt: time.Now(),
		Summary:     FrameworkSummary{Total: 10, Pass: 7, Fail: 2, Manual: 1},
		Checks: []ComplianceCheck{
			{ControlID: "1.2.22", Title: "Audit policy", Status: "pass", Severity: "high"},
			{ControlID: "5.2.1", Title: "No privileged containers", Status: "fail", Severity: "high", Evidence: "demo-pod has privileged: true"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	if !strings.Contains(s, "CIS Kubernetes 1.9") {
		t.Fatalf("framework name missing")
	}
	if !strings.Contains(s, "77%") {
		t.Fatalf("expected graded pass pct 77%%: %s", s)
	}
	if !strings.Contains(s, "5.2.1") {
		t.Fatalf("control id missing")
	}
}

func TestExecutiveHTML(t *testing.T) {
	t.Parallel()
	html, err := ExecutiveHTML(ExecutiveData{
		OrgName: "Demo", GeneratedAt: time.Now(), ScanWindow: "last 30 days",
		TotalFindings: 42, CriticalFindings: 3, HighFindings: 9,
		TopAssets:      []AssetRow{{Name: "ghcr.io/demo/api", RiskScore: 92, Findings: 14}},
		MTTRBySeverity: []MTTRRow{{Severity: "critical", Days: 2.3, Resolved: 6}},
		FrameworkPass:  []FrameworkSummaryNamed{{Name: "CIS K8s", FrameworkSummary: FrameworkSummary{Pass: 7, Fail: 3, Total: 10}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	for _, needle := range []string{"42", "ghcr.io/demo/api", "CIS K8s", "70%"} {
		if !strings.Contains(s, needle) {
			t.Fatalf("missing %q in executive html", needle)
		}
	}
}

func TestReportsRenderExactWorkloadRoleAndExplicitSource(t *testing.T) {
	t.Parallel()
	html, err := ExecutiveHTML(ExecutiveData{OrgName: "Actual Org", ScanWindow: "All retained finding instances", SourceLabel: "selected cluster", MTTRSource: "Organization-wide materialized metrics", TopAssets: []AssetRow{{Name: "api", Namespace: "orbit", ClusterID: "cluster-a", PlatformRole: "core", RiskScore: 80}, {Name: "customer", Namespace: "app", ClusterID: "cluster-b"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"orbit/api", "cluster-a", "core", "Unclassified", "selected cluster", "Organization-wide materialized metrics"} {
		if !strings.Contains(string(html), needle) {
			t.Fatal("missing source/role", needle)
		}
	}
	if (FrameworkSummary{Total: 10, Pass: 1, Fail: 1, Exempted: 8}).PassPct() != 50 || (FrameworkSummary{Total: 10, Manual: 10}).PassPct() != 0 {
		t.Fatal("ungraded records entered graded denominator")
	}
}
