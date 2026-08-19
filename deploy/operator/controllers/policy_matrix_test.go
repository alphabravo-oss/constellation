package controllers

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cv1alpha1 "github.com/alphabravocompany/constellation/deploy/operator/api/v1alpha1"
	"github.com/alphabravocompany/constellation/deploy/operator/policydb"
)

// compile-time assertion: *policydb.Store satisfies the aggregate MatrixStore contract, so a
// single store backs all three B7 reconcilers (SetupMatrixControllers).
var _ MatrixStore = (*policydb.Store)(nil)

// testOrg is declared in policy_controller_test.go; reuse it here.
const testCluster = "22222222-2222-2222-2222-222222222222"

// (ConstellationDLPSensor mapping tests removed in P0-01 with the orphan CRD.)

// -------------------------------- signature rule --------------------------------

func TestMapSignatureRule_Defaults(t *testing.T) {
	cr := &cv1alpha1.ConstellationSignatureRule{
		ObjectMeta: metav1.ObjectMeta{Name: "log4shell"},
		Spec: cv1alpha1.ConstellationSignatureRuleSpec{
			OrgID:     testOrg,
			ClusterID: testCluster,
			Patterns:  []string{`\$\{jndi:`},
		},
	}
	row, err := mapSignatureRule(cr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row.Mode != "monitor" {
		t.Errorf("mode default = %q, want monitor (safety: observe by default)", row.Mode)
	}
	if row.Severity != 5 {
		t.Errorf("severity default = %d, want 5", row.Severity)
	}
	if row.ApplyDir != 3 {
		t.Errorf("applyDir default = %d, want 3 (both)", row.ApplyDir)
	}
}

func TestMapSignatureRule_Rejects(t *testing.T) {
	cases := map[string]cv1alpha1.ConstellationSignatureRuleSpec{
		"bad org":      {OrgID: "x", ClusterID: testCluster, Patterns: []string{"a"}},
		"bad cluster":  {OrgID: testOrg, ClusterID: "x", Patterns: []string{"a"}},
		"no patterns":  {OrgID: testOrg, ClusterID: testCluster},
		"bad mode":     {OrgID: testOrg, ClusterID: testCluster, Mode: "block", Patterns: []string{"a"}},
		"bad severity": {OrgID: testOrg, ClusterID: testCluster, Severity: 42, Patterns: []string{"a"}},
		"bad applydir": {OrgID: testOrg, ClusterID: testCluster, ApplyDir: 9, Patterns: []string{"a"}},
		"bad pcre":     {OrgID: testOrg, ClusterID: testCluster, Patterns: []string{"("}},
	}
	for name, spec := range cases {
		cr := &cv1alpha1.ConstellationSignatureRule{ObjectMeta: metav1.ObjectMeta{Name: "s"}, Spec: spec}
		if _, err := mapSignatureRule(cr); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// --------------------------------- vuln profile ---------------------------------

func TestMapVulnProfile_Mapping(t *testing.T) {
	cr := &cv1alpha1.ConstellationVulnProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "grace"},
		Spec: cv1alpha1.ConstellationVulnProfileSpec{
			OrgID:  testOrg,
			Active: true,
			Entries: []cv1alpha1.VulnProfileEntry{
				{Name: "recent", NameRegex: `CVE-2024-.*`, Action: "suppress", SeverityFloor: "high", Images: []string{"nginx:*"}},
			},
			DomainScope: cv1alpha1.VulnDomainScope{Namespaces: []string{"team-a"}},
		},
	}
	row, err := mapVulnProfile(cr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !row.Active || len(row.Entries) != 1 {
		t.Fatalf("mapping mismatch: %+v", row)
	}
	// camelCase CR field -> snake_case DB shape carried through the row's typed field.
	if row.Entries[0].NameRegex != `CVE-2024-.*` || row.Entries[0].SeverityFloor != "high" {
		t.Errorf("entry field mapping lost: %+v", row.Entries[0])
	}
	if len(row.DomainScope.Namespaces) != 1 || row.DomainScope.Namespaces[0] != "team-a" {
		t.Errorf("domain scope not mapped: %+v", row.DomainScope)
	}
}

func TestMapVulnProfile_Rejects(t *testing.T) {
	cases := map[string]cv1alpha1.ConstellationVulnProfileSpec{
		"bad org":      {OrgID: "x"},
		"bad action":   {OrgID: testOrg, Entries: []cv1alpha1.VulnProfileEntry{{Name: "e", Action: "ignore"}}},
		"bad severity": {OrgID: testOrg, Entries: []cv1alpha1.VulnProfileEntry{{Name: "e", Action: "suppress", SeverityFloor: "sev1"}}},
		"bad regex":    {OrgID: testOrg, Entries: []cv1alpha1.VulnProfileEntry{{Name: "e", Action: "suppress", NameRegex: "("}}},
		"empty name":   {OrgID: testOrg, Entries: []cv1alpha1.VulnProfileEntry{{Name: "", Action: "suppress"}}},
	}
	for name, spec := range cases {
		cr := &cv1alpha1.ConstellationVulnProfile{ObjectMeta: metav1.ObjectMeta{Name: "p"}, Spec: spec}
		if _, err := mapVulnProfile(cr); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
