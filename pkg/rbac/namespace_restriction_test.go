package rbac

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// NamespaceRestriction is the security-critical core of RBAC-NS-24 row filtering:
// a single namespace-unrestricted grant for the verb must yield restricted=false
// (no filter), while purely namespace-scoped grants yield the exact allow-set.
func TestNamespaceRestriction(t *testing.T) {
	org := uuid.New()
	c1 := uuid.New()
	res := Resource{OrgID: org, ClusterID: &c1}
	// RoleAnalyst grants VerbReadFindings (per existing tests).
	v := VerbReadFindings

	cases := []struct {
		name       string
		asg        []RoleAssignment
		wantNS     []string
		wantRestr  bool
	}{
		{
			name:      "org-wide grant → unrestricted",
			asg:       []RoleAssignment{{Role: RoleAnalyst, Scope: Scope{OrgID: org}}},
			wantRestr: false,
		},
		{
			name:      "cluster-wide grant (no namespace) → unrestricted",
			asg:       []RoleAssignment{{Role: RoleAnalyst, Scope: Scope{OrgID: org, ClusterID: &c1}}},
			wantRestr: false,
		},
		{
			name:      "single namespace grant → restricted to it",
			asg:       []RoleAssignment{{Role: RoleAnalyst, Scope: Scope{OrgID: org, ClusterID: &c1, Namespace: "prod"}}},
			wantNS:    []string{"prod"},
			wantRestr: true,
		},
		{
			name: "two namespace grants → union, sorted, deduped",
			asg: []RoleAssignment{
				{Role: RoleAnalyst, Scope: Scope{OrgID: org, ClusterID: &c1, Namespace: "prod"}},
				{Role: RoleAnalyst, Scope: Scope{OrgID: org, ClusterID: &c1, Namespace: "dev"}},
				{Role: RoleAuditor, Scope: Scope{OrgID: org, ClusterID: &c1, Namespace: "prod"}},
			},
			wantNS:    []string{"dev", "prod"},
			wantRestr: true,
		},
		{
			name: "namespace grant + org-wide grant for the verb → unrestricted wins",
			asg: []RoleAssignment{
				{Role: RoleAnalyst, Scope: Scope{OrgID: org, ClusterID: &c1, Namespace: "prod"}},
				{Role: RoleAnalyst, Scope: Scope{OrgID: org}},
			},
			wantRestr: false,
		},
		{
			name:      "no grant for the verb → not restricted (Authorize denies separately)",
			asg:       []RoleAssignment{{Role: RoleAnalyst, Scope: Scope{OrgID: uuid.New(), Namespace: "prod"}}}, // different org
			wantRestr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns, restr := NamespaceRestriction(tc.asg, v, res, nil)
			if restr != tc.wantRestr {
				t.Fatalf("restricted = %v, want %v (ns=%v)", restr, tc.wantRestr, ns)
			}
			if tc.wantRestr && !reflect.DeepEqual(ns, tc.wantNS) {
				t.Fatalf("namespaces = %v, want %v", ns, tc.wantNS)
			}
			if !tc.wantRestr && ns != nil {
				t.Fatalf("unrestricted must return nil namespaces, got %v", ns)
			}
		})
	}
}
