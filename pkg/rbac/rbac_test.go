package rbac

import (
	"testing"

	"github.com/google/uuid"
)

func TestAuthorizeOrgScope(t *testing.T) {
	org := uuid.New()
	other := uuid.New()
	assignments := []RoleAssignment{{Role: RoleSecurityAdmin, Scope: Scope{OrgID: org}}}

	if err := Authorize(assignments, VerbSuppressFindings, Resource{OrgID: org}); err != nil {
		t.Fatalf("expected SecurityAdmin to be allowed to suppress: %v", err)
	}
	if err := Authorize(assignments, VerbSuppressFindings, Resource{OrgID: other}); err == nil {
		t.Fatalf("expected cross-org suppress to be forbidden")
	}
	if err := Authorize(assignments, VerbManageOrg, Resource{OrgID: org}); err == nil {
		t.Fatalf("SecurityAdmin should not be able to manage-org")
	}
}

func TestAuthorizeClusterScope(t *testing.T) {
	org := uuid.New()
	c1 := uuid.New()
	c2 := uuid.New()
	assignments := []RoleAssignment{{Role: RoleAnalyst, Scope: Scope{OrgID: org, ClusterID: &c1}}}

	if err := Authorize(assignments, VerbTriageFindings, Resource{OrgID: org, ClusterID: &c1}); err != nil {
		t.Fatalf("Analyst on cluster c1 should triage in c1: %v", err)
	}
	if err := Authorize(assignments, VerbTriageFindings, Resource{OrgID: org, ClusterID: &c2}); err == nil {
		t.Fatalf("Analyst on c1 must not triage in c2")
	}
	// P0-09 keystone: a cluster-scoped grant must NOT authorize an org-wide resource (nil
	// ClusterID). requireVerb builds an org-wide Resource for non-cluster routes, so this is
	// exactly what stops a cluster-scoped user from acting org-wide.
	if err := Authorize(assignments, VerbTriageFindings, Resource{OrgID: org}); err == nil {
		t.Fatalf("Analyst scoped to c1 must not authorize an org-wide resource")
	}
}

// TestAuthorizeNamespaceScope is the P0-10 keystone: a namespace-scoped grant authorizes ONLY a
// resource carrying the same namespace on the same cluster — it must never widen to the whole
// cluster (the over-grant the materializer previously avoided by dropping namespace grants).
func TestAuthorizeNamespaceScope(t *testing.T) {
	org := uuid.New()
	c1 := uuid.New()
	c2 := uuid.New()
	assignments := []RoleAssignment{{Role: RoleAnalyst, Scope: Scope{OrgID: org, ClusterID: &c1, Namespace: "prod"}}}

	// Exact (cluster, namespace) match is authorized.
	if err := Authorize(assignments, VerbTriageFindings, Resource{OrgID: org, ClusterID: &c1, Namespace: "prod"}); err != nil {
		t.Fatalf("Analyst on c1/prod should triage in c1/prod: %v", err)
	}
	// Same cluster, different namespace — forbidden.
	if err := Authorize(assignments, VerbTriageFindings, Resource{OrgID: org, ClusterID: &c1, Namespace: "staging"}); err == nil {
		t.Fatalf("namespace grant on prod must not authorize staging")
	}
	// Same cluster, NO namespace on the resource — must NOT widen to the whole cluster.
	if err := Authorize(assignments, VerbTriageFindings, Resource{OrgID: org, ClusterID: &c1}); err == nil {
		t.Fatalf("namespace-scoped grant must not authorize a whole-cluster resource")
	}
	// Different cluster, matching namespace name — forbidden.
	if err := Authorize(assignments, VerbTriageFindings, Resource{OrgID: org, ClusterID: &c2, Namespace: "prod"}); err == nil {
		t.Fatalf("namespace grant on c1/prod must not authorize c2/prod")
	}
	// A cluster-scoped grant (no namespace) still covers a namespaced resource in that cluster.
	clusterWide := []RoleAssignment{{Role: RoleAnalyst, Scope: Scope{OrgID: org, ClusterID: &c1}}}
	if err := Authorize(clusterWide, VerbTriageFindings, Resource{OrgID: org, ClusterID: &c1, Namespace: "prod"}); err != nil {
		t.Fatalf("cluster-wide grant should cover a namespaced resource in that cluster: %v", err)
	}
}

func TestRoleVerbsMonotonic(t *testing.T) {
	// Each higher tier must include every verb of the prior tier.
	tiers := []string{RoleAuditor, RoleAnalyst, RoleClusterAdmin, RoleSecurityAdmin, RoleGlobalAdmin}
	for i := 1; i < len(tiers); i++ {
		lower := VerbsForRole(tiers[i-1])
		higher := VerbsForRole(tiers[i])
		for _, v := range lower {
			if !roleGrants(tiers[i], v) {
				t.Fatalf("role %s is supposed to include %s's verb %q", tiers[i], tiers[i-1], v)
			}
			_ = higher
		}
	}
}

func TestUnknownRolesGrantNoPermissions(t *testing.T) {
	if IsRole("SuperAdmin") {
		t.Fatalf("SuperAdmin must not be accepted as a current product role")
	}
	if roleGrants("SuperAdmin", VerbManageOrg) {
		t.Fatalf("unknown role should not grant permissions")
	}
	if verbs := VerbsForRole("SuperAdmin"); len(verbs) != 0 {
		t.Fatalf("unknown role verbs = %+v, want none", verbs)
	}
}
