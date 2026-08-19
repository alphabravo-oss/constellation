package auth

import (
	"reflect"
	"testing"
)

// A2: MapScopedRoles must reproduce MapRoles' org-scope grants (as IsOrg ScopedRoles) AND add
// the cluster/namespace grants from ScopedRules, de-duplicated by the full (role,cluster,ns)
// triple, org-scope first.
func TestMapScopedRoles(t *testing.T) {
	m := RoleMapping{
		Rules:   map[string]string{"secadmins": "SecurityAdmin"},
		Default: "",
		ScopedRules: map[string][]ScopedRole{
			"secadmins": {
				{Role: "Admin", Scope: RoleScope{ClusterID: "c1"}},
				{Role: "Viewer", Scope: RoleScope{ClusterID: "c1", Namespace: "prod"}},
			},
			"auditors": {
				{Role: "Auditor", Scope: RoleScope{ClusterID: "c2", Namespace: "kube-system"}},
			},
		},
	}

	got := m.MapScopedRoles([]string{"secadmins", "auditors", "unknown"})
	want := []ScopedRole{
		{Role: "SecurityAdmin"}, // org scope, from Rules, emitted first
		{Role: "Admin", Scope: RoleScope{ClusterID: "c1"}},
		{Role: "Viewer", Scope: RoleScope{ClusterID: "c1", Namespace: "prod"}},
		{Role: "Auditor", Scope: RoleScope{ClusterID: "c2", Namespace: "kube-system"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MapScopedRoles() =\n  %+v\nwant\n  %+v", got, want)
	}
}

// The org-scope subset of MapScopedRoles must exactly equal MapRoles so the two resolvers never
// diverge (the existing session path reads the IsOrg() subset).
func TestMapScopedRolesOrgSubsetMatchesMapRoles(t *testing.T) {
	m := RoleMapping{
		Rules:   map[string]string{"a": "RoleA", "b": "RoleB"},
		Default: "Viewer",
		ScopedRules: map[string][]ScopedRole{
			"a": {{Role: "Admin", Scope: RoleScope{ClusterID: "c1"}}},
		},
	}
	values := []string{"a", "b"}
	names := m.MapRoles(values)
	var orgOnly []string
	for _, sr := range m.MapScopedRoles(values) {
		if sr.Scope.IsOrg() {
			orgOnly = append(orgOnly, sr.Role)
		}
	}
	if !reflect.DeepEqual(orgOnly, names) {
		t.Fatalf("org-scope subset %v != MapRoles %v", orgOnly, names)
	}
}

// A group with no ScopedRules (env/legacy provider) yields only org-scope grants — the pre-A2
// behaviour is preserved.
func TestMapScopedRolesNoScopedRules(t *testing.T) {
	m := RoleMapping{Rules: map[string]string{"g": "Viewer"}}
	got := m.MapScopedRoles([]string{"g"})
	want := []ScopedRole{{Role: "Viewer"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MapScopedRoles() = %+v, want %+v", got, want)
	}
}

// WithScopedRules lower-cases group keys so lookups match the case-insensitive resolver.
func TestWithScopedRulesNormalisesKeys(t *testing.T) {
	m := RoleMapping{Rules: map[string]string{}}.WithScopedRules(map[string][]ScopedRole{
		"  SecAdmins ": {{Role: "Admin", Scope: RoleScope{ClusterID: "c1"}}},
	})
	got := m.MapScopedRoles([]string{"secadmins"})
	want := []ScopedRole{{Role: "Admin", Scope: RoleScope{ClusterID: "c1"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MapScopedRoles() = %+v, want %+v", got, want)
	}
}
