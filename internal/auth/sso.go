package auth

import "strings"

// RoleScope identifies WHERE a mapped role applies (A2). The zero value is ORG scope (the
// historical behaviour: a role granted org-wide). A set ClusterID narrows the grant to a
// single cluster; a set Namespace narrows it further to one namespace on that cluster. This
// mirrors NeuVector's GroupRoleMapping.RoleDomains, where a group's mapped role carries a list
// of "domains" (namespaces); we generalise a domain to a (cluster, namespace) pair.
type RoleScope struct {
	// ClusterID is the target cluster, or "" for all clusters (org scope).
	ClusterID string
	// Namespace is the target namespace within ClusterID, or "" for the whole cluster/org.
	Namespace string
}

// IsOrg reports whether the scope is org-wide (no cluster/namespace narrowing).
func (s RoleScope) IsOrg() bool { return s.ClusterID == "" && s.Namespace == "" }

// ScopedRole is a Constellation role name bound to the scope at which it is granted (A2).
type ScopedRole struct {
	Role  string
	Scope RoleScope
}

// RoleMapping is the per-org rule that turns IdP-supplied group/attribute values into
// Constellation RBAC role names. It is deliberately data, not code: a deployment configures
// it per organization (e.g. {"okta-secadmins": "SecurityAdmin", "cn=auditors": "Auditor"})
// and both the SAML and LDAP paths resolve roles through the same MapRoles call before the
// existing JWT signer + role_assignments path issues the session. There is no new session
// model — SAML/LDAP land a user with the same Claims an OIDC login would.
type RoleMapping struct {
	// Rules maps a lower-cased IdP value (a SAML attribute value or an LDAP group CN)
	// to a Constellation role name. These grants are always ORG-scoped (backward compatible).
	Rules map[string]string
	// Default is granted when no rule matches and at least one identity was returned.
	// Empty means "no role" (login still succeeds; the user has no privileges until an
	// admin assigns one, mirroring the OIDC provision-by-admin behaviour).
	Default string
	// ScopedRules maps a lower-cased IdP value to one or more CLUSTER/NAMESPACE-scoped role
	// grants (A2), mirroring NeuVector's GroupRoleMapping.RoleDomains. It is additive to Rules:
	// a group may appear in both (an org-scope grant AND narrower per-cluster grants). Loaded
	// from the sso_role_mappings table (migration 125); nil for env/legacy providers, whose
	// mapping stays org-scope-only exactly as before. Populated via WithScopedRules.
	ScopedRules map[string][]ScopedRole `json:"scoped_rules,omitempty"`
}

// WithScopedRules returns a copy of m with its ScopedRules set (keys are lower-cased on the
// way in so lookups match the same normalisation MapRoles/MapScopedRoles use). Loaders build
// the scoped map from the DB rows and attach it here without mutating the shared value.
func (m RoleMapping) WithScopedRules(scoped map[string][]ScopedRole) RoleMapping {
	if len(scoped) == 0 {
		m.ScopedRules = nil
		return m
	}
	norm := make(map[string][]ScopedRole, len(scoped))
	for k, v := range scoped {
		norm[strings.ToLower(strings.TrimSpace(k))] = v
	}
	m.ScopedRules = norm
	return m
}

// MapRoles resolves the set of IdP values (SAML attribute values or LDAP group names) to the
// distinct, de-duplicated set of Constellation role names. Matching is case-insensitive and
// order-preserving on first appearance so the output is stable for tests and audit logs.
func (m RoleMapping) MapRoles(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range values {
		role, ok := m.Rules[strings.ToLower(strings.TrimSpace(v))]
		if !ok || role == "" {
			continue
		}
		if _, dup := seen[role]; dup {
			continue
		}
		seen[role] = struct{}{}
		out = append(out, role)
	}
	if len(out) == 0 && m.Default != "" {
		out = append(out, m.Default)
	}
	return out
}

// MapScopedRoles resolves the IdP values to the full set of SCOPED role grants (A2): every
// org-scope grant MapRoles would produce (from Rules/Default) PLUS every cluster/namespace
// grant from ScopedRules. Matching is case-insensitive; output is de-duplicated by the full
// (role, cluster, namespace) triple and order-preserving on first appearance so it is stable
// for tests and audit logs. This is the scope-aware analogue of MapRoles; MapRoles is retained
// unchanged for the callers that only need org-scope role names.
//
// The org-scope grants are emitted first (RoleScope zero value) so a consumer that only writes
// org-scoped role_assignments today can keep reading the IsOrg() subset while the scoped grants
// wait on the cluster/namespace-aware assignment writer (see reconcileJITRoles).
func (m RoleMapping) MapScopedRoles(values []string) []ScopedRole {
	seen := map[ScopedRole]struct{}{}
	var out []ScopedRole
	add := func(sr ScopedRole) {
		if sr.Role == "" {
			return
		}
		if _, dup := seen[sr]; dup {
			return
		}
		seen[sr] = struct{}{}
		out = append(out, sr)
	}
	// Org-scope grants first, reusing MapRoles so the two resolvers can never diverge.
	for _, name := range m.MapRoles(values) {
		add(ScopedRole{Role: name})
	}
	// Cluster/namespace-scoped grants.
	for _, v := range values {
		key := strings.ToLower(strings.TrimSpace(v))
		for _, sr := range m.ScopedRules[key] {
			add(sr)
		}
	}
	return out
}
