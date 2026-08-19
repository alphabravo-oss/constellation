package admission

import (
	"context"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

// RiskyRole is a bit flag identifying one class of over-privileged RBAC grant.
// A (Cluster)Role that satisfies any of these is "risky"; a pod whose
// ServiceAccount binds such a role is flagged by the saBindRiskyRole criterion.
//
// The five classes mirror the C3 plan (and NeuVector's predefined risky-role
// set): cluster-admin, broad secret access, exec-into-container, RBAC
// escalation (escalate/bind), and wildcard verbs-or-resources.
type RiskyRole int

const (
	// RiskyClusterAdmin is the built-in cluster-admin ClusterRole, matched by
	// name (its rules are wildcard-everything, but we also short-circuit on the
	// well-known name so an aggregated/edited copy is still caught).
	RiskyClusterAdmin RiskyRole = 1 << iota
	// RiskyReadSecrets grants get/list/watch (or *) on secrets (or *).
	RiskyReadSecrets
	// RiskyExecPods grants create/get/* on pods/exec (or pods/* or *).
	RiskyExecPods
	// RiskyEscalate grants the escalate or bind verb on RBAC roles — the
	// canonical privilege-escalation primitive.
	RiskyEscalate
	// RiskyWildcard grants "*" verbs or "*" resources in the core or rbac
	// API groups (or "*" apiGroups), i.e. unscoped power.
	RiskyWildcard
)

// riskyRoleLabels gives a stable, human-readable label per flag for deny
// messages. Order matters for stable output (see RiskyRole.Labels).
var riskyRoleLabels = []struct {
	flag  RiskyRole
	label string
}{
	{RiskyClusterAdmin, "cluster-admin"},
	{RiskyReadSecrets, "read-secrets"},
	{RiskyExecPods, "pods/exec"},
	{RiskyEscalate, "escalate/bind"},
	{RiskyWildcard, "wildcard-verbs-or-resources"},
}

// Labels returns the human-readable labels for every flag set on r, in a
// stable order. Empty when r == 0.
func (r RiskyRole) Labels() []string {
	out := make([]string, 0, len(riskyRoleLabels))
	for _, e := range riskyRoleLabels {
		if r&e.flag != 0 {
			out = append(out, e.label)
		}
	}
	return out
}

// ClassifyRiskyRole inspects a (Cluster)Role's name + policy rules and returns
// the set of risky-role flags it satisfies. roleName is the role's metadata
// name (used only for the cluster-admin short-circuit); rules are its
// PolicyRules.
func ClassifyRiskyRole(roleName string, rules []rbacv1.PolicyRule) RiskyRole {
	var risk RiskyRole
	if roleName == "cluster-admin" {
		risk |= RiskyClusterAdmin
	}
	for _, rule := range rules {
		verbs := newStringSet(rule.Verbs)
		resources := newStringSet(rule.Resources)
		groups := newStringSet(rule.APIGroups)

		// Wildcard verbs or wildcard resources => unscoped power.
		if verbs.has("*") || resources.has("*") || groups.has("*") {
			// A bare wildcard ClusterRole is effectively cluster-admin; but we
			// classify it as RiskyWildcard plus, when all three are wildcard,
			// also RiskyClusterAdmin equivalence.
			risk |= RiskyWildcard
			if verbs.has("*") && resources.has("*") && groups.has("*") {
				risk |= RiskyClusterAdmin
			}
		}

		// Secrets read.
		if resources.hasAny("secrets", "*") &&
			verbs.hasAny("*", "get", "list", "watch") {
			risk |= RiskyReadSecrets
		}

		// Exec into containers. pods/exec is a subresource; we also catch the
		// broad "pods/*" and bare "*" resource grants with create/get/*.
		if resources.hasAny("pods/exec", "pods/*", "*") &&
			verbs.hasAny("*", "create", "get") {
			risk |= RiskyExecPods
		}

		// RBAC escalation: the escalate or bind verb on rbac resources.
		if inRBACGroup(groups) &&
			resources.hasAny("*", "roles", "clusterroles", "rolebindings", "clusterrolebindings") &&
			verbs.hasAny("escalate", "bind") {
			risk |= RiskyEscalate
		}
	}
	return risk
}

// RBACResolver resolves the risky-role exposure of a pod's ServiceAccount. The
// cmd/constellation-admission binary provides a client-go backed implementation
// that reads (Cluster)RoleBindings from the API server; tests install a fake.
//
// Implementations must be safe for concurrent use.
type RBACResolver interface {
	// RiskyRolesForServiceAccount returns the union of risky-role flags across
	// every Role/ClusterRole bound to the named ServiceAccount, plus the names
	// of the bound risky roles (for the deny message). A zero RiskyRole means
	// the SA binds no risky role.
	RiskyRolesForServiceAccount(ctx context.Context, namespace, name string) (RiskyRole, []string, error)
}

// staticRBACResolver is an in-memory resolver built from a set of bindings and
// roles. It backs both tests and any caller that wants to snapshot RBAC state.
type staticRBACResolver struct {
	// risky maps "namespace/serviceaccount" to the union of risky flags and the
	// bound risky-role names from ServiceAccount-subject bindings.
	risky map[string]rbacBinding
	// clusterGroupRisky holds risk from bindings to groups that every SA in the
	// cluster implicitly belongs to (system:serviceaccounts, system:authenticated):
	// it applies to ALL ServiceAccounts regardless of namespace. Without this, a
	// risky role bound to e.g. the system:serviceaccounts group would never be
	// attributed to a pod's SA — the canonical group-subject bypass.
	clusterGroupRisky rbacBinding
	// nsGroupRisky maps a namespace to risk from bindings to that namespace's
	// implicit group system:serviceaccounts:<namespace>; it applies to every SA in
	// that namespace.
	nsGroupRisky map[string]rbacBinding
}

// well-known Kubernetes group names every ServiceAccount implicitly belongs to.
const (
	groupAllAuthenticated    = "system:authenticated"
	groupAllServiceAccounts  = "system:serviceaccounts"
	groupNSServiceAccountsPx = "system:serviceaccounts:" // + namespace
)

type rbacBinding struct {
	flags RiskyRole
	roles []string
}

// NewStaticRBACResolver builds a resolver from RBAC objects. ClusterRoleBindings
// use an empty namespace key prefix ("") matched against any SA namespace;
// RoleBindings are namespace-scoped.
func NewStaticRBACResolver(
	roles []rbacv1.Role,
	clusterRoles []rbacv1.ClusterRole,
	roleBindings []rbacv1.RoleBinding,
	clusterRoleBindings []rbacv1.ClusterRoleBinding,
) RBACResolver {
	// Index role risk by name. Roles are namespaced; ClusterRoles are global.
	clusterRoleRisk := map[string]RiskyRole{}
	for _, cr := range clusterRoles {
		clusterRoleRisk[cr.Name] = ClassifyRiskyRole(cr.Name, cr.Rules)
	}
	roleRisk := map[string]RiskyRole{} // key: namespace/name
	for _, r := range roles {
		roleRisk[r.Namespace+"/"+r.Name] = ClassifyRiskyRole(r.Name, r.Rules)
	}

	res := &staticRBACResolver{
		risky:        map[string]rbacBinding{},
		nsGroupRisky: map[string]rbacBinding{},
	}

	merge := func(b *rbacBinding, roleName string, flags RiskyRole) {
		if flags == 0 {
			return
		}
		b.flags |= flags
		b.roles = appendUnique(b.roles, roleName)
	}
	add := func(saNamespace, saName, roleName string, flags RiskyRole) {
		if flags == 0 {
			return
		}
		key := saNamespace + "/" + saName
		b := res.risky[key]
		merge(&b, roleName, flags)
		res.risky[key] = b
	}
	// addGroup attributes a Group-subject binding's risk to the ServiceAccounts that
	// implicitly belong to that group. defaultNS scopes a bare
	// "system:serviceaccounts:<ns>" reference when the subject omits the namespace
	// (only meaningful for the namespaced suffix form).
	addGroup := func(group, roleName string, flags RiskyRole) {
		if flags == 0 {
			return
		}
		switch {
		case group == groupAllAuthenticated || group == groupAllServiceAccounts:
			merge(&res.clusterGroupRisky, roleName, flags)
		case strings.HasPrefix(group, groupNSServiceAccountsPx):
			ns := strings.TrimPrefix(group, groupNSServiceAccountsPx)
			if ns == "" {
				return
			}
			b := res.nsGroupRisky[ns]
			merge(&b, roleName, flags)
			res.nsGroupRisky[ns] = b
		}
	}

	for _, rb := range roleBindings {
		var flags RiskyRole
		switch rb.RoleRef.Kind {
		case "ClusterRole":
			flags = clusterRoleRisk[rb.RoleRef.Name]
		case "Role":
			flags = roleRisk[rb.Namespace+"/"+rb.RoleRef.Name]
		}
		for _, s := range rb.Subjects {
			switch s.Kind {
			case "ServiceAccount":
				ns := s.Namespace
				if ns == "" {
					ns = rb.Namespace
				}
				add(ns, s.Name, rb.RoleRef.Name, flags)
			case "Group":
				// A RoleBinding to a SA group is namespace-scoped, so it only
				// reaches SAs in the binding's namespace. A binding to the broad
				// system:serviceaccounts / system:authenticated group via a
				// RoleBinding still only grants within rb.Namespace.
				addGroupNS(res, rb.Namespace, s.Name, rb.RoleRef.Name, flags)
			}
		}
	}
	for _, crb := range clusterRoleBindings {
		flags := clusterRoleRisk[crb.RoleRef.Name]
		for _, s := range crb.Subjects {
			switch s.Kind {
			case "ServiceAccount":
				// ClusterRoleBinding subjects must carry an explicit namespace.
				add(s.Namespace, s.Name, crb.RoleRef.Name, flags)
			case "Group":
				// A ClusterRoleBinding to a SA group grants cluster-wide.
				addGroup(s.Name, crb.RoleRef.Name, flags)
			}
		}
	}
	return res
}

// addGroupNS attributes a namespaced (RoleBinding) Group-subject grant. A
// RoleBinding only reaches subjects within bindingNS, so a binding to any SA group
// (system:serviceaccounts, system:authenticated, or system:serviceaccounts:<ns>)
// applies to the SAs in bindingNS.
func addGroupNS(res *staticRBACResolver, bindingNS, group, roleName string, flags RiskyRole) {
	if flags == 0 {
		return
	}
	isSAGroup := group == groupAllAuthenticated ||
		group == groupAllServiceAccounts ||
		strings.HasPrefix(group, groupNSServiceAccountsPx)
	if !isSAGroup {
		return
	}
	// For the namespaced suffix form, the binding only matters when its namespace
	// matches the group's namespace (a RoleBinding in ns A to
	// system:serviceaccounts:B reaches no SA — group B members aren't in ns A).
	if strings.HasPrefix(group, groupNSServiceAccountsPx) {
		if ns := strings.TrimPrefix(group, groupNSServiceAccountsPx); ns != "" && ns != bindingNS {
			return
		}
	}
	b := res.nsGroupRisky[bindingNS]
	b.flags |= flags
	b.roles = appendUnique(b.roles, roleName)
	res.nsGroupRisky[bindingNS] = b
}

func (r *staticRBACResolver) RiskyRolesForServiceAccount(_ context.Context, namespace, name string) (RiskyRole, []string, error) {
	// Union three sources of risk for this SA:
	//  1. bindings whose subject is this exact ServiceAccount,
	//  2. bindings to this SA's namespace group (system:serviceaccounts:<ns>) or to
	//     a broad SA group via a RoleBinding scoped to <ns>,
	//  3. ClusterRoleBindings to the cluster-wide implicit groups
	//     (system:serviceaccounts, system:authenticated) — these reach every SA.
	var flags RiskyRole
	var roles []string
	collect := func(b rbacBinding) {
		flags |= b.flags
		for _, rn := range b.roles {
			roles = appendUnique(roles, rn)
		}
	}
	collect(r.risky[namespace+"/"+name])
	collect(r.nsGroupRisky[namespace])
	collect(r.clusterGroupRisky)
	sort.Strings(roles)
	return flags, roles, nil
}

// --- small helpers ---------------------------------------------------------

type stringSet map[string]struct{}

func newStringSet(vals []string) stringSet {
	s := make(stringSet, len(vals))
	for _, v := range vals {
		s[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	return s
}

func (s stringSet) has(v string) bool { _, ok := s[v]; return ok }

func (s stringSet) hasAny(vals ...string) bool {
	for _, v := range vals {
		if _, ok := s[v]; ok {
			return true
		}
	}
	return false
}

// inRBACGroup reports whether the rule targets the rbac.authorization.k8s.io
// API group (or a wildcard group).
func inRBACGroup(groups stringSet) bool {
	return groups.hasAny("*", "rbac.authorization.k8s.io")
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
