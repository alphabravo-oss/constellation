package admission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// podRaw marshals a Pod with the given ServiceAccount for an AdmissionRequest.
func podRaw(t *testing.T, namespace, name, sa string) []byte {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			ServiceAccountName: sa,
			Containers:         []corev1.Container{{Name: "c", Image: "alpine:3.18"}},
		},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	return raw
}

// podReviewWithUser builds a Pod AdmissionRequest carrying userInfo.
func podReviewWithUser(raw []byte, user string, groups []string) *admissionv1.AdmissionRequest {
	return &admissionv1.AdmissionRequest{
		UID:      "test-uid",
		Kind:     metav1.GroupVersionKind{Kind: "Pod"},
		Object:   runtime.RawExtension{Raw: raw},
		UserInfo: authenticationv1.UserInfo{Username: user, Groups: groups},
	}
}

func TestEvaluate_RuleMatchesByUser(t *testing.T) {
	e := &PolicyEngine{Rules: []Rule{{
		ID:    "block-ci-user",
		Mode:  "enforce",
		Kinds: []string{"Pod"},
		Conditions: RuleConditions{
			UserMatch: `system:serviceaccount:ci:.*`,
		},
	}}}

	raw := podRaw(t, "prod", "p1", "default")

	// Matching user is denied.
	resp := e.Evaluate(context.Background(), podReviewWithUser(raw, "system:serviceaccount:ci:runner", nil))
	if resp.Allowed {
		t.Fatalf("request from matching user must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "block-ci-user") {
		t.Fatalf("expected denial referencing rule, got %+v", resp.Result)
	}

	// Non-matching user passes.
	resp = e.Evaluate(context.Background(), podReviewWithUser(raw, "alice@example.com", nil))
	if !resp.Allowed {
		t.Fatalf("non-matching user must pass, got %+v", resp.Result)
	}
}

func TestEvaluate_RuleMatchesByGroup(t *testing.T) {
	e := &PolicyEngine{Rules: []Rule{{
		ID:    "block-unauth-group",
		Mode:  "enforce",
		Kinds: []string{"Pod"},
		Conditions: RuleConditions{
			GroupMatch: `system:unauthenticated`,
		},
	}}}

	raw := podRaw(t, "prod", "p1", "default")

	resp := e.Evaluate(context.Background(), podReviewWithUser(raw, "anon", []string{"system:unauthenticated", "system:authenticated"}))
	if resp.Allowed {
		t.Fatalf("request from matching group must be denied")
	}

	resp = e.Evaluate(context.Background(), podReviewWithUser(raw, "alice", []string{"system:authenticated"}))
	if !resp.Allowed {
		t.Fatalf("request without matching group must pass, got %+v", resp.Result)
	}
}

func TestClassifyRiskyRole(t *testing.T) {
	cases := []struct {
		name  string
		role  string
		rules []rbacv1.PolicyRule
		want  RiskyRole
	}{
		{
			name: "cluster-admin by name",
			role: "cluster-admin",
			want: RiskyClusterAdmin,
		},
		{
			name: "wildcard everything",
			role: "god",
			rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
			}},
			want: RiskyWildcard | RiskyClusterAdmin | RiskyReadSecrets | RiskyExecPods,
		},
		{
			name: "read secrets",
			role: "secret-reader",
			rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"},
			}},
			want: RiskyReadSecrets,
		},
		{
			name: "exec into pods",
			role: "execer",
			rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"},
			}},
			want: RiskyExecPods,
		},
		{
			name: "escalate rbac",
			role: "escalator",
			rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"escalate"},
			}},
			want: RiskyEscalate,
		},
		{
			name: "bind rbac",
			role: "binder",
			rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles"}, Verbs: []string{"bind"},
			}},
			want: RiskyEscalate,
		},
		{
			name: "benign read configmaps",
			role: "config-reader",
			rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"},
			}},
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyRiskyRole(tc.role, tc.rules)
			if got != tc.want {
				t.Fatalf("ClassifyRiskyRole = %b (%v), want %b (%v)", got, got.Labels(), tc.want, tc.want.Labels())
			}
		})
	}
}

// riskyRBACFixture builds a fake RBAC graph where ServiceAccount
// prod/privileged-sa binds a ClusterRole granting cluster-admin via a
// RoleBinding, while prod/safe-sa binds only a benign Role.
func riskyRBACFixture() RBACResolver {
	clusterRoles := []rbacv1.ClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
			}},
		},
	}
	roles := []rbacv1.Role{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "configmap-reader", Namespace: "prod"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"},
			}},
		},
	}
	roleBindings := []rbacv1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "give-admin", Namespace: "prod"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "privileged-sa", Namespace: "prod"}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "give-read", Namespace: "prod"},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "configmap-reader"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "safe-sa", Namespace: "prod"}},
		},
	}
	return NewStaticRBACResolver(roles, clusterRoles, roleBindings, nil)
}

func TestEvaluate_SABindRiskyRoleDenies(t *testing.T) {
	yes := true
	e := &PolicyEngine{
		Rules: []Rule{{
			ID:         "sa-bind-risky-role",
			Mode:       "enforce",
			Kinds:      []string{"Pod"},
			Conditions: RuleConditions{SABindRiskyRole: &yes},
		}},
		RBAC: riskyRBACFixture(),
	}

	// Pod whose SA binds cluster-admin is denied.
	raw := podRaw(t, "prod", "evil", "privileged-sa")
	resp := e.Evaluate(context.Background(), podReviewWithUser(raw, "u", nil))
	if resp.Allowed {
		t.Fatalf("pod whose SA binds a risky role must be denied")
	}
	if resp.Result == nil ||
		!strings.Contains(resp.Result.Message, "sa-bind-risky-role") ||
		!strings.Contains(resp.Result.Message, "cluster-admin") {
		t.Fatalf("expected denial naming rule + risky role, got %+v", resp.Result)
	}

	// Pod whose SA binds only a benign role is allowed.
	raw = podRaw(t, "prod", "good", "safe-sa")
	resp = e.Evaluate(context.Background(), podReviewWithUser(raw, "u", nil))
	if !resp.Allowed {
		t.Fatalf("pod whose SA binds no risky role must pass, got %+v", resp.Result)
	}

	// Pod whose SA has no bindings at all is allowed.
	raw = podRaw(t, "prod", "default-pod", "default")
	resp = e.Evaluate(context.Background(), podReviewWithUser(raw, "u", nil))
	if !resp.Allowed {
		t.Fatalf("pod with unbound SA must pass, got %+v", resp.Result)
	}
}

func TestEvaluate_SABindRiskyRoleClusterRoleBinding(t *testing.T) {
	yes := true
	clusterRoles := []rbacv1.ClusterRole{{
		ObjectMeta: metav1.ObjectMeta{Name: "secret-peeker"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"},
		}},
	}}
	crbs := []rbacv1.ClusterRoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "peek"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "secret-peeker"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "peeker-sa", Namespace: "kube-system"}},
	}}
	e := &PolicyEngine{
		Rules: []Rule{{ID: "rr", Mode: "enforce", Kinds: []string{"Pod"}, Conditions: RuleConditions{SABindRiskyRole: &yes}}},
		RBAC:  NewStaticRBACResolver(nil, clusterRoles, nil, crbs),
	}
	raw := podRaw(t, "kube-system", "p", "peeker-sa")
	resp := e.Evaluate(context.Background(), podReviewWithUser(raw, "u", nil))
	if resp.Allowed {
		t.Fatalf("pod whose SA binds a secret-reading ClusterRole via CRB must be denied")
	}
	if !strings.Contains(resp.Result.Message, "read-secrets") {
		t.Fatalf("expected read-secrets label in denial, got %+v", resp.Result)
	}
}

func TestEvaluate_SABindRiskyRoleNoResolverFailsOpen(t *testing.T) {
	yes := true
	e := &PolicyEngine{Rules: []Rule{{
		ID: "rr", Mode: "enforce", Kinds: []string{"Pod"},
		Conditions: RuleConditions{SABindRiskyRole: &yes},
	}}} // no RBAC resolver wired
	raw := podRaw(t, "prod", "p", "privileged-sa")
	resp := e.Evaluate(context.Background(), podReviewWithUser(raw, "u", nil))
	if !resp.Allowed {
		t.Fatalf("without an RBAC resolver the rule must fail open (allow), got %+v", resp.Result)
	}
}

// C3 bypass guard: a risky ClusterRole bound to the implicit group
// system:serviceaccounts (which EVERY ServiceAccount belongs to) must be attributed
// to the pod's SA. Before the fix the resolver only inspected ServiceAccount-kind
// subjects, so this group binding granted effective cluster-admin while the rule
// returned 0 flags and failed open.
func TestEvaluate_SABindRiskyRole_ClusterGroupSubject(t *testing.T) {
	yes := true
	clusterRoles := []rbacv1.ClusterRole{{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
		}},
	}}
	crbs := []rbacv1.ClusterRoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "all-sas-admin"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:serviceaccounts"}},
	}}
	e := &PolicyEngine{
		Rules: []Rule{{ID: "rr", Mode: "enforce", Kinds: []string{"Pod"}, Conditions: RuleConditions{SABindRiskyRole: &yes}}},
		RBAC:  NewStaticRBACResolver(nil, clusterRoles, nil, crbs),
	}
	// An SA in an arbitrary namespace inherits the group grant.
	raw := podRaw(t, "prod", "p", "default")
	resp := e.Evaluate(context.Background(), podReviewWithUser(raw, "u", nil))
	if resp.Allowed {
		t.Fatalf("pod SA bound to cluster-admin via system:serviceaccounts group must be denied")
	}
	if !strings.Contains(resp.Result.Message, "cluster-admin") {
		t.Fatalf("expected cluster-admin label in denial, got %+v", resp.Result)
	}
}

// C3: a RoleBinding to the namespace group system:serviceaccounts:<ns> reaches
// every SA in that namespace, but NOT SAs in other namespaces.
func TestEvaluate_SABindRiskyRole_NamespaceGroupSubject(t *testing.T) {
	yes := true
	clusterRoles := []rbacv1.ClusterRole{{
		ObjectMeta: metav1.ObjectMeta{Name: "secret-peeker"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"},
		}},
	}}
	rbs := []rbacv1.RoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-sas-peek", Namespace: "team-a"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "secret-peeker"},
		Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:serviceaccounts:team-a"}},
	}}
	res := NewStaticRBACResolver(nil, clusterRoles, rbs, nil)
	e := &PolicyEngine{
		Rules: []Rule{{ID: "rr", Mode: "enforce", Kinds: []string{"Pod"}, Conditions: RuleConditions{SABindRiskyRole: &yes}}},
		RBAC:  res,
	}
	// SA in team-a is caught.
	if resp := e.Evaluate(context.Background(), podReviewWithUser(podRaw(t, "team-a", "p", "default"), "u", nil)); resp.Allowed {
		t.Fatalf("SA in team-a bound via namespace group must be denied")
	}
	// SA in team-b is NOT caught (group is namespace-scoped).
	if resp := e.Evaluate(context.Background(), podReviewWithUser(podRaw(t, "team-b", "p", "default"), "u", nil)); !resp.Allowed {
		t.Fatalf("SA in team-b must be allowed: the namespace group does not reach it")
	}
}

// C3: a malformed UserMatch/GroupMatch regex must be rejected at load time rather
// than silently failing open at evaluation.
func TestRuleFromYAML_InvalidIdentityRegexRejected(t *testing.T) {
	for _, field := range []string{"userMatch", "groupMatch"} {
		spec := "spec:\n  match:\n    kinds: [Pod]\n  identity:\n    " + field + ": \"([\"\n"
		if _, _, err := RuleFromYAML("id", "title", "", "enforce", spec); err == nil {
			t.Fatalf("expected RuleFromYAML to reject invalid %s regex", field)
		}
	}
}

func TestRuleFromYAML_Identity(t *testing.T) {
	spec := `
spec:
  match:
    kinds: [Pod]
  identity:
    userMatch: "system:serviceaccount:ci:.*"
    groupMatch: "system:unauthenticated"
    saBindRiskyRole: true
`
	rule, supported, err := RuleFromYAML("id", "title", "", "enforce", spec)
	if err != nil {
		t.Fatalf("RuleFromYAML: %v", err)
	}
	if !supported {
		t.Fatalf("identity rule must be supported by the local engine")
	}
	if rule.Conditions.UserMatch != "system:serviceaccount:ci:.*" {
		t.Fatalf("userMatch not parsed: %q", rule.Conditions.UserMatch)
	}
	if rule.Conditions.GroupMatch != "system:unauthenticated" {
		t.Fatalf("groupMatch not parsed: %q", rule.Conditions.GroupMatch)
	}
	if rule.Conditions.SABindRiskyRole == nil || !*rule.Conditions.SABindRiskyRole {
		t.Fatalf("saBindRiskyRole not parsed")
	}
}
