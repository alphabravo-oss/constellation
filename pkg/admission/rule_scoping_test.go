package admission

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeNamespaceLabeler resolves per-namespace labels for the namespaceSelector
// (A5) tests.
type fakeNamespaceLabeler struct {
	labels map[string]map[string]string
}

func (f fakeNamespaceLabeler) NamespaceLabels(_ context.Context, ns string) (map[string]string, error) {
	return f.labels[ns], nil
}

type fakeGroupResolver map[string]bool

func (f fakeGroupResolver) PodMatchesGroup(_ context.Context, group string, pod *corev1.Pod) (bool, error) {
	ns := pod.Namespace
	if ns == "" {
		ns = "default"
	}
	return f[group+"\x00"+ns+"/"+pod.Name], nil
}

func scopedPrivilegedPod(name, namespace string) *corev1.Pod {
	tr := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", Image: "alpine:3.18",
			SecurityContext: &corev1.SecurityContext{Privileged: &tr},
		}}},
	}
}

// TestEvaluate_PerRuleNamespaceTargetingByName verifies A5 name-based per-rule
// namespace targeting: a rule scoped to match.namespaces only fires for pods in
// those namespaces.
func TestEvaluate_PerRuleNamespaceTargetingByName(t *testing.T) {
	tr := true
	rule := Rule{
		ID: "block-privileged-prod", Mode: "enforce", Kinds: []string{"Pod"},
		Namespaces: []string{"prod", "staging"},
		Conditions: RuleConditions{Privileged: &tr},
	}
	engine := &PolicyEngine{Rules: []Rule{rule}}

	if resp := engine.Evaluate(context.Background(), reviewFor(scopedPrivilegedPod("p", "prod"))); resp.Allowed {
		t.Fatal("privileged pod in a targeted namespace (prod) should be denied")
	}
	if resp := engine.Evaluate(context.Background(), reviewFor(scopedPrivilegedPod("p", "dev"))); !resp.Allowed {
		t.Fatalf("privileged pod in an untargeted namespace (dev) must be admitted: %+v", resp.Result)
	}
	// Cluster-wide rule (no Namespaces) still fires everywhere.
	engine.SetRules([]Rule{{ID: "block-privileged", Mode: "enforce", Kinds: []string{"Pod"}, Conditions: RuleConditions{Privileged: &tr}}})
	if resp := engine.Evaluate(context.Background(), reviewFor(scopedPrivilegedPod("p", "dev"))); resp.Allowed {
		t.Fatal("cluster-wide rule must still deny in any namespace")
	}
}

// TestEvaluate_PerRuleNamespaceSelector verifies A5 label-based per-rule
// namespace scoping via a namespaceSelector resolved through a NamespaceLabeler,
// and the safe-by-default behaviour when no labeler is wired.
func TestEvaluate_PerRuleNamespaceSelector(t *testing.T) {
	tr := true
	rule := Rule{
		ID: "block-privileged-restricted", Mode: "enforce", Kinds: []string{"Pod"},
		NamespaceSelector: map[string]string{"tier": "restricted"},
		Conditions:        RuleConditions{Privileged: &tr},
	}
	labeler := fakeNamespaceLabeler{labels: map[string]map[string]string{
		"prod": {"tier": "restricted", "team": "payments"},
		"dev":  {"tier": "open"},
	}}
	engine := &PolicyEngine{Rules: []Rule{rule}, NamespaceLabeler: labeler}

	if resp := engine.Evaluate(context.Background(), reviewFor(scopedPrivilegedPod("p", "prod"))); resp.Allowed {
		t.Fatal("privileged pod in a namespace whose labels match the selector should be denied")
	}
	if resp := engine.Evaluate(context.Background(), reviewFor(scopedPrivilegedPod("p", "dev"))); !resp.Allowed {
		t.Fatalf("privileged pod in a namespace whose labels do not match must be admitted: %+v", resp.Result)
	}

	// No labeler wired: a namespaceSelector rule cannot be resolved and must not
	// fire (safe-by-default, never broadens a deny into unscoped namespaces).
	unwired := &PolicyEngine{Rules: []Rule{rule}}
	if resp := unwired.Evaluate(context.Background(), reviewFor(scopedPrivilegedPod("p", "prod"))); !resp.Allowed {
		t.Fatal("namespaceSelector rule must not fire without a namespace labeler")
	}
}

func TestEvaluate_PerRuleGroupScoping(t *testing.T) {
	tr := true
	rule := Rule{
		ID: "block-privileged-payments", Mode: "enforce", Kinds: []string{"Pod"},
		Groups:     []string{"payments"},
		Conditions: RuleConditions{Privileged: &tr},
	}
	engine := &PolicyEngine{
		Rules: []Rule{rule},
		GroupResolver: fakeGroupResolver{
			"payments\x00prod/api": true,
		},
	}

	if resp := engine.Evaluate(context.Background(), reviewFor(scopedPrivilegedPod("api", "prod"))); resp.Allowed {
		t.Fatal("privileged pod in a targeted group should be denied")
	}
	if resp := engine.Evaluate(context.Background(), reviewFor(scopedPrivilegedPod("worker", "prod"))); !resp.Allowed {
		t.Fatalf("privileged pod outside the targeted group must be admitted: %+v", resp.Result)
	}

	unwired := &PolicyEngine{Rules: []Rule{rule}}
	if resp := unwired.Evaluate(context.Background(), reviewFor(scopedPrivilegedPod("api", "prod"))); !resp.Allowed {
		t.Fatal("group-scoped rule must not fire without a group resolver")
	}
}

// TestRuleFromYAMLParsesNamedCVEGraceAndNamespaceScoping covers the A3/A4/A5
// spec surface: deniedCVEs, cveGraceDays, match.namespaces and
// match.namespaceSelector.
func TestRuleFromYAMLParsesNamedCVEGraceAndNamespaceScoping(t *testing.T) {
	rule, supported, err := RuleFromYAML("block-named-cves", "block-named-cves", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-named-cves
spec:
  match:
    kinds: [Pod]
    namespaces: [prod, staging]
    namespaceSelector:
      tier: restricted
  vulnerability:
    deniedCVEs:
      - CVE-2026-1234
      - cve-2026-5678
      - CVE-2026-1234
    cveGraceDays: 14
  action: deny
`)
	if err != nil || !supported {
		t.Fatalf("supported=%v err=%v", supported, err)
	}
	if len(rule.Namespaces) != 2 || rule.Namespaces[0] != "prod" || rule.Namespaces[1] != "staging" {
		t.Fatalf("namespaces = %#v", rule.Namespaces)
	}
	if rule.NamespaceSelector["tier"] != "restricted" {
		t.Fatalf("namespaceSelector = %#v", rule.NamespaceSelector)
	}
	if len(rule.Conditions.EvidenceGates) != 1 {
		t.Fatalf("gates = %+v", rule.Conditions.EvidenceGates)
	}
	gate := rule.Conditions.EvidenceGates[0]
	// Upper-cased and de-duplicated.
	if len(gate.DeniedCVEs) != 2 || gate.DeniedCVEs[0] != "CVE-2026-1234" || gate.DeniedCVEs[1] != "CVE-2026-5678" {
		t.Fatalf("deniedCVEs = %#v", gate.DeniedCVEs)
	}
	if gate.CVEGraceDays == nil || *gate.CVEGraceDays != 14 {
		t.Fatalf("cveGraceDays = %v", gate.CVEGraceDays)
	}
}

func TestRuleFromYAMLParsesGroupScoping(t *testing.T) {
	rule, supported, err := RuleFromYAML("group-scope", "group-scope", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: group-scope
spec:
  match:
    kinds: [Pod]
    groups: [payments, payments, "  "]
  conditions:
    any:
      - field: spec.containers[*].securityContext.privileged
        equals: true
  action: deny
`)
	if err != nil || !supported {
		t.Fatalf("supported=%v err=%v", supported, err)
	}
	if len(rule.Groups) != 1 || rule.Groups[0] != "payments" {
		t.Fatalf("groups = %#v", rule.Groups)
	}
}
