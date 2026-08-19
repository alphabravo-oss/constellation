package admission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func reviewForUser(pod *corev1.Pod, username string, groups ...string) *admissionv1.AdmissionRequest {
	b, _ := json.Marshal(pod)
	return &admissionv1.AdmissionRequest{
		UID:      "test-uid",
		Kind:     metav1.GroupVersionKind{Kind: "Pod"},
		Object:   runtime.RawExtension{Raw: b},
		UserInfo: authenticationv1.UserInfo{Username: username, Groups: groups},
	}
}

func privilegedPod() *corev1.Pod {
	t1 := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv", Namespace: "kube-system"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "c", Image: "alpine:3.18",
				SecurityContext: &corev1.SecurityContext{Privileged: &t1},
			}},
		},
	}
}

// TestEvaluate_AllowCarveOutBeatsDeny is the core P1-3 precedence guarantee: an
// enforce-mode allow/except rule whose conditions match short-circuits to ADMIT
// before the matching deny rule is ever evaluated.
func TestEvaluate_AllowCarveOutBeatsDeny(t *testing.T) {
	e := &PolicyEngine{Rules: []Rule{
		// A broad deny that WOULD block this privileged pod.
		{ID: "block-privileged", Mode: "enforce", Kinds: []string{"Pod"},
			Conditions: RuleConditions{Privileged: boolPtr(true)}},
		// An allow carve-out for kube-system service accounts.
		{ID: "allow-system", Mode: "enforce", Effect: EffectAllow, Kinds: []string{"Pod"},
			Conditions: RuleConditions{UserMatch: `system:serviceaccount:kube-system:.*`}},
	}}

	req := reviewForUser(privilegedPod(), "system:serviceaccount:kube-system:deployer")
	resp := e.Evaluate(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("allow carve-out must admit the privileged pod, got denied: %+v", resp.Result)
	}
}

// TestEvaluate_AllowCarveOutDoesNotMatchOtherUser confirms the carve-out is
// scoped: a non-matching user still hits the deny rule.
func TestEvaluate_AllowCarveOutDoesNotMatchOtherUser(t *testing.T) {
	e := &PolicyEngine{Rules: []Rule{
		{ID: "block-privileged", Mode: "enforce", Kinds: []string{"Pod"},
			Conditions: RuleConditions{Privileged: boolPtr(true)}},
		{ID: "allow-system", Mode: "enforce", Effect: EffectAllow, Kinds: []string{"Pod"},
			Conditions: RuleConditions{UserMatch: `system:serviceaccount:kube-system:.*`}},
	}}

	req := reviewForUser(privilegedPod(), "system:serviceaccount:default:app")
	resp := e.Evaluate(context.Background(), req)
	if resp.Allowed {
		t.Fatalf("non-matching user must still be denied by the privileged rule")
	}
}

// TestEvaluate_MonitorAllowOnlyObserves confirms the SAFETY default: a
// monitor-mode allow rule does NOT short-circuit; it only warns, so the deny
// rule still blocks until an operator flips the carve-out to enforce.
func TestEvaluate_MonitorAllowOnlyObserves(t *testing.T) {
	e := &PolicyEngine{Rules: []Rule{
		{ID: "block-privileged", Mode: "enforce", Kinds: []string{"Pod"},
			Conditions: RuleConditions{Privileged: boolPtr(true)}},
		{ID: "allow-system", Mode: "monitor", Effect: EffectAllow, Kinds: []string{"Pod"},
			Conditions: RuleConditions{UserMatch: `system:serviceaccount:kube-system:.*`}},
	}}

	req := reviewForUser(privilegedPod(), "system:serviceaccount:kube-system:deployer")
	resp := e.Evaluate(context.Background(), req)
	if resp.Allowed {
		t.Fatalf("monitor-mode allow must NOT carve out; deny should still block")
	}
	var sawWarning bool
	for _, w := range resp.Warnings {
		if strings.Contains(w, "allow-system") && strings.Contains(w, "would carve out") {
			sawWarning = true
		}
	}
	if !sawWarning {
		t.Fatalf("monitor-mode allow should record an observe warning, got: %v", resp.Warnings)
	}
}

func TestRuleFromYAML_AllowAndExceptSetEffect(t *testing.T) {
	for _, action := range []string{"allow", "except", "exception"} {
		spec := `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: allow-x
spec:
  match:
    kinds: ["Pod"]
  identity:
    userMatch: system:serviceaccount:kube-system:.*
  action: ` + action + "\n"
		rule, supported, err := RuleFromYAML("allow-x", "allow-x", "", "monitor", spec)
		if err != nil {
			t.Fatalf("action %q: %v", action, err)
		}
		if !supported {
			t.Fatalf("action %q: expected supported", action)
		}
		if !rule.isAllow() || rule.Effect != EffectAllow {
			t.Fatalf("action %q: expected allow effect, got %q", action, rule.Effect)
		}
	}
}

func TestRuleFromYAML_DefaultEffectIsDeny(t *testing.T) {
	spec := `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: deny-x
spec:
  match:
    kinds: ["Pod"]
  identity:
    userMatch: system:serviceaccount:kube-system:.*
`
	rule, _, err := RuleFromYAML("deny-x", "deny-x", "", "enforce", spec)
	if err != nil {
		t.Fatal(err)
	}
	if rule.isAllow() || rule.Effect != EffectDeny {
		t.Fatalf("expected deny effect by default, got %q", rule.Effect)
	}
}

func TestRuleFromYAML_UnknownActionRejected(t *testing.T) {
	spec := `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: bad
spec:
  match:
    kinds: ["Pod"]
  images:
    requireDigest: true
  action: bogus
`
	if _, _, err := RuleFromYAML("bad", "bad", "", "enforce", spec); err == nil {
		t.Fatal("expected unknown action to be rejected")
	}
}
