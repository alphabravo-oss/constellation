package k8scompliance

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestCollect_CustomChecks_PassAndFail verifies user-supplied CEL checks are evaluated over
// collected objects and produce Custom-framework compliance rows. Without the custom-check
// wiring in Collect this returns zero custom evidence and the test fails.
func TestCollect_CustomChecks_PassAndFail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "good", Namespace: "default"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "default"}},
	)
	checks := []CustomCheck{{
		ID:          "check-1",
		Name:        "name must not be bad",
		Severity:    "high",
		TargetKind:  "Deployment",
		Expression:  `object.metadata.name != "bad"`,
		Remediation: "rename the workload",
	}}

	items, err := Collect(context.Background(), client, Options{
		ObservedAt:   time.Unix(1700000000, 0).UTC(),
		CustomChecks: checks,
	})
	if err != nil {
		t.Fatal(err)
	}

	byTarget := map[string]Evidence{}
	for _, it := range items {
		if it.Custom {
			byTarget[it.Target] = it
		}
	}
	if len(byTarget) != 2 {
		t.Fatalf("expected 2 custom evidence rows, got %d", len(byTarget))
	}
	if got := byTarget["default/good"]; got.Status != "pass" {
		t.Fatalf("good deployment: want pass, got %q", got.Status)
	}
	bad := byTarget["default/bad"]
	if bad.Status != "fail" {
		t.Fatalf("bad deployment: want fail, got %q", bad.Status)
	}
	if bad.Severity != "high" || bad.Title != "name must not be bad" {
		t.Fatalf("bad deployment: unexpected title/severity: %+v", bad)
	}

	// A custom Evidence expands into a single "Custom" framework row carrying the check id.
	expanded := bad.Expand()
	if len(expanded) != 1 {
		t.Fatalf("expected 1 expanded check, got %d", len(expanded))
	}
	if expanded[0].Framework != "Custom" || expanded[0].ControlID != "check-1" || expanded[0].Status != "fail" {
		t.Fatalf("unexpected expanded check: %+v", expanded[0])
	}
}

// TestEvaluateCustomChecks_FailsClosedOnError ensures a CEL expression that errors at runtime
// (e.g. referencing an absent key) is scored as a violation rather than silently passing.
func TestEvaluateCustomChecks_FailsClosedOnError(t *testing.T) {
	targets := []customTarget{{
		kind:   "Deployment",
		name:   "api",
		object: map[string]any{"metadata": map[string]any{"name": "api"}},
	}}
	checks := []CustomCheck{{
		ID:         "c",
		TargetKind: "Deployment",
		Expression: `object.spec.replicas > 0`, // no spec key -> eval error
	}}
	out := evaluateCustomChecks(checks, targets, time.Unix(1700000000, 0).UTC())
	if len(out) != 1 || out[0].Status != "fail" {
		t.Fatalf("want single fail (fail-closed), got %+v", out)
	}
}

func TestValidateExpression(t *testing.T) {
	if err := ValidateExpression(`object.metadata.name == "x"`); err != nil {
		t.Fatalf("valid expression rejected: %v", err)
	}
	if err := ValidateExpression(`this is not (cel`); err == nil {
		t.Fatal("expected compile error for malformed expression")
	}
	if err := ValidateExpression(``); err == nil {
		t.Fatal("expected error for empty expression")
	}
}
