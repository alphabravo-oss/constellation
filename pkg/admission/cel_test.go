package admission

import (
	"context"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestCELEngine_DeniesHostNetwork(t *testing.T) {
	rules := []*CELRule{
		{
			ID:                "block-host-network",
			Expression:        `object.spec.hostNetwork != true`,
			MessageExpression: `"hostNetwork is forbidden"`,
			Mode:              "enforce",
		},
	}
	e, errs, err := NewCELEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 0 {
		t.Fatalf("compile errs: %+v", errs)
	}
	pod := &corev1.Pod{Spec: corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "x", Image: "alpine"}}}}
	raw, _ := json.Marshal(pod)
	resp := e.Evaluate(context.Background(), &admissionv1.AdmissionRequest{
		UID:    "u-1",
		Kind:   metav1.GroupVersionKind{Kind: "Pod"},
		Object: runtime.RawExtension{Raw: raw},
	})
	if resp.Allowed {
		t.Fatalf("hostNetwork pod should be denied: %+v", resp)
	}
	if resp.Result == nil || resp.Result.Message != "hostNetwork is forbidden" {
		t.Fatalf("expected custom message; got %+v", resp.Result)
	}
}

func TestCELEngine_AllowsCompliant(t *testing.T) {
	rules := []*CELRule{{
		ID: "block-host-network",
		// Guard the absent key with has(): a correctly-authored rule does not
		// error on a pod that simply omits spec.hostNetwork.
		Expression: `!has(object.spec.hostNetwork) || object.spec.hostNetwork != true`,
		Mode:       "enforce",
	}}
	e, _, _ := NewCELEngine(rules)
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "x", Image: "alpine"}}}}
	raw, _ := json.Marshal(pod)
	resp := e.Evaluate(context.Background(), &admissionv1.AdmissionRequest{
		UID: "u-2", Kind: metav1.GroupVersionKind{Kind: "Pod"}, Object: runtime.RawExtension{Raw: raw},
	})
	if !resp.Allowed {
		t.Fatalf("compliant pod denied: %+v", resp.Result)
	}
}

// TestCELEngine_EnforceEvalErrorFailsClosed is the regression guard for the
// fail-open finding: an enforce-mode CEL expression that ERRORS at evaluation
// (here "no such key" on an absent securityContext) must DENY, not warn-and-
// admit. A monitor-mode rule with the same error keeps warning (never blocks).
func TestCELEngine_EnforceEvalErrorFailsClosed(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "x", Image: "alpine"}}}}
	raw, _ := json.Marshal(pod)
	req := &admissionv1.AdmissionRequest{
		UID: "u-err", Kind: metav1.GroupVersionKind{Kind: "Pod"}, Object: runtime.RawExtension{Raw: raw},
	}

	enforce, _, _ := NewCELEngine([]*CELRule{{
		ID:         "require-nonroot",
		Expression: `object.spec.securityContext.runAsNonRoot == true`, // errors: no securityContext
		Mode:       "enforce",
	}})
	if resp := enforce.Evaluate(context.Background(), req); resp.Allowed {
		t.Fatalf("enforce CEL eval error must fail closed (deny); got allow: %+v", resp)
	}

	monitor, _, _ := NewCELEngine([]*CELRule{{
		ID:         "require-nonroot",
		Expression: `object.spec.securityContext.runAsNonRoot == true`,
		Mode:       "monitor",
	}})
	resp := monitor.Evaluate(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("monitor CEL eval error must not deny; got %+v", resp.Result)
	}
	if len(resp.Warnings) == 0 {
		t.Fatalf("monitor CEL eval error should surface a warning")
	}
}

func TestCELEngine_MonitorEmitsWarnings(t *testing.T) {
	rules := []*CELRule{{
		ID:         "monitor-image-tag",
		Expression: `object.spec.containers.all(c, !c.image.endsWith(":latest"))`,
		Mode:       "monitor",
	}}
	e, _, _ := NewCELEngine(rules)
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "x", Image: "alpine:latest"}}}}
	raw, _ := json.Marshal(pod)
	resp := e.Evaluate(context.Background(), &admissionv1.AdmissionRequest{
		UID: "u-3", Kind: metav1.GroupVersionKind{Kind: "Pod"}, Object: runtime.RawExtension{Raw: raw},
	})
	if !resp.Allowed {
		t.Fatalf("monitor mode shouldn't deny")
	}
	if len(resp.Warnings) == 0 {
		t.Fatalf("expected warning")
	}
}
