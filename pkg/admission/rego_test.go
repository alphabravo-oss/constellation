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

const blockHostNetworkRego = `
package constellation.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  input.request.object.spec.hostNetwork == true
  msg := "hostNetwork is forbidden by org policy"
}
`

func TestRegoEngine_DeniesHostNetworkPod(t *testing.T) {
	ctx := context.Background()
	e, errs, err := NewRegoEngine(ctx,
		map[string]string{"block-host-network": blockHostNetworkRego},
		map[string]string{"block-host-network": "enforce"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 0 {
		t.Fatalf("compile errs: %v", errs)
	}
	pod := &corev1.Pod{Spec: corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "x", Image: "alpine"}}}}
	raw, _ := json.Marshal(pod)
	resp := e.Evaluate(ctx, &admissionv1.AdmissionRequest{
		UID:    "u-1",
		Kind:   metav1.GroupVersionKind{Kind: "Pod"},
		Object: runtime.RawExtension{Raw: raw},
	})
	if resp.Allowed {
		t.Fatalf("hostNetwork pod should be denied; result: %+v", resp.Result)
	}
}

func TestRegoEngine_AllowsCompliantPod(t *testing.T) {
	ctx := context.Background()
	e, _, _ := NewRegoEngine(ctx,
		map[string]string{"block-host-network": blockHostNetworkRego},
		map[string]string{"block-host-network": "enforce"},
	)
	pod := &corev1.Pod{Spec: corev1.PodSpec{HostNetwork: false, Containers: []corev1.Container{{Name: "x", Image: "alpine"}}}}
	raw, _ := json.Marshal(pod)
	resp := e.Evaluate(ctx, &admissionv1.AdmissionRequest{
		UID: "u-2", Kind: metav1.GroupVersionKind{Kind: "Pod"},
		Object: runtime.RawExtension{Raw: raw},
	})
	if !resp.Allowed {
		t.Fatalf("compliant pod should pass: %+v", resp.Result)
	}
}

func TestRegoEngine_MonitorEmitsWarnings(t *testing.T) {
	ctx := context.Background()
	e, _, _ := NewRegoEngine(ctx,
		map[string]string{"block-host-network": blockHostNetworkRego},
		map[string]string{"block-host-network": "monitor"},
	)
	pod := &corev1.Pod{Spec: corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "x", Image: "alpine"}}}}
	raw, _ := json.Marshal(pod)
	resp := e.Evaluate(ctx, &admissionv1.AdmissionRequest{
		UID: "u-3", Kind: metav1.GroupVersionKind{Kind: "Pod"},
		Object: runtime.RawExtension{Raw: raw},
	})
	if !resp.Allowed {
		t.Fatalf("monitor-mode rego should not deny")
	}
	if len(resp.Warnings) == 0 {
		t.Fatalf("expected warnings on monitor-mode hit")
	}
}

// regoEvalConflict triggers a non-suppressible OPA runtime error (object key
// conflict: the same key "dup" is bound to two distinct container images). OPA's
// default config swallows *builtin* errors as undefined, but a comprehension key
// conflict always surfaces as an eval error — a deterministic way to exercise
// the engine's error path.
const regoEvalConflict = `
package constellation.admission

deny[msg] {
  obj := {k: v | k := "dup"; v := input.request.object.spec.containers[_].image}
  msg := sprintf("%v", [obj])
}
`

// TestRegoEngine_EnforceEvalErrorFailsClosed is the regression guard for the
// fail-open finding: an enforce-mode Rego policy whose evaluation ERRORS must
// DENY (fail closed), not warn-and-admit. The same error under monitor mode
// must keep warning so a faulty policy can't start blocking on an error.
func TestRegoEngine_EnforceEvalErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "n"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "a", Image: "img-a"}, {Name: "b", Image: "img-b"}}},
	}
	raw, _ := json.Marshal(pod)
	req := &admissionv1.AdmissionRequest{UID: "u", Kind: metav1.GroupVersionKind{Kind: "Pod"}, Object: runtime.RawExtension{Raw: raw}}

	enforce, errs, err := NewRegoEngine(ctx, map[string]string{"p": regoEvalConflict}, map[string]string{"p": "enforce"})
	if err != nil || len(errs) != 0 {
		t.Fatalf("compile: %v %v", err, errs)
	}
	if resp := enforce.Evaluate(ctx, req); resp.Allowed {
		t.Fatalf("enforce rego eval error must fail closed (deny); got allow: %+v", resp)
	}

	monitor, _, _ := NewRegoEngine(ctx, map[string]string{"p": regoEvalConflict}, map[string]string{"p": "monitor"})
	resp := monitor.Evaluate(ctx, req)
	if !resp.Allowed {
		t.Fatalf("monitor rego eval error must not deny; got %+v", resp.Result)
	}
	if len(resp.Warnings) == 0 {
		t.Fatalf("monitor rego eval error should surface a warning")
	}
}

func TestRegoEngine_CompileErrorIsolated(t *testing.T) {
	ctx := context.Background()
	_, errs, _ := NewRegoEngine(ctx,
		map[string]string{
			"bad":  `not actually rego`,
			"good": blockHostNetworkRego,
		},
		map[string]string{},
	)
	if _, ok := errs["bad"]; !ok {
		t.Fatalf("expected compile error for 'bad' policy: %v", errs)
	}
	if _, ok := errs["good"]; ok {
		t.Fatalf("good policy should compile cleanly")
	}
}
