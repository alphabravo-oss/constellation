package admission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func reviewFor(pod *corev1.Pod) *admissionv1.AdmissionRequest {
	b, _ := json.Marshal(pod)
	return &admissionv1.AdmissionRequest{
		UID:    "test-uid",
		Kind:   metav1.GroupVersionKind{Kind: "Pod"},
		Object: runtime.RawExtension{Raw: b},
	}
}

func TestEvaluate_BlocksPrivileged(t *testing.T) {
	e := NewEngine()
	t1 := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "evil"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "c", Image: "alpine:3.18",
				SecurityContext: &corev1.SecurityContext{Privileged: &t1},
			}},
		},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatalf("privileged pod must be denied")
	}
	if resp.Result == nil || resp.Result.Message == "" {
		t.Fatalf("expected denial message")
	}
}

func TestEvaluate_BlocksPrivilegedEphemeralContainer(t *testing.T) {
	e := NewEngine()
	t1 := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "debug-target",
			Annotations: map[string]string{SignatureAnnotation: "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "alpine:3.18",
				SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &t1},
			}},
			EphemeralContainers: []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name: "debugger", Image: "busybox:1.36",
					SecurityContext: &corev1.SecurityContext{Privileged: &t1},
				},
				TargetContainerName: "app",
			}},
		},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatalf("privileged ephemeral container must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, `container "debugger" is privileged`) {
		t.Fatalf("expected denial to name the privileged ephemeral container, got: %+v", resp.Result)
	}
}

func TestEvaluate_BlocksHostNetwork(t *testing.T) {
	e := NewEngine()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hostnet"},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers:  []corev1.Container{{Name: "c", Image: "alpine:3.18"}},
		},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatalf("hostNetwork pod must be denied")
	}
}

func TestEvaluate_MonitorOnlyEmitsWarnings(t *testing.T) {
	e := NewEngine()
	// No signature annotation + no readOnlyRoot → both monitor-mode rules fire as warnings.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ok"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c", Image: "alpine:3.18"}},
		},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if !resp.Allowed {
		t.Fatalf("expected pod allowed (monitor rules only)")
	}
	if len(resp.Warnings) == 0 {
		t.Fatalf("expected at least one monitor-mode warning")
	}
}

func TestEvaluate_AllowsCompliantPod(t *testing.T) {
	e := NewEngine()
	t1 := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "good",
			Annotations: map[string]string{SignatureAnnotation: "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "c", Image: "alpine:3.18",
				SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &t1},
			}},
		},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if !resp.Allowed {
		t.Fatalf("compliant pod should be allowed: %+v", resp.Result)
	}
	if len(resp.Warnings) > 0 {
		t.Fatalf("expected zero warnings on a compliant pod, got %v", resp.Warnings)
	}
}

func TestImageInAllowlist_RegistryBoundary(t *testing.T) {
	cases := []struct {
		name      string
		image     string
		allowlist []string
		want      bool
	}{
		{"exact host allowed", "registry.corp.com/app:1.0", []string{"registry.corp.com"}, true},
		{"spoofed suffix denied", "registry.corp.com.evil.io/malware:latest", []string{"registry.corp.com"}, false},
		{"trailing slash entry", "registry.corp/app:1.0", []string{"registry.corp/"}, true},
		{"non-allowlisted host", "docker.io/library/nginx:1.25", []string{"registry.corp/"}, false},
		{"path prefix exact repo", "registry.corp/team:1.0", []string{"registry.corp/team"}, true},
		{"path prefix descendant", "registry.corp/team/app:1.0", []string{"registry.corp/team"}, true},
		{"path prefix boundary spoof", "registry.corp/teamevil/app:1.0", []string{"registry.corp/team"}, false},
		{"digest pinned host", "registry.corp/app@sha256:" + strings.Repeat("a", 64), []string{"registry.corp"}, true},
	}
	for _, c := range cases {
		if got := imageInAllowlist(c.image, c.allowlist); got != c.want {
			t.Errorf("%s: imageInAllowlist(%q, %v) = %v; want %v", c.name, c.image, c.allowlist, got, c.want)
		}
	}
}
