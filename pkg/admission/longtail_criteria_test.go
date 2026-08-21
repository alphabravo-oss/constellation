package admission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// engineWith builds a single-enforce-rule engine for the given conditions so a
// pod that violates the condition is denied and a compliant one is admitted.
func engineWith(id string, conds RuleConditions) *PolicyEngine {
	return &PolicyEngine{Rules: []Rule{{
		ID: id, Title: id, Mode: "enforce", Kinds: []string{"Pod"},
		Conditions: conds,
	}}}
}

// --- ADM-30: OpenShift DeploymentConfig is not bypassed ---------------------

func TestEvaluate_DeniesBadDeploymentConfigTemplate(t *testing.T) {
	e := NewEngine() // built-in block-privileged
	dc := map[string]any{
		"apiVersion": "apps.openshift.io/v1",
		"kind":       "DeploymentConfig",
		"metadata":   map[string]any{"name": "evil-dc", "namespace": "prod"},
		"spec": map[string]any{
			"template": corev1.PodTemplateSpec{Spec: privilegedPodSpec()},
		},
	}
	raw, _ := json.Marshal(dc)

	resp := e.Evaluate(context.Background(), reviewForKind("DeploymentConfig", raw))
	if resp.Allowed {
		t.Fatalf("DeploymentConfig with a privileged pod template must be denied (ADM-30)")
	}
}

func TestExtractPodFromObject_DeploymentConfig(t *testing.T) {
	if !isPodTemplateKind("DeploymentConfig") {
		t.Fatal("DeploymentConfig must be recognised as a pod-template kind")
	}
	dc := map[string]any{
		"kind":     "DeploymentConfig",
		"metadata": map[string]any{"name": "web", "namespace": "apps"},
		"spec": map[string]any{
			"template": corev1.PodTemplateSpec{Spec: privilegedPodSpec()},
		},
	}
	raw, _ := json.Marshal(dc)
	pod, err := extractPodFromObject("DeploymentConfig", raw)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if pod.Name != "web" || pod.Namespace != "apps" {
		t.Fatalf("expected controller identity fallback, got name=%q ns=%q", pod.Name, pod.Namespace)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("expected template container carried over, got %d", len(pod.Spec.Containers))
	}
}

// --- ADM-26: HostIPC --------------------------------------------------------

func TestEvaluate_HostIPC(t *testing.T) {
	tr := true
	e := engineWith("block-host-ipc", RuleConditions{HostIPC: &tr})

	bad := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ipc"},
		Spec:       corev1.PodSpec{HostIPC: true, Containers: []corev1.Container{{Name: "c", Image: "alpine:3.18"}}},
	}
	if resp := e.Evaluate(context.Background(), reviewFor(bad)); resp.Allowed {
		t.Fatal("pod sharing host IPC must be denied")
	}

	good := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "no-ipc"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "alpine:3.18"}}},
	}
	if resp := e.Evaluate(context.Background(), reviewFor(good)); !resp.Allowed {
		t.Fatalf("pod not sharing host IPC must be admitted: %+v", resp.Result)
	}
}

// --- ADM-26: allowPrivilegeEscalation --------------------------------------

func TestEvaluate_AllowPrivilegeEscalation(t *testing.T) {
	tr := true
	fa := false
	e := engineWith("block-priv-esc", RuleConditions{AllowPrivilegeEscalation: &tr})

	bad := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "esc"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", Image: "alpine:3.18",
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &tr},
		}}},
	}
	resp := e.Evaluate(context.Background(), reviewFor(bad))
	if resp.Allowed {
		t.Fatal("container allowing privilege escalation must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "privilege escalation") {
		t.Fatalf("expected denial to mention privilege escalation, got %+v", resp.Result)
	}

	good := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "no-esc"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", Image: "alpine:3.18",
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &fa},
		}}},
	}
	if resp := e.Evaluate(context.Background(), reviewFor(good)); !resp.Allowed {
		t.Fatalf("container disallowing privilege escalation must be admitted: %+v", resp.Result)
	}
}

// --- ADM-26: imageNoOS ------------------------------------------------------

func TestEvaluate_ImageNoOS(t *testing.T) {
	tr := true
	e := engineWith("block-no-os", RuleConditions{ImageNoOS: &tr})

	bad := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "scratch", Annotations: map[string]string{ImageNoOSAnnotation: "true"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "scratch"}}},
	}
	if resp := e.Evaluate(context.Background(), reviewFor(bad)); resp.Allowed {
		t.Fatal("pod flagged with no-OS image annotation must be denied")
	}

	good := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "distro"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "alpine:3.18"}}},
	}
	if resp := e.Evaluate(context.Background(), reviewFor(good)); !resp.Allowed {
		t.Fatalf("pod without the no-OS annotation must be admitted: %+v", resp.Result)
	}
}

// --- ADM-26: resourceLimit --------------------------------------------------

func TestEvaluate_ResourceLimit_MissingLimits(t *testing.T) {
	e := engineWith("require-limits", RuleConditions{ResourceLimit: &ResourceLimitCondition{
		RequireCPURequest: true, RequireCPULimit: true,
		RequireMemoryRequest: true, RequireMemoryLimit: true,
	}})

	bad := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "unbounded"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "alpine:3.18"}}},
	}
	resp := e.Evaluate(context.Background(), reviewFor(bad))
	if resp.Allowed {
		t.Fatal("container missing cpu/memory requests+limits must be denied")
	}

	good := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "bounded"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", Image: "alpine:3.18",
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("250m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
			},
		}}},
	}
	if resp := e.Evaluate(context.Background(), reviewFor(good)); !resp.Allowed {
		t.Fatalf("fully-bounded container must be admitted: %+v", resp.Result)
	}
}

func TestEvaluate_ResourceLimit_Exceeds(t *testing.T) {
	e := engineWith("cap-limits", RuleConditions{ResourceLimit: &ResourceLimitCondition{
		MaxCPULimit: "500m", MaxMemoryLimit: "256Mi",
	}})

	bad := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "greedy"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", Image: "alpine:3.18",
			Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse("2"),
			}},
		}}},
	}
	resp := e.Evaluate(context.Background(), reviewFor(bad))
	if resp.Allowed {
		t.Fatal("container whose CPU limit exceeds the cap must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "exceeds max") {
		t.Fatalf("expected denial mentioning the cap, got %+v", resp.Result)
	}

	good := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "modest"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", Image: "alpine:3.18",
			Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			}},
		}}},
	}
	if resp := e.Evaluate(context.Background(), reviewFor(good)); !resp.Allowed {
		t.Fatalf("container within the cap must be admitted: %+v", resp.Result)
	}
}
