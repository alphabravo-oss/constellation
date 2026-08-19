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

// reviewForKind builds an AdmissionRequest for an arbitrary kind from a
// pre-marshalled object. Controllers and PVCs are decoded generically by the
// engine, so we feed raw JSON rather than importing the apps/batch types.
func reviewForKind(kind string, raw []byte) *admissionv1.AdmissionRequest {
	return &admissionv1.AdmissionRequest{
		UID:    "test-uid",
		Kind:   metav1.GroupVersionKind{Kind: kind},
		Object: runtime.RawExtension{Raw: raw},
	}
}

// privilegedPodSpec returns a pod spec that the built-in catalog denies
// (block-privileged), used as the template for controller tests.
func privilegedPodSpec() corev1.PodSpec {
	t1 := true
	return corev1.PodSpec{
		Containers: []corev1.Container{{
			Name:            "c",
			Image:           "alpine:3.18",
			SecurityContext: &corev1.SecurityContext{Privileged: &t1},
		}},
	}
}

func TestEvaluate_DeniesBadDeploymentTemplate(t *testing.T) {
	e := NewEngine()

	dep := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "evil-dep", "namespace": "prod"},
		"spec": map[string]any{
			"template": corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Name: "evil-pod"},
				Spec:       privilegedPodSpec(),
			},
		},
	}
	raw, _ := json.Marshal(dep)

	resp := e.Evaluate(context.Background(), reviewForKind("Deployment", raw))
	if resp.Allowed {
		t.Fatalf("Deployment with privileged template must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "block-privileged") {
		t.Fatalf("expected block-privileged denial, got %+v", resp.Result)
	}
}

func TestEvaluate_AllowsCleanDeploymentTemplate(t *testing.T) {
	e := NewEngine()
	t1 := true
	dep := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "good-dep"},
		"spec": map[string]any{
			"template": corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{SignatureAnnotation: "true"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:            "c",
						Image:           "alpine:3.18",
						SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &t1},
					}},
				},
			},
		},
	}
	raw, _ := json.Marshal(dep)

	resp := e.Evaluate(context.Background(), reviewForKind("Deployment", raw))
	if !resp.Allowed {
		t.Fatalf("clean Deployment should be allowed, got %+v", resp.Result)
	}
}

func TestEvaluate_DeniesBadCronJobTemplate(t *testing.T) {
	e := NewEngine()
	cj := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "CronJob",
		"metadata":   map[string]any{"name": "evil-cron"},
		"spec": map[string]any{
			"jobTemplate": map[string]any{
				"spec": map[string]any{
					"template": corev1.PodTemplateSpec{Spec: privilegedPodSpec()},
				},
			},
		},
	}
	raw, _ := json.Marshal(cj)

	resp := e.Evaluate(context.Background(), reviewForKind("CronJob", raw))
	if resp.Allowed {
		t.Fatalf("CronJob with privileged template must be denied")
	}
}

func TestExtractPodFromObject_ControllerIdentityFallback(t *testing.T) {
	ss := map[string]any{
		"kind":     "StatefulSet",
		"metadata": map[string]any{"name": "db", "namespace": "data"},
		"spec": map[string]any{
			"template": corev1.PodTemplateSpec{Spec: privilegedPodSpec()},
		},
	}
	raw, _ := json.Marshal(ss)

	pod, err := extractPodFromObject("StatefulSet", raw)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if pod.Name != "db" || pod.Namespace != "data" {
		t.Fatalf("expected controller identity fallback, got name=%q ns=%q", pod.Name, pod.Namespace)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("expected template containers carried over, got %d", len(pod.Spec.Containers))
	}
}

// pvcEngine builds an engine with a single enforce rule that only allows the
// given storage classes on PersistentVolumeClaim.
func pvcEngine(mode string, allowed ...string) *PolicyEngine {
	return &PolicyEngine{Rules: []Rule{{
		ID:    "pvc-storageclass-allowlist",
		Title: "PVC storage class allowlist",
		Mode:  mode,
		Kinds: []string{"PersistentVolumeClaim"},
		Conditions: RuleConditions{
			AllowedStorageClasses: allowed,
		},
	}}}
}

func pvcRaw(name, sc string, scSet bool) []byte {
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "prod"},
	}
	if scSet {
		pvc.Spec.StorageClassName = &sc
	}
	raw, _ := json.Marshal(pvc)
	return raw
}

func TestEvaluate_PVCStorageClassGate(t *testing.T) {
	e := pvcEngine("enforce", "fast-ssd", "standard")

	// Disallowed class is denied.
	resp := e.Evaluate(context.Background(), reviewForKind("PersistentVolumeClaim", pvcRaw("c1", "slow-hdd", true)))
	if resp.Allowed {
		t.Fatalf("PVC with disallowed storageClassName must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "pvc-storageclass-allowlist") {
		t.Fatalf("expected denial message referencing the rule, got %+v", resp.Result)
	}

	// Allowed class passes.
	resp = e.Evaluate(context.Background(), reviewForKind("PersistentVolumeClaim", pvcRaw("c2", "fast-ssd", true)))
	if !resp.Allowed {
		t.Fatalf("PVC with allowed storageClassName must pass, got %+v", resp.Result)
	}
}

func TestEvaluate_PVCDefaultStorageClass(t *testing.T) {
	// An allowlist that does not include "" denies a PVC that omits the class.
	e := pvcEngine("enforce", "fast-ssd")
	resp := e.Evaluate(context.Background(), reviewForKind("PersistentVolumeClaim", pvcRaw("c1", "", false)))
	if resp.Allowed {
		t.Fatalf("PVC omitting storageClassName must be denied when default is not allowlisted")
	}

	// Including "" permits the cluster-default PVC.
	e = pvcEngine("enforce", "", "fast-ssd")
	resp = e.Evaluate(context.Background(), reviewForKind("PersistentVolumeClaim", pvcRaw("c2", "", false)))
	if !resp.Allowed {
		t.Fatalf("PVC omitting storageClassName must pass when \"\" is allowlisted, got %+v", resp.Result)
	}
}

func TestEvaluate_PVCMonitorModeWarns(t *testing.T) {
	e := pvcEngine("monitor", "fast-ssd")
	resp := e.Evaluate(context.Background(), reviewForKind("PersistentVolumeClaim", pvcRaw("c1", "slow-hdd", true)))
	if !resp.Allowed {
		t.Fatalf("monitor mode must not deny")
	}
	if len(resp.Warnings) == 0 || !strings.Contains(resp.Warnings[0], "monitor") {
		t.Fatalf("expected a monitor warning, got %+v", resp.Warnings)
	}
}

func TestRuleFromYAML_PVCStorageClass(t *testing.T) {
	spec := `
spec:
  match:
    kinds: [PersistentVolumeClaim]
  persistentVolumeClaim:
    allowedStorageClasses: [fast-ssd, standard]
`
	rule, supported, err := RuleFromYAML("pvc-rule", "PVC rule", "", "enforce", spec)
	if err != nil {
		t.Fatalf("RuleFromYAML: %v", err)
	}
	if !supported {
		t.Fatalf("PVC storage-class rule must be supported by the local engine")
	}
	if len(rule.Conditions.AllowedStorageClasses) != 2 {
		t.Fatalf("expected 2 allowed storage classes, got %+v", rule.Conditions.AllowedStorageClasses)
	}
	if !matchesKind(rule.Kinds, "PersistentVolumeClaim") {
		t.Fatalf("rule should scope to PersistentVolumeClaim")
	}
}
