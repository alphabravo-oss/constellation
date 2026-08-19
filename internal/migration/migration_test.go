package migration_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/migration/aqua"
	"github.com/alphabravocompany/constellation/internal/migration/neuvector"
	"github.com/alphabravocompany/constellation/internal/migration/prisma"
	constellationadmission "github.com/alphabravocompany/constellation/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const nvExport = `
admission:
  rules:
    - id: 1001
      desc: Block latest tag
      action: deny
      criteria:
        - { key: image_name, op: regex, value: ".*:latest$" }
response:
  rules:
    - id: 2001
      event: process
      conditions: [process_baseline]
      actions: [alert, quarantine]
`

func TestNeuVector_Convert(t *testing.T) {
	out, err := neuvector.Convert([]byte(nvExport))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d", len(out))
	}
	// The latest-tag admission criterion is supported, so it converts to a real
	// constellation-admission rule (not the legacy no-op enforce Kyverno policy).
	if out[0].Engine != "constellation-admission" {
		t.Fatalf("admission engine: %s", out[0].Engine)
	}
	if out[0].Mode != "enforce" {
		t.Fatalf("deny admission rule should be enforce, got %s", out[0].Mode)
	}
	if !strings.Contains(out[0].SpecYAML, "disallowLatestTag") {
		t.Fatalf("admission spec should carry a real pattern, got:\n%s", out[0].SpecYAML)
	}
	if out[1].Mode != "enforce" {
		t.Fatalf("response w/ quarantine should be enforce, got %s", out[1].Mode)
	}
}

const nvFileMonitorExport = `
profiles:
  - group: nv.default.api
    mode: protect
    cfg_type: user_created
    filters:
      - filter: /etc/passwd
        recursive: false
        behavior: block_access
        applications: [cat, vi, cat]
---
kind: NvSecurityRule
metadata:
  name: payments-file-profile
spec:
  target:
    selector:
      name: nv.payments
  process_profile:
    mode: monitor
  file:
    - filter: /var/run/secrets/kubernetes.io/serviceaccount/*
      recursive: true
      behavior: monitor_change
      app: [sh]
`

func TestNeuVector_ConvertFileProfiles(t *testing.T) {
	out, err := neuvector.ConvertFileProfiles([]byte(nvFileMonitorExport))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d profiles: %+v", len(out), out)
	}
	if out[0].Group != "nv.default.api" ||
		out[0].Mode != "enforce" ||
		out[0].Rules[0].Behavior != "block_access" ||
		len(out[0].Rules[0].Applications) != 2 {
		t.Fatalf("rest file profile = %+v", out[0])
	}
	if out[1].Group != "nv.payments" ||
		out[1].Mode != "monitor" ||
		out[1].Rules[0].Filter != "/var/run/secrets/kubernetes.io/serviceaccount/*" ||
		out[1].Rules[0].Applications[0] != "sh" ||
		!out[1].Rules[0].Recursive {
		t.Fatalf("crd file profile = %+v", out[1])
	}
}

const nvAdmissionProfileExport = `
admission:
  rules:
    - id: 3001
      desc: Block latest tag
      action: deny
      criteria:
        - { key: image_name, op: regex, value: ".*:latest$" }
    - id: 3002
      desc: Block privileged containers
      action: deny
      criteria:
        - { key: privileged, op: eq, value: "true" }
    - id: 3003
      desc: Critical CVE gate
      action: deny
      criteria:
        - { key: severity, op: eq, value: "critical" }
    - id: 3004
      desc: Vendor-specific sharing mode
      action: deny
      criteria:
        - { key: share_network_namespace, op: eq, value: "container:sidecar" }
`

func TestNeuVector_ConvertAdmissionProfileBundleParity(t *testing.T) {
	bundle, err := neuvector.ConvertAdmissionProfileBundle([]byte(nvAdmissionProfileExport))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.APIVersion != constellationadmission.AdmissionProfileAPIVersion ||
		bundle.Kind != constellationadmission.AdmissionProfileKind {
		t.Fatalf("bad bundle envelope: %+v", bundle)
	}
	if bundle.Profile.ID != "neuvector-import" {
		t.Fatalf("profile id: %s", bundle.Profile.ID)
	}
	if bundle.Profile.FailurePolicy != "Fail" {
		t.Fatalf("failure policy: %s", bundle.Profile.FailurePolicy)
	}

	var liveRules []constellationadmission.Rule
	var manualReviewFound, vulnerabilityGateFound bool
	for _, profileRule := range bundle.Profile.Rules {
		switch profileRule.Engine {
		case "manual-review":
			manualReviewFound = true
			if profileRule.Enabled {
				t.Fatalf("manual-review rule should be disabled: %+v", profileRule)
			}
			if !strings.Contains(profileRule.SpecYAML, "share_network_namespace") {
				t.Fatalf("manual-review spec lost unsupported criterion: %s", profileRule.SpecYAML)
			}
			continue
		case "constellation-admission":
			rule, supported, err := constellationadmission.RuleFromYAML(
				"neuvector-import/"+profileRule.Name,
				profileRule.Name,
				profileRule.Description,
				profileRule.Mode,
				profileRule.SpecYAML,
			)
			if err != nil {
				t.Fatalf("parse converted rule %s: %v", profileRule.Name, err)
			}
			if profileRule.Category == "vulnerability-gating" {
				vulnerabilityGateFound = true
				if !supported || len(rule.Conditions.EvidenceGates) == 0 {
					t.Fatalf("vulnerability-backed import should produce an evidence gate: %+v", rule)
				}
				continue
			}
			if !supported {
				t.Fatalf("converted rule should be locally enforceable: %s", profileRule.Name)
			}
			liveRules = append(liveRules, rule)
		default:
			t.Fatalf("unexpected profile rule engine %q", profileRule.Engine)
		}
	}
	if !manualReviewFound {
		t.Fatal("unsupported NeuVector criteria should be preserved as a manual-review rule")
	}
	if !vulnerabilityGateFound {
		t.Fatal("critical vulnerability rule should be preserved as an evidence-backed admission gate")
	}
	if len(liveRules) < 2 {
		t.Fatalf("expected latest-tag and privileged live rules, got %d", len(liveRules))
	}

	engine := &constellationadmission.PolicyEngine{Rules: liveRules}
	if resp := engine.Evaluate(context.Background(), admissionReviewForPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "latest"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "registry.example/app:latest",
		}}},
	})); resp.Allowed {
		t.Fatal("converted latest-tag rule should deny latest images")
	}
	t1 := true
	if resp := engine.Evaluate(context.Background(), admissionReviewForPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "privileged"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "registry.example/app:1.0",
			SecurityContext: &corev1.SecurityContext{Privileged: &t1},
		}}},
	})); resp.Allowed {
		t.Fatal("converted privileged rule should deny privileged containers")
	}
}

const aquaExport = `
[
  {"id":42,"name":"Block critical CVEs","description":"Image assurance","enabled":true,
   "fail_cicd_on":true,
   "controls":{"block_critical_vulns":true,"block_high_vulns":false,"scan_coverage_pct":95}}
]`

func TestAqua_Convert(t *testing.T) {
	out, err := aqua.Convert([]byte(aquaExport))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d", len(out))
	}
	if out[0].Mode != "enforce" {
		t.Fatalf("block_critical should enforce, got %s", out[0].Mode)
	}
	if !strings.Contains(out[0].SpecYAML, "block_critical: true") {
		t.Fatalf("yaml missing block_critical: %s", out[0].SpecYAML)
	}
}

const prismaExport = `
{"policies":[
  {"policyId":"P-1001","name":"S3 public","policyType":"config","severity":"high",
   "enabled":true,"description":"public bucket",
   "complianceMetadata":[{"standardName":"PCI-DSS","sectionId":"3.4"}]}
]}`

func TestPrisma_Convert(t *testing.T) {
	out, err := prisma.Convert([]byte(prismaExport))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d", len(out))
	}
	if out[0].Mode != "enforce" {
		t.Fatalf("high severity should enforce, got %s", out[0].Mode)
	}
	if !strings.Contains(out[0].SpecYAML, "PCI-DSS:3.4") {
		t.Fatalf("frameworks missing in yaml: %s", out[0].SpecYAML)
	}
}

func admissionReviewForPod(pod *corev1.Pod) *admissionv1.AdmissionRequest {
	raw, _ := json.Marshal(pod)
	return &admissionv1.AdmissionRequest{
		UID:       "test",
		Kind:      metav1.GroupVersionKind{Kind: "Pod"},
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	}
}
