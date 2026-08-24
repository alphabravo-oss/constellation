package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"

	constadmission "github.com/alphabravocompany/constellation/pkg/admission"
)

// fakeCVEEvidence denies any pod whose container image exceeds a critical-CVE
// gate, standing in for the Postgres-backed admissionevidence source so the
// assess path can be exercised without a database.
type fakeCVEEvidence struct{ reason string }

func (f fakeCVEEvidence) EvaluateAdmissionEvidence(_ context.Context, _ constadmission.Rule, _ *corev1.Pod) (string, bool, error) {
	return f.reason, true, nil
}

func (f fakeCVEEvidence) EvaluateAdmissionEvidenceWithDetails(_ context.Context, _ constadmission.Rule, _ *corev1.Pod) (string, bool, []constadmission.EvidenceDetail, error) {
	return f.reason, true, nil, nil
}

func TestAssessImageMatchesHandlesAdmissionCatalogSupportedCriteria(t *testing.T) {
	unsupported := []string{}
	evaluated := 0

	for _, opt := range admissionCriteriaCatalog() {
		t.Run(opt.Key, func(t *testing.T) {
			name := "catalog-" + strings.ReplaceAll(opt.Key, "_", "-")
			body := bodyWith([2]string{opt.Key, sampleAdmissionCriterionValue(opt)})
			body.Name = name
			specYAML, err := buildAdmissionSpecYAML(body)
			if err != nil {
				t.Fatalf("buildAdmissionSpecYAML: %v", err)
			}
			if _, supported, err := constadmission.RuleFromYAML(name, name, "", "enforce", specYAML); err != nil {
				t.Fatalf("RuleFromYAML: %v\n%s", err, specYAML)
			} else if !supported {
				unsupported = append(unsupported, opt.Key)
				return
			}

			evaluated++
			policies := []policyDTO{{
				ID:       uuid.New(),
				Name:     name,
				Engine:   "constellation-admission",
				Category: "admission",
				Enabled:  true,
				Mode:     "enforce",
				SpecYAML: specYAML,
			}}
			matches, err := assessImageMatches(
				context.Background(),
				"ghcr.io/acme/app:latest",
				"default",
				map[string]string{"app": "catalog-assess"},
				policies,
				fakeCVEEvidence{reason: "catalog evidence gate hit"},
				nil,
				nil,
			)
			if err != nil {
				t.Fatalf("assessImageMatches: %v", err)
			}
			if !criterionMatchesSyntheticAssessPod(opt.Key) {
				return
			}
			if len(matches) != 1 {
				t.Fatalf("expected one dry-run match, got %d: %+v\n%s", len(matches), matches, specYAML)
			}
			if matches[0].PolicyName != name || matches[0].Action != "deny" || strings.TrimSpace(matches[0].Reason) == "" {
				t.Fatalf("unexpected match payload: %+v", matches[0])
			}
		})
	}

	if evaluated == 0 {
		t.Fatal("expected at least one supported catalog criterion")
	}
	if len(unsupported) != 1 || unsupported[0] != "namespace" {
		t.Fatalf("unsupported catalog criteria = %v, want [namespace] only", unsupported)
	}
}

func sampleAdmissionCriterionValue(opt admissionCriterionOption) string {
	switch opt.Key {
	case "namespace":
		return "default"
	case "allowed_registries":
		return "registry.corp/acme"
	case "denied_cves":
		return "CVE-2026-CATALOG"
	case "pss_level":
		return "restricted"
	}
	switch opt.ValueType {
	case "int":
		return "1"
	case "float":
		return "1.0"
	case "severity":
		return "high"
	case "csv":
		return "prod,staging"
	default:
		return ""
	}
}

func criterionMatchesSyntheticAssessPod(key string) bool {
	switch key {
	case "run_as_privileged",
		"host_network",
		"host_pid",
		"host_ipc",
		"allow_privilege_escalation",
		"image_no_os":
		return false
	default:
		return true
	}
}

// TestAssessImageMatchesDeniesOnCVEGate asserts a known-bad image (one that
// exceeds a critical-CVE gate) is denied by assess with the gate's reason.
func TestAssessImageMatchesDeniesOnCVEGate(t *testing.T) {
	policies := []policyDTO{{
		Name:    "block-critical-cves",
		Engine:  "constellation-admission",
		Mode:    "enforce",
		Enabled: true,
		SpecYAML: "apiVersion: constellation.alphabravo.io/v1\n" +
			"kind: AdmissionRule\n" +
			"spec:\n" +
			"  match:\n    kinds: [Pod]\n" +
			"  vulnerability:\n    maxCriticalCount: 0\n",
	}}
	reason := `image "bad.example.com/app:latest" has 3 critical CVEs (policy allows at most 0)`

	matches, err := assessImageMatches(context.Background(), "bad.example.com/app:latest", "default", nil, policies, fakeCVEEvidence{reason: reason}, nil, nil)
	if err != nil {
		t.Fatalf("assessImageMatches: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Action != "deny" {
		t.Fatalf("expected deny, got %q", matches[0].Action)
	}
	if !strings.Contains(matches[0].Reason, "critical CVEs") {
		t.Fatalf("expected CVE reason, got %q", matches[0].Reason)
	}
}
