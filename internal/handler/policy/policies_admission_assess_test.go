package policy

import (
	"context"
	"strings"
	"testing"

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

	matches, err := assessImageMatches(context.Background(), "bad.example.com/app:latest", "default", nil, policies, fakeCVEEvidence{reason: reason}, nil)
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
