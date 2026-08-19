package controllers

import (
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/deploy/operator/policydb"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// TestExportRoundTrip_Admission proves the GitOps loop closes for admission rules: a stored row
// exported to a CR (policydb.AdmissionCR) and fed back through the reconciler's mapping
// (mapAdmissionRule) reproduces the identical row. Export then `kubectl apply` is lossless.
func TestExportRoundTrip_Admission(t *testing.T) {
	org := uuid.New()
	want := policydb.AdmissionRuleRow{
		OrgID:       org,
		Name:        "no-privileged",
		Description: "block privileged pods",
		Engine:      "kyverno",
		Mode:        "enforce",
		Enabled:     true,
		SpecYAML:    "rules:\n  - deny: privileged\n",
	}

	cr := policydb.AdmissionCR(want)

	// The exported CR must be self-describing (kubectl-applyable).
	if cr.APIVersion != policydb.APIVersion || cr.Kind != policydb.KindAdmissionRule {
		t.Fatalf("CR TypeMeta = %s/%s, want %s/%s", cr.APIVersion, cr.Kind, policydb.APIVersion, policydb.KindAdmissionRule)
	}
	if cr.Name != want.Name {
		t.Fatalf("CR metadata.name = %q, want %q", cr.Name, want.Name)
	}

	got, err := mapAdmissionRule(cr)
	if err != nil {
		t.Fatalf("mapAdmissionRule: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

// TestExportRoundTrip_Response proves the GitOps loop closes for response rules: a stored rule
// exported to a CR (policydb.ResponseCR) and fed back through mapResponseRule reproduces the
// identical rule (modulo the DB-assigned ID, which is not part of the CR's identity).
func TestExportRoundTrip_Response(t *testing.T) {
	org := uuid.New()
	want := responserule.ResponseRule{
		OrgID:     org,
		Name:      "curl-quarantine",
		Enabled:   true,
		Priority:  10,
		EventType: responserule.EventProcess,
		Conditions: []responserule.Condition{
			{Field: "process_name", Op: responserule.OpContains, Value: "curl"},
			{Field: "severity", Op: responserule.OpGt, Value: "7"},
		},
		Actions: []responserule.Action{
			{Type: responserule.ActionQuarantine},
			{Type: responserule.ActionWebhook, Params: map[string]string{"receiver": "sec-webhook"}},
		},
	}

	cr := policydb.ResponseCR(want)
	if cr.APIVersion != policydb.APIVersion || cr.Kind != policydb.KindResponseRule {
		t.Fatalf("CR TypeMeta = %s/%s, want %s/%s", cr.APIVersion, cr.Kind, policydb.APIVersion, policydb.KindResponseRule)
	}

	got, err := mapResponseRule(cr)
	if err != nil {
		t.Fatalf("mapResponseRule: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}
