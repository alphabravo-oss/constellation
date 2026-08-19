package handler

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestAdmissionDenyNotifyEvent asserts an admission.deny audit row folds into a notify.Event
// whose kind routes to "admission" receivers + the syslog mirror, and whose labels/workload
// carry the deny context. This is the mapping that makes admission denies reach webhooks and
// syslog (P1-18); before this change there was no such delivery path at all.
func TestAdmissionDenyNotifyEvent(t *testing.T) {
	org := uuid.New()
	at := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	after := map[string]any{
		"cluster_id": "cluster-abc",
		"rule_id":    "rule-42",
		"reason":     "image not signed",
		"namespace":  "prod",
		"pod":        "web-7",
		"operation":  "CREATE",
		"user":       "system:serviceaccount:prod:deployer",
	}

	ev := admissionDenyNotifyEvent(org, "prod/web-7", after, at)

	if ev.Kind != "admission.deny" {
		t.Fatalf("Kind = %q, want admission.deny (routes to 'admission' receivers + syslog)", ev.Kind)
	}
	if ev.OrgID != org {
		t.Fatalf("OrgID = %v, want %v", ev.OrgID, org)
	}
	if ev.Severity != "high" {
		t.Fatalf("Severity = %q, want high", ev.Severity)
	}
	if ev.Workload != "prod/web-7" {
		t.Fatalf("Workload = %q, want prod/web-7", ev.Workload)
	}
	if ev.Cluster != "cluster-abc" {
		t.Fatalf("Cluster = %q, want cluster-abc", ev.Cluster)
	}
	if !ev.FiredAt.Equal(at) {
		t.Fatalf("FiredAt = %v, want %v", ev.FiredAt, at)
	}
	if ev.Title != "Admission denied: prod/web-7 (image not signed)" {
		t.Fatalf("Title = %q", ev.Title)
	}
	for k, want := range map[string]string{
		"namespace": "prod",
		"pod":       "web-7",
		"rule_id":   "rule-42",
		"operation": "CREATE",
	} {
		if got := ev.Labels[k]; got != want {
			t.Fatalf("Labels[%q] = %q, want %q", k, got, want)
		}
	}
	// Payload must carry the full audit `after` so templates can render extra context.
	if p, ok := ev.Payload.(map[string]any); !ok || p["user"] != "system:serviceaccount:prod:deployer" {
		t.Fatalf("Payload did not preserve the audit after map: %#v", ev.Payload)
	}
}

// TestAdmissionDenyNotifyEventToleratesSparseRow ensures a deny with a nil/partial `after`
// map (e.g. a legacy row) still yields a well-formed event rather than panicking.
func TestAdmissionDenyNotifyEventToleratesSparseRow(t *testing.T) {
	org := uuid.New()
	ev := admissionDenyNotifyEvent(org, "", nil, time.Time{})
	if ev.Kind != "admission.deny" || ev.OrgID != org {
		t.Fatalf("unexpected event for sparse row: %+v", ev)
	}
	if ev.Title != "Admission denied: workload" {
		t.Fatalf("Title = %q, want fallback 'Admission denied: workload'", ev.Title)
	}
	if ev.Labels["namespace"] != "" || ev.Labels["pod"] != "" {
		t.Fatalf("expected empty labels for sparse row, got %v", ev.Labels)
	}
}
