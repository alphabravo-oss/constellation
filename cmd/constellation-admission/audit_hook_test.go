package main

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

func TestAdmissionDenyAuditEvent(t *testing.T) {
	orgID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	clusterID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	event := admissionAuditEvent(orgID, clusterID, admission.DenyEvent{
		RuleID:    "block-privileged",
		Reason:    "container \"debug\" is privileged",
		Namespace: "default",
		Pod:       "debug",
		Operation: "CREATE",
		UserInfo:  "system:serviceaccount:default:deployer",
		EvidenceDetails: []admission.EvidenceDetail{{
			Kind:  "image-finding",
			Label: "CVE-2026-AUDIT",
			Image: admission.EvidenceImageDetail{Container: "app", Ref: "ghcr.io/acme/app@sha256:abc", Digest: "sha256:abc"},
			ScanResult: &admission.EvidenceScanResultDetail{
				ID:                  "33333333-3333-3333-3333-333333333333",
				ImageRef:            "ghcr.io/acme/app@sha256:abc",
				ImageDigest:         "sha256:abc",
				LastScannedAt:       time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC),
				VulnDBBundleVersion: "bundle-20260614",
				VulnDBBundleHash:    "sha256:bundle",
				PackageCount:        8,
				FindingCount:        1,
			},
			Finding: &admission.EvidenceFindingDetail{
				ID:              "44444444-4444-4444-4444-444444444444",
				ExternalID:      "CVE-2026-AUDIT",
				Severity:        "critical",
				CanonicalEngine: "vulndb",
				PackageName:     "openssl",
				PackageVersion:  "3.0.0",
				FixedVersion:    "3.0.2",
			},
		}},
	})

	if event.OrgID == nil || *event.OrgID != orgID {
		t.Fatalf("org id not attached: %+v", event.OrgID)
	}
	if event.Action != "admission.deny" {
		t.Fatalf("action = %s", event.Action)
	}
	if event.TargetKind != "pod" || event.TargetID != "default/debug" {
		t.Fatalf("target = %s/%s", event.TargetKind, event.TargetID)
	}
	after, ok := event.After.(map[string]any)
	if !ok {
		t.Fatalf("after payload type = %T", event.After)
	}
	if after["cluster_id"] != clusterID.String() ||
		after["rule_id"] != "block-privileged" ||
		after["reason"] != "container \"debug\" is privileged" ||
		after["operation"] != "CREATE" ||
		after["user"] != "system:serviceaccount:default:deployer" {
		t.Fatalf("bad after payload: %+v", after)
	}
	details, ok := after["evidence_details"].([]admission.EvidenceDetail)
	if !ok || len(details) != 1 {
		t.Fatalf("missing evidence details: %+v", after["evidence_details"])
	}
	if details[0].Finding == nil || details[0].Finding.ExternalID != "CVE-2026-AUDIT" || details[0].ScanResult == nil || details[0].ScanResult.VulnDBBundleVersion != "bundle-20260614" {
		t.Fatalf("bad evidence details: %+v", details[0])
	}
}

func TestAdmissionMonitorAuditEvent(t *testing.T) {
	orgID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	clusterID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	event := admissionAuditEvent(orgID, clusterID, admission.DenyEvent{
		Monitor:   true,
		RuleID:    "require-image-signature",
		Reason:    "missing constellation image-signed annotation",
		Namespace: "default",
		Pod:       "web",
		Operation: "CREATE",
		UserInfo:  "system:serviceaccount:default:deployer",
	})
	if event.Action != "admission.monitor" {
		t.Fatalf("action = %s, want admission.monitor", event.Action)
	}
	if event.TargetKind != "pod" || event.TargetID != "default/web" {
		t.Fatalf("target = %s/%s", event.TargetKind, event.TargetID)
	}
	after, ok := event.After.(map[string]any)
	if !ok || after["rule_id"] != "require-image-signature" {
		t.Fatalf("bad after payload: %+v", event.After)
	}
}

func TestChainDenyHooks(t *testing.T) {
	var calls []string
	hook := chainDenyHooks(
		func(_ context.Context, ev admission.DenyEvent) { calls = append(calls, "first:"+ev.RuleID) },
		nil,
		func(_ context.Context, ev admission.DenyEvent) { calls = append(calls, "second:"+ev.RuleID) },
	)
	hook(context.Background(), admission.DenyEvent{RuleID: "block-host-network"})
	if len(calls) != 2 || calls[0] != "first:block-host-network" || calls[1] != "second:block-host-network" {
		t.Fatalf("hooks not chained in order: %+v", calls)
	}
}
