package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/admission"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/responserule"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func admissionAuditTestDB(t *testing.T) (context.Context, *pgxpool.Pool, uuid.UUID, uuid.UUID) {
	t.Helper()
	databaseURL := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Skipf("test DB unavailable: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("test DB unavailable: %v", err)
	}
	orgID, clusterID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Admission Audit Test')`, orgID, "admission-audit-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID); err != nil {
			t.Errorf("remove test org: %v", err)
		}
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'admission-audit-test')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, orgID, clusterID
}

func TestAdmissionResponseRuleLegacyTagIsUnsupported(t *testing.T) {
	ctx, pool, orgID, clusterID := admissionAuditTestDB(t)
	pod := "legacy-tag-" + uuid.NewString()
	deny := admission.DenyEvent{Namespace: "default", Pod: pod}
	event := &responserule.Event{Type: responserule.EventAdmission, Fields: map[string]string{"namespace": "default", "pod": pod, "workload_id": "default/" + pod}}
	if err := applyAdmissionResponseRuleAction(ctx, pool, audit.New(pool), orgID, clusterID, deny, event,
		responserule.Action{Type: responserule.ActionTag, Params: map[string]string{"key": "team", "value": "sec"}}, 0, nil); err != nil {
		t.Fatal(err)
	}
	var enforced, reason string
	if err := pool.QueryRow(ctx, `SELECT after->>'enforced', after->>'enforce_error' FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='response_rule.action.tag'`, orgID, "default/"+pod).Scan(&enforced, &reason); err != nil {
		t.Fatal(err)
	}
	if enforced != "unsupported" || reason == "" {
		t.Fatalf("legacy tag outcome=%q reason=%q", enforced, reason)
	}
}

func TestAdmissionSuppressLogAuditHook(t *testing.T) {
	tests := []struct {
		name             string
		conditions       []responserule.Condition
		actions          []responserule.Action
		badRow           bool
		addValidSuppress bool
		monitor          bool
		wantDeny         int
		wantMonitor      int
		wantActions      int
	}{
		{
			name:        "matched suppress with quarantine",
			conditions:  []responserule.Condition{{Field: "namespace", Op: responserule.OpEq, Value: "default"}},
			actions:     []responserule.Action{{Type: responserule.ActionSuppressLog}, {Type: responserule.ActionQuarantine}},
			wantActions: 2,
		},
		{
			name:       "unmatched suppress",
			conditions: []responserule.Condition{{Field: "namespace", Op: responserule.OpEq, Value: "other"}},
			actions:    []responserule.Action{{Type: responserule.ActionSuppressLog}},
			wantDeny:   1,
		},
		{name: "no response rules", wantDeny: 1},
		{name: "monitor match", actions: []responserule.Action{{Type: responserule.ActionSuppressLog}}, monitor: true, wantMonitor: 1},
		{name: "malformed response rule", badRow: true, addValidSuppress: true, wantDeny: 1},
		{
			name:             "invalid regex",
			conditions:       []responserule.Condition{{Field: "namespace", Op: responserule.OpRegex, Value: "["}},
			actions:          []responserule.Action{{Type: responserule.ActionSuppressLog}},
			addValidSuppress: true,
			wantDeny:         1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pool, orgID, clusterID := admissionAuditTestDB(t)
			if tc.actions != nil || tc.badRow {
				conditions, err := json.Marshal(tc.conditions)
				if err != nil {
					t.Fatal(err)
				}
				actions, err := json.Marshal(tc.actions)
				if err != nil {
					t.Fatal(err)
				}
				if tc.badRow {
					conditions = []byte(`{}`)
					actions = []byte(`[{"type":"suppress_log"}]`)
				}
				if _, err := pool.Exec(ctx, `INSERT INTO response_rules (org_id, name, event_type, conditions, actions) VALUES ($1, 'admission-suppress-test', 'admission', $2, $3)`, orgID, conditions, actions); err != nil {
					t.Fatal(err)
				}
			}
			if tc.addValidSuppress {
				if _, err := pool.Exec(ctx, `INSERT INTO response_rules (org_id, name, event_type, conditions, actions) VALUES ($1, 'valid-suppress', 'admission', '[]', '[{"type":"suppress_log"}]')`, orgID); err != nil {
					t.Fatal(err)
				}
			}
			pod := "audit-" + uuid.NewString()
			hook, gotOrgID, err := newAdmissionAuditHook(ctx, pool, clusterID, nil)
			if err != nil {
				t.Fatal(err)
			}
			if gotOrgID != orgID {
				t.Fatalf("org = %s, want %s", gotOrgID, orgID)
			}
			hook(ctx, admission.DenyEvent{Namespace: "default", Pod: pod, RuleID: "block-test", Monitor: tc.monitor})
			var denyCount, monitorCount, actionCount int
			if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='admission.deny'), count(*) FILTER (WHERE action='admission.monitor'), count(*) FILTER (WHERE action LIKE 'response_rule.action.%') FROM audit_events WHERE org_id=$1 AND target_id=$2`, orgID, "default/"+pod).Scan(&denyCount, &monitorCount, &actionCount); err != nil {
				t.Fatal(err)
			}
			if denyCount != tc.wantDeny || monitorCount != tc.wantMonitor || actionCount != tc.wantActions {
				t.Fatalf("audit counts deny=%d monitor=%d actions=%d; want %d, %d, %d", denyCount, monitorCount, actionCount, tc.wantDeny, tc.wantMonitor, tc.wantActions)
			}
			if tc.wantActions > 0 {
				var enforced string
				if err := pool.QueryRow(ctx, `SELECT after->>'enforced' FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='response_rule.action.suppress_log'`, orgID, "default/"+pod).Scan(&enforced); err != nil {
					t.Fatal(err)
				}
				if enforced != "suppressed_log" {
					t.Fatalf("suppress_log outcome = %q", enforced)
				}
				var quarantineCount int
				if err := pool.QueryRow(ctx, `SELECT count(*) FROM quarantine_entries WHERE org_id=$1 AND cluster_id=$2 AND match_key=$3`, orgID, clusterID, "default/"+pod).Scan(&quarantineCount); err != nil {
					t.Fatal(err)
				}
				if quarantineCount != 1 {
					t.Fatalf("quarantine entries = %d, want 1", quarantineCount)
				}
			}
		})
	}
}

func TestAdmissionSuppressLogPreservesDenial(t *testing.T) {
	ctx, pool, orgID, clusterID := admissionAuditTestDB(t)
	if _, err := pool.Exec(ctx, `INSERT INTO response_rules (org_id, name, event_type, conditions, actions) VALUES ($1, 'suppress-deny', 'admission', '[]', '[{"type":"suppress_log"}]')`, orgID); err != nil {
		t.Fatal(err)
	}
	hook, _, err := newAdmissionAuditHook(ctx, pool, clusterID, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := admission.NewEngine()
	engine.OnDeny = hook
	privileged := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "blocked-" + uuid.NewString(), Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "alpine:3.18",
			SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
		}}},
	}
	podJSON, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	response := engine.Evaluate(ctx, &admissionv1.AdmissionRequest{
		Kind:   metav1.GroupVersionKind{Kind: "Pod"},
		Object: runtime.RawExtension{Raw: podJSON},
	})
	if response.Allowed || response.Result == nil {
		t.Fatalf("privileged pod was not denied: %+v", response)
	}
	var denyCount, suppressionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='admission.deny'), count(*) FILTER (WHERE action='response_rule.action.suppress_log') FROM audit_events WHERE org_id=$1 AND target_id=$2`, orgID, "default/"+pod.Name).Scan(&denyCount, &suppressionCount); err != nil {
		t.Fatal(err)
	}
	if denyCount != 0 || suppressionCount != 1 {
		t.Fatalf("deny audit rows=%d suppression action rows=%d, want 0 and 1", denyCount, suppressionCount)
	}
}

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
