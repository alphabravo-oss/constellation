package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"sigs.k8s.io/yaml"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

// RT-2: a HIGH/CRITICAL classified event must reach the response-engine hook so
// detection->response is closed-loop; INFO events must not. Pure-logic (no DB):
// drives dispatchResponse via a fake hook.
func TestEventsIngest_DispatchResponseHook(t *testing.T) {
	orgID := uuid.New()
	clusterID := uuid.New()

	var got []response.Event
	h := NewEventsIngest(nil, nil, nil).
		WithResponseEngine(func(_ context.Context, gotOrg, gotCluster uuid.UUID, ev response.Event) {
			if gotOrg != orgID || gotCluster != clusterID {
				t.Fatalf("org/cluster mismatch: %s/%s", gotOrg, gotCluster)
			}
			got = append(got, ev)
		})

	ev := &IngestEvent{Kind: "process_exec", Comm: "nc", WorkloadID: "default/api", Namespace: "default", Pod: "api-1"}
	cls := eventClassification{Severity: "critical", Verdict: "alert", Reason: "suspicious-binary"}
	h.dispatchResponse(context.Background(), orgID, clusterID, ev, cls, []string{"T1059"})

	if len(got) != 1 {
		t.Fatalf("expected 1 response dispatch, got %d", len(got))
	}
	if got[0].Severity != "critical" || got[0].Type != response.EventRuntime {
		t.Fatalf("unexpected response event: %+v", got[0])
	}
	if got[0].Workload != "default/api" || got[0].Cluster != clusterID.String() {
		t.Fatalf("workload/cluster not mapped: %+v", got[0])
	}
	// Reason overrides the bare kind as the rule-matchable Name.
	if got[0].Name != "suspicious-binary" {
		t.Fatalf("expected Name=suspicious-binary, got %q", got[0].Name)
	}

	// Nil hook must be a no-op (no panic).
	NewEventsIngest(nil, nil, nil).WithResponseEngine(nil)
}

// RT-2 end-to-end: a critical runtime event flowing through Bulk fires a response rule
// whose quarantine action records an origin='auto' quarantine_entries row. Auto-skips
// when no DB is reachable.
func TestEventsIngest_AutoQuarantineFromCriticalEvent(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	var clusterID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 ORDER BY created_at LIMIT 1`, orgID).Scan(&clusterID); err != nil {
		t.Skipf("no cluster for org: %v", err)
	}

	workloadID := "rt2-test/" + uuid.New().String()
	tokenName := "rt2-test-" + uuid.New().String()
	ruleName := "rt2-quarantine-" + uuid.New().String()

	// Response rule: any HIGH+ runtime event -> quarantine.
	conds, _ := json.Marshal([]response.Condition{{Type: response.CondLevel, Value: "high"}})
	acts, _ := json.Marshal([]response.Action{{Kind: response.ActionQuarantine}})
	sel, _ := json.Marshal(response.WorkloadSelector{})
	var ruleID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO response_rules_v2 (org_id, cluster_id, name, description, enabled, event_type, conditions, actions, workload_match)
VALUES ($1, $2, $3, '', true, 'runtime', $4, $5, $6) RETURNING id`,
		orgID, clusterID, ruleName, conds, acts, sel).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// nc exec -> suspicious-binary -> high regardless of baseline.
	batch := []IngestEvent{{
		At: time.Now().UTC(), Kind: "process_exec", Node: "node-a",
		WorkloadID: workloadID, Namespace: "rt2-test", Pod: "api-1",
		Comm: "nc", Filename: "/usr/bin/nc",
	}}
	body, _ := json.Marshal(batch)

	bf := func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeEnforce, map[string]struct{}{}, true
	}
	h := NewEventsIngest(d, audit.New(pool), bf).
		WithResponseEngine(NewResponseDispatch(d, nil))

	req := httptest.NewRequest("POST", "/api/v1/events:bulk?cluster_id="+clusterID.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var n int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM quarantine_entries
 WHERE org_id=$1 AND match_key=$2 AND origin='auto'`, orgID, workloadID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 auto quarantine entry, got %d", n)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM quarantine_entries WHERE org_id=$1 AND match_key=$2`, orgID, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM response_rules_v2 WHERE id=$1`, ruleID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_agent_tokens WHERE name=$1`, tokenName)
	})
}

func TestEventsIngest_V2SuppressLogSkipsRuntimeEventRow(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	var clusterID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 ORDER BY created_at LIMIT 1`, orgID).Scan(&clusterID); err != nil {
		t.Skipf("no cluster for org: %v", err)
	}

	workloadID := "v2-suppress/" + uuid.New().String()
	tokenName := "v2-suppress-" + uuid.New().String()
	ruleName := "v2-suppress-" + uuid.New().String()

	conds, _ := json.Marshal([]response.Condition{{Type: response.CondLevel, Value: "high"}})
	acts, _ := json.Marshal([]response.Action{{Kind: response.ActionSuppressLog}})
	sel, _ := json.Marshal(response.WorkloadSelector{})
	var ruleID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO response_rules_v2 (org_id, cluster_id, name, description, enabled, event_type, conditions, actions, workload_match)
VALUES ($1, $2, $3, '', true, 'runtime', $4, $5, $6) RETURNING id`,
		orgID, clusterID, ruleName, conds, acts, sel).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE org_id=$1 AND target_id=$2`, orgID, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM response_rules_v2 WHERE id=$1`, ruleID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_agent_tokens WHERE name=$1`, tokenName)
	})

	batch := []IngestEvent{{
		At: time.Now().UTC(), Kind: "process_exec", Node: "node-a",
		WorkloadID: workloadID, Namespace: "v2-suppress", Pod: "api-1",
		Comm: "nc", Filename: "/usr/bin/nc",
	}}
	body, _ := json.Marshal(batch)
	bf := func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeEnforce, map[string]struct{}{}, true
	}
	h := NewEventsIngest(d, audit.New(pool), bf).
		WithResponseEngine(NewResponseDispatch(d, nil)).
		WithResponseDecision(NewResponseDecision(d))

	req := httptest.NewRequest("POST", "/api/v1/events:bulk?cluster_id="+clusterID.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp IngestResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Accepted != 0 {
		t.Fatalf("accepted=%d want 0 for suppressed event", resp.Accepted)
	}

	var eventRows, alertRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID).Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action LIKE 'runtime.alert.%'`, orgID, workloadID).Scan(&alertRows); err != nil {
		t.Fatal(err)
	}
	if eventRows != 0 || alertRows != 0 {
		t.Fatalf("suppressed event wrote events=%d runtime_alert_audits=%d, want 0/0", eventRows, alertRows)
	}
	var enforced string
	if err := pool.QueryRow(ctx, `
SELECT COALESCE(after->>'enforced','')
  FROM audit_events
 WHERE org_id=$1 AND target_id=$2 AND action='response_rule_v2.action.suppress_log'`,
		orgID, workloadID).Scan(&enforced); err != nil {
		t.Fatalf("expected v2 suppress-log audit row: %v", err)
	}
	if enforced != "suppressed_log" {
		t.Fatalf("v2 suppress-log enforced=%q want suppressed_log", enforced)
	}
}

func TestEventsIngest_V2GroupSelectorUsesCachedMembersAndPodOwnerLinks(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	var clusterID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 ORDER BY created_at LIMIT 1`, orgID).Scan(&clusterID); err != nil {
		t.Skipf("no cluster for org: %v", err)
	}

	suffix := uuid.New().String()
	namespace := "v2-group"
	podName := "api-" + suffix[:8]
	podWorkloadID := namespace + "/pod/" + podName
	ownerWorkloadID := namespace + "/api"
	tokenName := "v2-group-" + suffix
	groupID := uuid.New()
	groupName := "nv.api-" + suffix[:8]
	ruleName := "v2-group-suppress-" + suffix

	if _, err := pool.Exec(ctx, `
INSERT INTO groups (id, org_id, cluster_id, name, kind, criteria, members, policy_mode, profile_mode)
VALUES ($1, $2, $3, $4, 'ground', '[{"key":"namespace","op":"eq","value":"v2-group"}]'::jsonb, $5::jsonb, 'monitor', 'protect')`,
		groupID, orgID, clusterID, groupName, `["`+ownerWorkloadID+`"]`); err != nil {
		t.Fatalf("insert group: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO pod_workload_links (
    org_id, cluster_id, namespace, pod_name, pod_uid, pod_workload_id,
    owner_kind, owner_name, owner_workload_id
) VALUES ($1, $2, $3, $4, $5, $6, 'Deployment', 'api', $7)`,
		orgID, clusterID, namespace, podName, "uid-"+suffix, podWorkloadID, ownerWorkloadID); err != nil {
		t.Fatalf("insert pod owner link: %v", err)
	}

	conds, _ := json.Marshal([]response.Condition{{Type: response.CondLevel, Value: "high"}})
	acts, _ := json.Marshal([]response.Action{{Kind: response.ActionSuppressLog}})
	sel, _ := json.Marshal(response.WorkloadSelector{Group: groupName})
	var ruleID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO response_rules_v2 (org_id, cluster_id, name, description, enabled, event_type, conditions, actions, workload_match)
VALUES ($1, $2, $3, '', true, 'runtime', $4, $5, $6) RETURNING id`,
		orgID, clusterID, ruleName, conds, acts, sel).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE org_id=$1 AND workload_id=$2`, orgID, podWorkloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE org_id=$1 AND target_id=$2`, orgID, podWorkloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM response_rules_v2 WHERE id=$1`, ruleID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM pod_workload_links WHERE org_id=$1 AND pod_workload_id=$2`, orgID, podWorkloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, groupID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_agent_tokens WHERE name=$1`, tokenName)
	})

	batch := []IngestEvent{{
		At: time.Now().UTC(), Kind: "process_exec", Node: "node-a",
		WorkloadID: podWorkloadID, Namespace: namespace, Pod: podName,
		Comm: "nc", Filename: "/usr/bin/nc",
	}}
	body, _ := json.Marshal(batch)
	bf := func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeEnforce, map[string]struct{}{}, true
	}
	h := NewEventsIngest(d, audit.New(pool), bf).
		WithResponseEngine(NewResponseDispatch(d, nil)).
		WithResponseDecision(NewResponseDecision(d))

	req := httptest.NewRequest("POST", "/api/v1/events:bulk?cluster_id="+clusterID.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp IngestResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Accepted != 0 {
		t.Fatalf("accepted=%d want 0 for group-scoped suppressed event", resp.Accepted)
	}
	var suppressRows int
	if err := pool.QueryRow(ctx, `
SELECT count(*)
  FROM audit_events
 WHERE org_id=$1
   AND target_id=$2
   AND action='response_rule_v2.action.suppress_log'
   AND after->>'rule_name'=$3`, orgID, podWorkloadID, ruleName).Scan(&suppressRows); err != nil {
		t.Fatal(err)
	}
	if suppressRows != 1 {
		t.Fatalf("suppress audit rows=%d want 1", suppressRows)
	}
}

// RT-3: Isolate of a running workload must enqueue a default-deny NetworkPolicy as an
// applier-actionable lifecycle row (current_mode='protect', approval_status='applied',
// native manifest with both policy types and no allow rules), provenance-linked to the
// quarantine entry. Quarantine (the image/admission deny primitive) must NOT enqueue one.
// Auto-skips when no DB is reachable.
func TestQuarantineRuntime_IsolateEnqueuesDenyAll(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var orgID, clusterID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 ORDER BY created_at LIMIT 1`, orgID).Scan(&clusterID); err != nil {
		t.Skipf("no cluster for org: %v", err)
	}

	isolateWorkload := "rt3-isolate-ns/rt3-iso-" + uuid.New().String()
	quarWorkload := "rt3-quar-ns/rt3-quar-" + uuid.New().String()

	t.Cleanup(func() {
		for _, wl := range []string{isolateWorkload, quarWorkload} {
			_, _ = pool.Exec(context.Background(), `DELETE FROM network_policy_lifecycle_states WHERE org_id=$1 AND workload=$2`, orgID, wl)
			_, _ = pool.Exec(context.Background(), `DELETE FROM quarantine_entries WHERE org_id=$1 AND match_key=$2`, orgID, wl)
		}
	})

	q := &quarantineRuntime{db: d, orgID: orgID, clusterID: clusterID}

	// Quarantine records the entry but enqueues NO cordon.
	if err := q.Quarantine(ctx, quarWorkload, "image admission deny"); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	var quarRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM network_policy_lifecycle_states WHERE org_id=$1 AND workload=$2`, orgID, quarWorkload).Scan(&quarRows); err != nil {
		t.Fatal(err)
	}
	if quarRows != 0 {
		t.Fatalf("Quarantine must NOT enqueue a netpolicy; got %d lifecycle rows", quarRows)
	}

	// Isolate records the entry AND enqueues the deny-all cordon.
	if err := q.Isolate(ctx, isolateWorkload, "lateral movement detected"); err != nil {
		t.Fatalf("Isolate: %v", err)
	}

	var entryID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM quarantine_entries WHERE org_id=$1 AND match_key=$2 AND origin='auto'`, orgID, isolateWorkload).Scan(&entryID); err != nil {
		t.Fatalf("expected auto quarantine entry: %v", err)
	}

	var currentMode, approval, reason, manifestsRaw string
	if err := pool.QueryRow(ctx, `
SELECT current_mode, approval_status, reason, preview_manifests::text
  FROM network_policy_lifecycle_states
 WHERE org_id=$1 AND cluster_id=$2 AND workload=$3`,
		orgID, clusterID, isolateWorkload).Scan(&currentMode, &approval, &reason, &manifestsRaw); err != nil {
		t.Fatalf("expected lifecycle row for isolate: %v", err)
	}
	if currentMode != "protect" || approval != "applied" {
		t.Fatalf("row not applier-actionable: current_mode=%q approval=%q (want protect/applied)", currentMode, approval)
	}
	if !strings.Contains(reason, entryID.String()) {
		t.Fatalf("reason missing quarantine entry provenance %q: %q", entryID.String(), reason)
	}

	var manifests map[string]string
	if err := json.Unmarshal([]byte(manifestsRaw), &manifests); err != nil {
		t.Fatalf("preview_manifests not JSON: %v", err)
	}
	nativeYAML := strings.TrimSpace(manifests["native"])
	if nativeYAML == "" {
		t.Fatalf("expected native manifest, got %v", manifests)
	}

	var np struct {
		Kind string `json:"kind"`
		Spec struct {
			PodSelector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"podSelector"`
			PolicyTypes []string `json:"policyTypes"`
			Ingress     []any    `json:"ingress"`
			Egress      []any    `json:"egress"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal([]byte(nativeYAML), &np); err != nil {
		t.Fatalf("native manifest not valid YAML: %v\n%s", err, nativeYAML)
	}
	if np.Kind != "NetworkPolicy" {
		t.Fatalf("kind=%q, want NetworkPolicy", np.Kind)
	}
	// podSelector must target the workload name (last segment of the key).
	if got := np.Spec.PodSelector.MatchLabels["app"]; got != lastWorkloadSegment(isolateWorkload) {
		t.Fatalf("podSelector app label=%q, want %q", got, lastWorkloadSegment(isolateWorkload))
	}
	var ing, egr bool
	for _, pt := range np.Spec.PolicyTypes {
		if pt == "Ingress" {
			ing = true
		}
		if pt == "Egress" {
			egr = true
		}
	}
	if !ing || !egr {
		t.Fatalf("policyTypes=%v, want both Ingress and Egress", np.Spec.PolicyTypes)
	}
	if len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 {
		t.Fatalf("deny-all must have no allow rules; ingress=%d egress=%d", len(np.Spec.Ingress), len(np.Spec.Egress))
	}
}

func lastWorkloadSegment(key string) string {
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		return key[i+1:]
	}
	return key
}
