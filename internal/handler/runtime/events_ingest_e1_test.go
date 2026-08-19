package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/responserule"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

// TestEventsIngest_E1RuleFiresOnIngest is the end-to-end regression for the E1-high
// finding: a declarative response rule must FIRE on a matching runtime event ingested
// through /events:bulk and execute its actions IN PRIORITY ORDER, with webhook actions
// dispatched. Previously ResponseRuleDefs.Evaluate had no production caller; this asserts
// the live ingest path now drives it.
func TestEventsIngest_E1RuleFiresOnIngest(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	workloadID := "e1-ingest/" + uuid.New().String()
	tokenName := "e1-ingest-" + uuid.New().String()

	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// A matching shell exec in an enforce-mode workload -> HIGH, which triggers E1 evaluation.
	batch := []IngestEvent{
		{
			At:         time.Now().UTC(),
			Kind:       "process_exec",
			Node:       "node-a",
			WorkloadID: workloadID,
			Namespace:  "e1-ingest",
			Pod:        "api-xyz",
			PID:        4321, PPID: 1, UID: 0,
			Comm:     "sh",
			Filename: "/bin/sh",
		},
	}
	body, _ := json.Marshal(batch)

	// Enforce mode, nothing baselined -> the shell exec promotes to HIGH.
	bf := func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeEnforce, map[string]struct{}{}, true
	}

	// Two enabled matching rules at different priorities (p10 quarantine, p50 webhook) so we
	// can assert ordered execution, plus a webhook-fired flag. This evaluator mirrors the
	// production ResponseRuleDefs.Evaluate (MatchRules in priority order; webhook side effect).
	rules := []responserule.ResponseRule{
		{OrgID: orgID, Name: "p50-webhook", Enabled: true, Priority: 50, EventType: responserule.EventProcess,
			Actions: []responserule.Action{{Type: responserule.ActionWebhook, Params: map[string]string{"receiver": "sec"}}}},
		{OrgID: orgID, Name: "p10-quarantine", Enabled: true, Priority: 10, EventType: responserule.EventProcess,
			Conditions: []responserule.Condition{{Field: "process_name", Op: responserule.OpContains, Value: "sh"}},
			Actions:    []responserule.Action{{Type: responserule.ActionQuarantine}}},
		{OrgID: orgID, Name: "disabled", Enabled: false, Priority: 1, EventType: responserule.EventProcess,
			Actions: []responserule.Action{{Type: responserule.ActionTag}}},
	}

	var (
		mu          sync.Mutex
		gotEvents   []*responserule.Event
		webhookHits int
	)
	eval := func(_ context.Context, _ uuid.UUID, ev *responserule.Event) ([]responserule.Action, error) {
		mu.Lock()
		defer mu.Unlock()
		gotEvents = append(gotEvents, ev)
		matched := responserule.MatchRules(rules, ev)
		var out []responserule.Action
		for i := range matched {
			for _, a := range matched[i].Actions {
				out = append(out, a)
				if a.Type == responserule.ActionWebhook {
					webhookHits++ // production fires the dispatcher here
				}
			}
		}
		return out, nil
	}

	h := NewEventsIngest(d, audit.New(pool), bf).WithResponseRuleEngine(eval)

	req := httptest.NewRequest("POST", "/api/v1/events:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	// The evaluator was invoked exactly once for the HIGH event, mapped to event_type=process.
	if len(gotEvents) != 1 {
		t.Fatalf("E1 evaluator invocations=%d, want 1", len(gotEvents))
	}
	if gotEvents[0].Type != responserule.EventProcess {
		t.Fatalf("mapped event type=%q, want process", gotEvents[0].Type)
	}
	if gotEvents[0].Fields["process_name"] != "sh" || gotEvents[0].Fields["severity"] != "high" {
		t.Fatalf("mapped fields=%+v, want process_name=sh severity=high", gotEvents[0].Fields)
	}
	// Webhook action fired.
	if webhookHits != 1 {
		t.Fatalf("webhook dispatches=%d, want 1", webhookHits)
	}

	// The applied actions were audit-logged IN PRIORITY ORDER (quarantine at order 0 from the
	// p10 rule, webhook at order 1 from the p50 rule).
	rows, err := pool.Query(ctx, `
SELECT after->>'action', (after->>'order')::int
  FROM audit_events
 WHERE org_id=$1 AND target_id=$2 AND action LIKE 'response_rule.action.%'
 ORDER BY (after->>'order')::int`, orgID, workloadID)
	if err != nil {
		t.Fatalf("query applied actions: %v", err)
	}
	defer rows.Close()
	type applied struct {
		action string
		order  int
	}
	var got []applied
	for rows.Next() {
		var a applied
		if err := rows.Scan(&a.action, &a.order); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, a)
	}
	want := []applied{{"quarantine", 0}, {"webhook", 1}}
	if len(got) != len(want) {
		t.Fatalf("applied actions=%+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("applied[%d]=%+v, want %+v (full=%+v)", i, got[i], want[i], got)
		}
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_agent_tokens WHERE name = $1`, tokenName)
	})
}

// TestEventsIngest_E1SuppressLog is the regression for the suppress_log half-wired finding:
// a matching suppress_log response rule must actually suppress the side-effects it claims to —
// the events row AND the runtime.alert.* audit row are NOT written — while still recording the
// suppression itself (a response_rule.action.suppress_log audit row) so it is observable, and
// while still enforcing any co-located quarantine action. Previously suppress_log fired AFTER
// those rows were already committed, so it suppressed nothing.
func TestEventsIngest_E1SuppressLog(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	workloadID := "e1-suppress/" + uuid.New().String()
	tokenName := "e1-suppress-" + uuid.New().String()

	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE org_id=$1 AND target_id=$2`, orgID, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_agent_tokens WHERE name=$1`, tokenName)
	})

	batch := []IngestEvent{{
		At:         time.Now().UTC(),
		Kind:       "process_exec",
		Node:       "node-a",
		WorkloadID: workloadID,
		Namespace:  "e1-suppress",
		Pod:        "api-xyz",
		PID:        4321, PPID: 1, UID: 0,
		Comm:     "sh",
		Filename: "/bin/sh",
	}}
	body, _ := json.Marshal(batch)

	// Enforce mode, nothing baselined -> the shell exec promotes to HIGH.
	bf := func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeEnforce, map[string]struct{}{}, true
	}

	// A single enabled rule with a suppress_log action that matches every process event.
	eval := func(_ context.Context, _ uuid.UUID, _ *responserule.Event) ([]responserule.Action, error) {
		return []responserule.Action{{Type: responserule.ActionSuppressLog}}, nil
	}

	h := NewEventsIngest(d, audit.New(pool), bf).WithResponseRuleEngine(eval)

	req := httptest.NewRequest("POST", "/api/v1/events:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp IngestResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	// The suppressed event was not stored, so Accepted reflects 0 rows inserted.
	if resp.Accepted != 0 {
		t.Errorf("Accepted=%d want 0 (event suppressed)", resp.Accepted)
	}

	// No events row was written for the suppressed detection.
	var eventCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM events WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID).Scan(&eventCount); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if eventCount != 0 {
		t.Errorf("events rows=%d want 0 (suppress_log must skip the events insert)", eventCount)
	}

	// No runtime.alert.* audit row was written.
	var alertCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action LIKE 'runtime.alert.%'`, orgID, workloadID).Scan(&alertCount); err != nil {
		t.Fatalf("count alert audit: %v", err)
	}
	if alertCount != 0 {
		t.Errorf("runtime.alert audit rows=%d want 0 (suppress_log must skip the alert)", alertCount)
	}

	// The suppression IS recorded as a response_rule.action.suppress_log audit row with an
	// explicit enforced outcome, so the action is never a silent no-op.
	var enforced string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(after->>'enforced','') FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='response_rule.action.suppress_log'`, orgID, workloadID).Scan(&enforced); err != nil {
		t.Fatalf("expected a response_rule.action.suppress_log audit row: %v", err)
	}
	if enforced != "suppressed_log" {
		t.Errorf("suppress_log audit enforced=%q want suppressed_log", enforced)
	}
}
