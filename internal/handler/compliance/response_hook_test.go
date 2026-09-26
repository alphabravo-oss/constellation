package compliance

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// captureReceiver records the alerts delivered to it so the test can assert a
// response rule actually fired on a folded compliance failure.
type captureReceiver struct {
	name  string
	sent  []notify.Alert
	calls int
}

func TestLegacyTagOutcomeOnComplianceAndHostCIS(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "legacy-tag-compliance-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID) })

	for _, source := range []string{"compliance", "host_cis"} {
		t.Run(source, func(t *testing.T) {
			for _, suppressed := range []bool{false, true} {
				name := "unsuppressed"
				if suppressed {
					name = "suppressed"
				}
				t.Run(name, func(t *testing.T) {
					checkID := "legacy-tag-" + uuid.NewString()
					responded := 0
					notifyCalls := 0
					dispatcher := notify.NewDispatcher(pool, notify.DispatcherConfig{
						SyslogTarget: func(context.Context, uuid.UUID) (*notify.Syslog, bool) {
							notifyCalls++
							return nil, false
						},
					})
					respond := func(_ context.Context, _, _ uuid.UUID, _ response.Event) { responded++ }
					eval := func(_ context.Context, _ uuid.UUID, ev *responserule.Event) ([]responserule.Action, error) {
						if ev.Type != responserule.EventCompliance || ev.Fields["check_id"] != checkID {
							t.Fatalf("unexpected rule event: %+v", ev)
						}
						actions := []responserule.Action{{Type: responserule.ActionTag, Params: map[string]string{"key": "team", "value": "sec"}}}
						if suppressed {
							actions = append([]responserule.Action{{Type: responserule.ActionSuppressLog}}, actions...)
						}
						return actions, nil
					}
					var alerts complianceResponder
					switch source {
					case "compliance":
						alerts = NewCompliance(database, audit.New(pool)).WithResponseAlerts(respond, eval, dispatcher).alerts
					case "host_cis":
						alerts = NewHostCIS(database).WithResponseAlerts(respond, eval, dispatcher).alerts
					}
					alerts.fire(ctx, orgID, uuid.Nil, []complianceFailure{{CheckID: checkID, Framework: source, Severity: "high"}})
					wantNotify := 1
					if suppressed {
						wantNotify = 0
					}
					if responded != 1 || notifyCalls != wantNotify {
						t.Fatalf("RT-2 response calls=%d notify calls=%d, want 1/%d", responded, notifyCalls, wantNotify)
					}
					var enforced, reason, key, value string
					var order int
					if err := pool.QueryRow(ctx, `
SELECT after->>'enforced', after->>'enforce_error', after->>'param_key', after->>'param_value', (after->>'order')::int
  FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='response_rule.action.tag'`, orgID, checkID).
						Scan(&enforced, &reason, &key, &value, &order); err != nil {
						t.Fatalf("query tag outcome: %v", err)
					}
					wantOrder := 0
					if suppressed {
						wantOrder = 1
					}
					if enforced != "unsupported" || reason == "" || key != "team" || value != "sec" || order != wantOrder {
						t.Fatalf("tag outcome=(%q,%q,%q,%q,%d), want unsupported with reason, params and order %d", enforced, reason, key, value, order, wantOrder)
					}
				})
			}
		})
	}
}

func (r *captureReceiver) Name() string { return r.name }
func (r *captureReceiver) Send(_ context.Context, alerts []notify.Alert) error {
	r.calls++
	r.sent = append(r.sent, alerts...)
	return nil
}

// TestComplianceFailureFiresResponseRule proves the RT-2 loop: a failed control folds
// to a response.Event{Type: EventCompliance} that a NeuVector-style response rule
// (event_type=compliance, name regex, level threshold) matches and dispatches to a
// receiver. Before P1-16 no code ever constructed such an event, so this fold + the
// EventCompliance-typed rule path did not exist.
func TestComplianceFailureFiresResponseRule(t *testing.T) {
	f := complianceFailure{
		CheckID:   "1.2.22",
		Title:     "Ensure audit policy file is set",
		Framework: "cis-k8s",
		Severity:  "high",
	}
	ev := f.responseEvent(uuid.Nil)
	if ev.Type != response.EventCompliance {
		t.Fatalf("event type = %q, want %q", ev.Type, response.EventCompliance)
	}
	if ev.Name != "1.2.22" {
		t.Fatalf("event name = %q, want the check id", ev.Name)
	}

	recv := &captureReceiver{name: "sec-webhook"}
	eng := response.NewEngine(map[string]notify.Receiver{"sec-webhook": recv}, nil, nil)
	eng.SetRules([]response.Rule{{
		ID:      "r1",
		Name:    "alert on failed CIS controls",
		Enabled: true,
		// A rule scoped to compliance events with a level floor — only matches
		// because responseEvent tags Type=EventCompliance with a real severity.
		EventType: response.EventCompliance,
		Conditions: []response.Condition{
			{Type: response.CondEventType, Value: "compliance"},
			{Type: response.CondLevel, Value: "high"},
		},
		Actions: []response.Action{{Kind: response.ActionNotify, Target: "sec-webhook"}},
	}})

	dispatched := eng.Dispatch(context.Background(), &ev)
	if len(dispatched) != 1 {
		t.Fatalf("dispatched %d rules, want 1", len(dispatched))
	}
	if recv.calls != 1 || len(recv.sent) != 1 {
		t.Fatalf("receiver got %d calls / %d alerts, want 1/1", recv.calls, len(recv.sent))
	}
	if recv.sent[0].Kind != string(response.EventCompliance) {
		t.Fatalf("alert kind = %q, want compliance", recv.sent[0].Kind)
	}
}

// TestComplianceRuleEventMatchesE1 proves the E1 declarative side: event_type=compliance
// is now a valid rule type and a failed control's ruleEvent() carries the fields
// (check_id/level/node) an operator's rule can match on. Before P1-16, Validate rejected
// event_type=compliance and MatchRules never saw a compliance event.
func TestComplianceRuleEventMatchesE1(t *testing.T) {
	rule := responserule.ResponseRule{
		ID:        uuid.New(),
		Name:      "webhook on failed node control",
		Enabled:   true,
		EventType: responserule.EventCompliance,
		Conditions: []responserule.Condition{
			{Field: "check_id", Op: responserule.OpEq, Value: "1.2.22"},
			{Field: "level", Op: responserule.OpEq, Value: "high"},
		},
		Actions: []responserule.Action{{Type: responserule.ActionWebhook, Params: map[string]string{"receiver": "sec"}}},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("compliance rule should validate, got %v", err)
	}

	f := complianceFailure{CheckID: "1.2.22", Title: "audit policy", Node: "node-a", Severity: "high"}
	matched := responserule.MatchRules([]responserule.ResponseRule{rule}, f.ruleEvent())
	if len(matched) != 1 {
		t.Fatalf("MatchRules matched %d rules, want 1", len(matched))
	}
}

func TestComplianceFailureSeverityDefault(t *testing.T) {
	if got := (complianceFailure{}).severity(); got != "high" {
		t.Fatalf("empty severity = %q, want high", got)
	}
	if got := (complianceFailure{Severity: "bogus"}).severity(); got != "high" {
		t.Fatalf("invalid severity = %q, want high fallback", got)
	}
	if got := (complianceFailure{Severity: "low"}).severity(); got != "low" {
		t.Fatalf("valid severity = %q, want low passthrough", got)
	}
}

// TestFireSuppressLogGatesNotify verifies the E1 suppress_log action stops the notify
// fan-out (and its syslog mirror) while the RT-2 respond hook still runs — matching the
// runtime events-ingest semantics.
func TestFireSuppressLogGatesNotify(t *testing.T) {
	var responded int
	cr := complianceResponder{
		respond: func(_ context.Context, _, _ uuid.UUID, _ response.Event) { responded++ },
		evalRules: func(_ context.Context, _ uuid.UUID, _ *responserule.Event) ([]responserule.Action, error) {
			return []responserule.Action{{Type: responserule.ActionSuppressLog}}, nil
		},
		// dispatcher nil: if fire tried to dispatch it would be a no-op anyway, so we
		// assert on the suppress decision via actionsSuppressLog directly below.
	}
	cr.fire(context.Background(), uuid.New(), uuid.Nil, []complianceFailure{{CheckID: "x", Severity: "high"}})
	if responded != 1 {
		t.Fatalf("RT-2 respond hook fired %d times, want 1 (independent of suppress_log)", responded)
	}
	if !actionsSuppressLog([]responserule.Action{{Type: responserule.ActionSuppressLog}}) {
		t.Fatal("actionsSuppressLog should report true for a suppress_log action")
	}
	if actionsSuppressLog([]responserule.Action{{Type: responserule.ActionWebhook}}) {
		t.Fatal("actionsSuppressLog should report false without a suppress_log action")
	}
}
