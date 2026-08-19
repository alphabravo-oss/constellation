package responserule

import (
	"testing"

	"github.com/google/uuid"
)

func proc(fields map[string]string) *Event {
	return &Event{Type: EventProcess, Fields: fields}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		rule    ResponseRule
		wantErr bool
	}{
		{
			name:    "ok minimal",
			rule:    ResponseRule{Name: "r", EventType: EventProcess, Actions: []Action{{Type: ActionQuarantine}}},
			wantErr: false,
		},
		{
			name:    "missing name",
			rule:    ResponseRule{EventType: EventProcess, Actions: []Action{{Type: ActionQuarantine}}},
			wantErr: true,
		},
		{
			name:    "bad event_type",
			rule:    ResponseRule{Name: "r", EventType: EventType("bogus"), Actions: []Action{{Type: ActionTag}}},
			wantErr: true,
		},
		{
			name:    "no actions",
			rule:    ResponseRule{Name: "r", EventType: EventFile},
			wantErr: true,
		},
		{
			name: "bad op",
			rule: ResponseRule{Name: "r", EventType: EventFile, Actions: []Action{{Type: ActionTag}},
				Conditions: []Condition{{Field: "path", Op: Op("startswith"), Value: "/etc"}}},
			wantErr: true,
		},
		{
			name: "empty field",
			rule: ResponseRule{Name: "r", EventType: EventFile, Actions: []Action{{Type: ActionTag}},
				Conditions: []Condition{{Field: "  ", Op: OpEq, Value: "x"}}},
			wantErr: true,
		},
		{
			name: "bad regex",
			rule: ResponseRule{Name: "r", EventType: EventProcess, Actions: []Action{{Type: ActionTag}},
				Conditions: []Condition{{Field: "process_name", Op: OpRegex, Value: "("}}},
			wantErr: true,
		},
		{
			name: "non-numeric gt",
			rule: ResponseRule{Name: "r", EventType: EventScan, Actions: []Action{{Type: ActionTag}},
				Conditions: []Condition{{Field: "cvss", Op: OpGt, Value: "high"}}},
			wantErr: true,
		},
		{
			name: "bad action type",
			rule: ResponseRule{Name: "r", EventType: EventProcess, Actions: []Action{{Type: ActionType("nuke")}}},
			wantErr: true,
		},
		{
			name: "webhook missing receiver",
			rule: ResponseRule{Name: "r", EventType: EventProcess, Actions: []Action{{Type: ActionWebhook}}},
			wantErr: true,
		},
		{
			name: "webhook with receiver ok",
			rule: ResponseRule{Name: "r", EventType: EventProcess,
				Actions: []Action{{Type: ActionWebhook, Params: map[string]string{"receiver": "sec"}}}},
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rule.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestMatchConditionOps(t *testing.T) {
	ev := proc(map[string]string{"process_name": "/usr/bin/curl", "cvss": "8.5"})
	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"eq hit", Condition{"process_name", OpEq, "/usr/bin/curl"}, true},
		{"eq miss", Condition{"process_name", OpEq, "/bin/sh"}, false},
		{"ne hit", Condition{"process_name", OpNe, "/bin/sh"}, true},
		{"ne miss", Condition{"process_name", OpNe, "/usr/bin/curl"}, false},
		{"contains hit", Condition{"process_name", OpContains, "curl"}, true},
		{"contains miss", Condition{"process_name", OpContains, "wget"}, false},
		{"regex hit", Condition{"process_name", OpRegex, "curl|wget"}, true},
		{"regex miss", Condition{"process_name", OpRegex, "^/bin/"}, false},
		{"gt hit", Condition{"cvss", OpGt, "8.0"}, true},
		{"gt miss", Condition{"cvss", OpGt, "9.0"}, false},
		{"lt hit", Condition{"cvss", OpLt, "9.0"}, true},
		{"lt miss", Condition{"cvss", OpLt, "8.0"}, false},
		{"gt non-numeric field", Condition{"process_name", OpGt, "1"}, false},
		{"missing field eq empty", Condition{"nope", OpEq, ""}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.cond
			if got := matchCondition(&c, ev); got != tc.want {
				t.Fatalf("matchCondition(%+v) = %v, want %v", tc.cond, got, tc.want)
			}
		})
	}
}

func TestMatchEnabledAndEventTypeAndAndSemantics(t *testing.T) {
	base := ResponseRule{
		Name: "r", Enabled: true, EventType: EventProcess,
		Actions: []Action{{Type: ActionQuarantine}},
		Conditions: []Condition{
			{Field: "process_name", Op: OpContains, Value: "curl"},
			{Field: "user", Op: OpEq, Value: "root"},
		},
	}
	ev := proc(map[string]string{"process_name": "/usr/bin/curl", "user": "root"})

	if !base.Match(ev) {
		t.Fatal("all conditions match + enabled + right type: want fire")
	}

	disabled := base
	disabled.Enabled = false
	if disabled.Match(ev) {
		t.Fatal("disabled rule must not fire")
	}

	wrongType := base
	wrongType.EventType = EventFile
	if wrongType.Match(ev) {
		t.Fatal("event_type mismatch must not fire")
	}

	// AND semantics: one condition fails -> no fire.
	evPartial := proc(map[string]string{"process_name": "/usr/bin/curl", "user": "nobody"})
	if base.Match(evPartial) {
		t.Fatal("one failing condition must block the whole rule (AND semantics)")
	}
}

func TestMatchRulesPriorityOrdering(t *testing.T) {
	q := Action{Type: ActionQuarantine}
	s := Action{Type: ActionSuppressLog}
	tag := Action{Type: ActionTag}
	rules := []ResponseRule{
		{Name: "low-priority-300", Enabled: true, Priority: 300, EventType: EventProcess, Actions: []Action{tag}},
		{Name: "high-priority-10", Enabled: true, Priority: 10, EventType: EventProcess, Actions: []Action{q}},
		{Name: "mid-priority-100", Enabled: true, Priority: 100, EventType: EventProcess, Actions: []Action{s}},
		{Name: "disabled", Enabled: false, Priority: 1, EventType: EventProcess, Actions: []Action{q}},
		{Name: "wrong-type", Enabled: true, Priority: 1, EventType: EventFile, Actions: []Action{q}},
	}
	ev := proc(map[string]string{}) // no conditions -> all matching rules of right type fire

	matched := MatchRules(rules, ev)
	if len(matched) != 3 {
		t.Fatalf("want 3 matched rules, got %d", len(matched))
	}
	wantOrder := []string{"high-priority-10", "mid-priority-100", "low-priority-300"}
	for i, w := range wantOrder {
		if matched[i].Name != w {
			t.Fatalf("position %d = %q, want %q", i, matched[i].Name, w)
		}
	}

	// Match (action-only) flattens in priority order.
	actions := Match(rules, ev)
	wantActions := []ActionType{ActionQuarantine, ActionSuppressLog, ActionTag}
	if len(actions) != len(wantActions) {
		t.Fatalf("want %d actions, got %d", len(wantActions), len(actions))
	}
	for i, w := range wantActions {
		if actions[i].Type != w {
			t.Fatalf("action %d = %q, want %q", i, actions[i].Type, w)
		}
	}
}

func TestMatchRulesTieBreakByName(t *testing.T) {
	rules := []ResponseRule{
		{Name: "bravo", Enabled: true, Priority: 50, EventType: EventNetwork, Actions: []Action{{Type: ActionTag}}},
		{Name: "alpha", Enabled: true, Priority: 50, EventType: EventNetwork, Actions: []Action{{Type: ActionTag}}},
	}
	matched := MatchRules(rules, &Event{Type: EventNetwork, Fields: map[string]string{}})
	if len(matched) != 2 || matched[0].Name != "alpha" || matched[1].Name != "bravo" {
		t.Fatalf("equal priority must tie-break by name: %+v", matched)
	}
}

func TestMatchInputUnmodified(t *testing.T) {
	rules := []ResponseRule{
		{Name: "z", Priority: 9, Enabled: true, EventType: EventProcess, Actions: []Action{{Type: ActionTag}}},
		{Name: "a", Priority: 1, Enabled: true, EventType: EventProcess, Actions: []Action{{Type: ActionTag}}},
	}
	_ = MatchRules(rules, proc(map[string]string{}))
	if rules[0].Name != "z" || rules[1].Name != "a" {
		t.Fatal("MatchRules must not reorder the caller's slice")
	}
}

// sanity: ID/OrgID round-trip through the model (used by sync serialization).
func TestRuleCarriesIdentity(t *testing.T) {
	id := uuid.New()
	org := uuid.New()
	r := ResponseRule{ID: id, OrgID: org, Name: "x", EventType: EventScan, Enabled: true,
		Actions: []Action{{Type: ActionTag}}}
	if r.ID != id || r.OrgID != org {
		t.Fatal("identity fields lost")
	}
}
