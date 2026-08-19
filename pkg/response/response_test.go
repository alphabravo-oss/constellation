package response

import (
	"context"
	"errors"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/notify"
)

type fakeReceiver struct {
	name string
	got  []notify.Alert
	err  error
}

func (s *fakeReceiver) Name() string { return s.name }
func (s *fakeReceiver) Send(_ context.Context, a []notify.Alert) error {
	s.got = append(s.got, a...)
	return s.err
}

type fakeRuntime struct {
	quarantined []string
	isolated    []string
	err         error
}

func (s *fakeRuntime) Quarantine(_ context.Context, w, _ string) error {
	s.quarantined = append(s.quarantined, w)
	return s.err
}
func (s *fakeRuntime) Isolate(_ context.Context, w, _ string) error {
	s.isolated = append(s.isolated, w)
	return s.err
}

func TestRule_Match_NameAndLevel(t *testing.T) {
	r := Rule{
		Enabled:   true,
		EventType: EventRuntime,
		Conditions: []Condition{
			{Type: CondName, Value: "^shell-spawned$"},
			{Type: CondLevel, Value: "high"},
		},
	}
	ev := &Event{Name: "shell-spawned", Type: EventRuntime, Severity: "critical"}
	if !r.Match(ev) {
		t.Fatal("expected match for shell-spawned critical")
	}
	ev2 := &Event{Name: "shell-spawned", Type: EventRuntime, Severity: "low"}
	if r.Match(ev2) {
		t.Fatal("expected no match below severity threshold")
	}
}

func TestRule_Match_CVECritical(t *testing.T) {
	r := Rule{
		Enabled:    true,
		EventType:  EventScan,
		Conditions: []Condition{{Type: CondCVECritical, Value: "9.0"}},
	}
	ev := &Event{Type: EventScan, CVEs: []CVERef{{ID: "CVE-1", Severity: "critical", BaseScore: 9.8}}}
	if !r.Match(ev) {
		t.Fatal("expected match for critical CVE >= 9.0")
	}
	ev2 := &Event{Type: EventScan, CVEs: []CVERef{{ID: "CVE-2", Severity: "high", BaseScore: 9.8}}}
	if r.Match(ev2) {
		t.Fatal("expected no match: severity not critical")
	}
}

func TestRule_Match_SelectorAndProc(t *testing.T) {
	r := Rule{
		Enabled:   true,
		EventType: EventRuntime,
		Conditions: []Condition{
			{Type: CondProc, Value: "^(bash|sh)$"},
		},
		Selector: WorkloadSelector{Namespace: "payments", Labels: map[string]string{"env": "prod"}},
	}
	ev := &Event{Type: EventRuntime, Namespace: "payments", Labels: map[string]string{"env": "prod"}, ProcessName: "bash"}
	if !r.Match(ev) {
		t.Fatal("expected match for bash in payments/prod")
	}
	ev.Namespace = "dev"
	if r.Match(ev) {
		t.Fatal("expected no match outside selector")
	}
}

func TestEngine_Dispatch_NotifyAndQuarantine(t *testing.T) {
	slack := &fakeReceiver{name: "slack"}
	rt := &fakeRuntime{}
	eng := NewEngine(map[string]notify.Receiver{"slack": slack}, rt, nil)
	eng.SetRules([]Rule{{
		ID: "r1", Name: "shell", Enabled: true, EventType: EventRuntime,
		Conditions: []Condition{{Type: CondName, Value: ".*"}},
		Actions: []Action{
			{Kind: ActionNotify, Target: "slack"},
			{Kind: ActionQuarantine},
		},
	}})
	got := eng.Dispatch(context.Background(), &Event{ID: "e1", Name: "x", Type: EventRuntime, Workload: "w1", Severity: "high"})
	if len(got) != 1 || len(got[0].Actions) != 2 {
		t.Fatalf("expected 2 actions fired, got %+v", got)
	}
	if len(slack.got) != 1 {
		t.Fatalf("expected slack to receive 1 alert")
	}
	if len(rt.quarantined) != 1 {
		t.Fatalf("expected runtime quarantine to fire")
	}
}

func TestEngine_Dispatch_RuntimeMissing(t *testing.T) {
	eng := NewEngine(nil, nil, nil)
	eng.SetRules([]Rule{{
		ID: "r1", Name: "iso", Enabled: true, EventType: EventRuntime,
		Conditions: []Condition{{Type: CondName, Value: ".*"}},
		Actions:    []Action{{Kind: ActionIsolate}},
	}})
	got := eng.Dispatch(context.Background(), &Event{ID: "e1", Name: "x", Type: EventRuntime})
	if len(got) != 1 || len(got[0].Warnings) == 0 {
		t.Fatalf("expected warning about missing runtime bridge; got %+v", got)
	}
}

func TestRule_Validate(t *testing.T) {
	cases := []struct {
		r    Rule
		want bool // want error
	}{
		{Rule{Name: "", EventType: EventRuntime}, true},
		{Rule{Name: "n", EventType: "bogus"}, true},
		{Rule{Name: "n", EventType: EventRuntime, Conditions: []Condition{{Type: CondName, Value: "[bad"}}}, true},
		{Rule{Name: "n", EventType: EventRuntime, Actions: []Action{{Kind: "wat"}}}, true},
		{Rule{Name: "ok", EventType: EventRuntime, Conditions: []Condition{{Type: CondName, Value: ".*"}}, Actions: []Action{{Kind: ActionNotify, Target: "slack"}}}, false},
	}
	for i, c := range cases {
		err := c.r.Validate()
		if (err != nil) != c.want {
			t.Errorf("case %d: gotErr=%v want=%v", i, err, c.want)
		}
	}
	_ = errors.New
}
