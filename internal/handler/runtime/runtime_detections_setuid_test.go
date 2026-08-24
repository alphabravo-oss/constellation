package runtime

import (
	"testing"

	"github.com/google/uuid"
)

// TestSetuidWithoutExec is the RT-SETUID-49 server-side detection: a uid_change event
// where a process escalated its effective UID to root from a non-root UID (with no
// exec — the agent's UID monitor only emits this kind for that case) is a privilege
// escalation; anything else is not.
func TestSetuidWithoutExec(t *testing.T) {
	cases := []struct {
		name string
		ev   *IngestEvent
		want bool
	}{
		{"escalation to root", &IngestEvent{Kind: "uid_change", UID: 0, PrevUID: 1000}, true},
		{"no change stays root", &IngestEvent{Kind: "uid_change", UID: 0, PrevUID: 0}, false},
		{"drop privileges", &IngestEvent{Kind: "uid_change", UID: 1000, PrevUID: 0}, false},
		{"non-root to non-root", &IngestEvent{Kind: "uid_change", UID: 33, PrevUID: 1000}, false},
		{"wrong kind ignored", &IngestEvent{Kind: "process_exec", UID: 0, PrevUID: 1000}, false},
		{"nil safe", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := setuidWithoutExec(c.ev); got != c.want {
				t.Fatalf("setuidWithoutExec()=%v want %v", got, c.want)
			}
		})
	}
}

// TestClassifyEventSetuid confirms a uid_change escalation classifies as a high-severity
// privilege-escalation alert through the full classifier entry point.
func TestClassifyEventSetuid(t *testing.T) {
	h := &EventsIngest{}
	cls := h.classifyEvent(uuid.Nil, uuid.Nil, &IngestEvent{Kind: "uid_change", UID: 0, PrevUID: 1000}, &fileProfileRuleSet{}, false)
	if cls.Severity != "high" || cls.Verdict != "alert" {
		t.Fatalf("uid_change escalation: got (%s,%s) want (high,alert)", cls.Severity, cls.Verdict)
	}
	if cls.Reason != "setuid-without-exec" {
		t.Fatalf("reason = %q want setuid-without-exec", cls.Reason)
	}
	if len(cls.Techniques) == 0 {
		t.Fatalf("expected ATT&CK privilege-escalation techniques")
	}
}
