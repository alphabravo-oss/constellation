package dlp

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

func mkHTTP(body string) dpi.L7Event {
	return dpi.L7Event{
		Protocol: "http", Dir: dpi.DirRequest,
		HTTP: &dpi.HTTPEvent{
			Method: "POST", Path: "/api", Headers: map[string][]string{},
			Body: []byte(body),
		},
	}
}

func TestCreditCardLuhn(t *testing.T) {
	e := NewEngine()
	if err := e.AddSensor(BuiltinSensor()); err != nil {
		t.Fatalf("AddSensor: %v", err)
	}
	e.SetMode("default/app", baseline.ModeEnforce)
	// 4111 1111 1111 1111 is Visa test number, Luhn-valid.
	v := e.Inspect("default/app", mkHTTP(`{"card":"4111-1111-1111-1111"}`))
	if v.Action != "block" {
		t.Fatalf("expected block, got %s (matches=%+v)", v.Action, v.Matches)
	}

	// Non-Luhn 16-digit string must NOT match.
	v = e.Inspect("default/app", mkHTTP(`{"card":"1234-5678-9012-3456"}`))
	for _, m := range v.Matches {
		if m.PatternID == 1001 {
			t.Fatalf("luhn allowed garbage: %+v", m)
		}
	}
}

func TestSSN(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinSensor())
	e.SetMode("w", baseline.ModeEnforce)
	v := e.Inspect("w", mkHTTP(`{"ssn":"123-45-6789"}`))
	if v.Action != "block" {
		t.Fatalf("expected block, got %s", v.Action)
	}
}

func TestAWSAccessKey(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinSensor())
	e.SetMode("w", baseline.ModeEnforce)
	v := e.Inspect("w", mkHTTP("AKIAIOSFODNN7EXAMPLE"))
	if v.Action != "block" {
		t.Fatalf("expected block, got %s", v.Action)
	}
}

func TestGitHubPAT(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinSensor())
	e.SetMode("w", baseline.ModeEnforce)
	v := e.Inspect("w", mkHTTP("token=ghp_1234567890abcdefghijklmnopqrstuvwxyz"))
	if v.Action != "block" {
		t.Fatalf("expected block, got %s", v.Action)
	}
}

func TestSlackToken(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinSensor())
	e.SetMode("w", baseline.ModeEnforce)
	v := e.Inspect("w", mkHTTP("xoxb-1234567890-12345-abcdefghij"))
	if v.Action != "block" {
		t.Fatalf("expected block, got %s (%+v)", v.Action, v.Matches)
	}
}

func TestBearerHeader(t *testing.T) {
	evt := dpi.L7Event{
		Protocol: "http", Dir: dpi.DirRequest,
		HTTP: &dpi.HTTPEvent{
			Method: "GET", Path: "/", Headers: map[string][]string{
				"authorization": {"Bearer abcdefghijklmnopqrstuvwxyz1234"},
			},
		},
	}
	e := NewEngine()
	_ = e.AddSensor(BuiltinSensor())
	e.SetMode("w", baseline.ModeMonitor)
	v := e.Inspect("w", evt)
	if v.Action != "alert" {
		t.Fatalf("expected alert, got %s (%+v)", v.Action, v.Matches)
	}
}

func TestLearnModeSilent(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinSensor())
	e.SetMode("w", baseline.ModeLearn)
	v := e.Inspect("w", mkHTTP("4111-1111-1111-1111"))
	if v.Action != "allow" || len(v.Matches) != 0 {
		t.Fatalf("learn leaked: %+v", v)
	}
}

func TestSQLQueryLeak(t *testing.T) {
	evt := dpi.L7Event{
		Protocol: "postgres", Dir: dpi.DirRequest,
		Postgres: &dpi.PostgresEvent{
			Command: "query",
			Query:   "INSERT INTO logs (data) VALUES ('user 4111-1111-1111-1111')",
		},
	}
	e := NewEngine()
	_ = e.AddSensor(BuiltinSensor())
	e.SetMode("w", baseline.ModeEnforce)
	v := e.Inspect("w", evt)
	if v.Action != "block" {
		t.Fatalf("expected block on PG query leak, got %s", v.Action)
	}
}

func TestRedact(t *testing.T) {
	if got := redact("4111111111111111"); got != "4111…1111" {
		t.Fatalf("redact = %q", got)
	}
	if got := redact("short"); got != "****" {
		t.Fatalf("redact short = %q", got)
	}
}

func TestLuhnValid(t *testing.T) {
	cases := map[string]bool{
		"4111111111111111": true,
		"5500000000000004": true,
		"1234567890123456": false,
		"":                 false,
	}
	for in, want := range cases {
		if got := luhnValid(in); got != want {
			t.Errorf("luhnValid(%q)=%v want %v", in, got, want)
		}
	}
}

func TestIBAN(t *testing.T) {
	// GB82 WEST 1234 5698 7654 32 is a documented sample.
	if !looksLikeIBAN("GB82WEST12345698765432") {
		t.Errorf("valid IBAN rejected")
	}
	if looksLikeIBAN("GB99NOPE00000000000000") {
		t.Errorf("invalid IBAN accepted")
	}
}
