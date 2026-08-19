package waf

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

func mkHTTP(method, path, query string, headers map[string][]string) dpi.L7Event {
	if headers == nil {
		headers = map[string][]string{}
	}
	return dpi.L7Event{
		Protocol: "http", Dir: dpi.DirRequest,
		HTTP: &dpi.HTTPEvent{
			Method: method, Path: path, Query: query, Headers: headers,
		},
	}
}

func TestSQLi(t *testing.T) {
	e := NewEngine()
	if err := e.AddSensor(BuiltinCRS()); err != nil {
		t.Fatalf("AddSensor: %v", err)
	}
	e.SetMode("default/app", baseline.ModeEnforce)
	v := e.Evaluate("default/app", mkHTTP("GET", "/users", "id=1+UNION+SELECT+password+FROM+users", nil))
	if v.Action != "block" {
		t.Fatalf("expected block, got %s (matches=%+v)", v.Action, v.Matches)
	}
	found := false
	for _, m := range v.Matches {
		if m.RuleID == 942100 {
			found = true
		}
	}
	if !found {
		t.Fatalf("942100 didn't fire: %+v", v.Matches)
	}
}

func TestXSS(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinCRS())
	e.SetMode("default/app", baseline.ModeEnforce)
	v := e.Evaluate("default/app", mkHTTP("GET", "/search", "q=%3Cscript%3Ealert(1)%3C/script%3E", nil))
	if v.Action != "block" {
		t.Fatalf("expected block, got %s", v.Action)
	}
}

func TestPathTraversal(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinCRS())
	e.SetMode("default/app", baseline.ModeEnforce)
	v := e.Evaluate("default/app", mkHTTP("GET", "/files/../../etc/passwd", "", nil))
	if v.Action != "block" {
		t.Fatalf("expected block, got %s", v.Action)
	}
}

func TestCmdInjection(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinCRS())
	e.SetMode("default/app", baseline.ModeEnforce)
	v := e.Evaluate("default/app", mkHTTP("GET", "/run", "cmd=foo;cat+/etc/passwd", nil))
	if v.Action != "block" {
		t.Fatalf("expected block, got %s", v.Action)
	}
}

func TestSuspiciousUA(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinCRS())
	e.SetMode("default/app", baseline.ModeEnforce)
	v := e.Evaluate("default/app", mkHTTP("GET", "/", "", map[string][]string{
		"user-agent": {"sqlmap/1.6"},
	}))
	if v.Action != "alert" {
		t.Fatalf("expected alert (block deferred), got %s", v.Action)
	}
}

func TestLearnModeSilent(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinCRS())
	e.SetMode("default/app", baseline.ModeLearn)
	v := e.Evaluate("default/app", mkHTTP("GET", "/x", "q=' OR '1'='1", nil))
	if v.Action != "allow" || len(v.Matches) != 0 {
		t.Fatalf("learn mode leaked: %+v", v)
	}
}

func TestMonitorAlerts(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinCRS())
	e.SetMode("default/app", baseline.ModeMonitor)
	v := e.Evaluate("default/app", mkHTTP("GET", "/x", "id=' UNION SELECT 1", nil))
	if v.Action != "alert" {
		t.Fatalf("monitor should alert, got %s", v.Action)
	}
}

func TestUnknownOperatorRejected(t *testing.T) {
	e := NewEngine()
	err := e.AddSensor(Sensor{
		Name: "bad",
		Rules: []Rule{{ID: 1, Operator: Operator{Type: "nope", Value: "x"}, Target: "ARGS"}},
	})
	if err == nil {
		t.Fatal("expected error for unknown operator")
	}
}

func TestCleanRequestAllowed(t *testing.T) {
	e := NewEngine()
	_ = e.AddSensor(BuiltinCRS())
	e.SetMode("default/app", baseline.ModeEnforce)
	v := e.Evaluate("default/app", mkHTTP("GET", "/health", "", nil))
	if v.Action != "allow" || len(v.Matches) != 0 {
		t.Fatalf("clean request shouldn't match: %+v", v)
	}
}
