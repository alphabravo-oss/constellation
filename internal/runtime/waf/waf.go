// Package waf implements the Constellation Web Application Firewall rule engine.
//
// Rule format (ModSecurity CRS-flavored, simplified):
//
//	Sensor:      ruleset + group bundle, e.g. {Name: "owasp-crs", Predefined: true}
//	Rule: {
//	  ID: 942100, Msg: "SQL Injection Attempt",
//	  Phase: "request", Severity: "critical",
//	  Transformations: [lowercase, urlDecode],
//	  Target: "ARGS"  | "REQUEST_URI" | "REQUEST_HEADERS:User-Agent" | "REQUEST_BODY",
//	  Operator: {Type: "rx", Value: "(?i)\\bunion.+select\\b"},
//	  Action:   "block"|"alert",
//	}
//
// Engine.Evaluate takes a dpi.L7Event (HTTP-flavored) and a workload mode (from
// pkg/runtime/baseline) and returns a Verdict. Modes:
//
//	learn    no alerts, no blocks
//	monitor  alerts, never blocks
//	enforce  alerts + blocks
//
// On the NFQUEUE path, the caller maps Verdict.Action to NfDrop / NfAccept. Tests use
// the same engine through an in-memory event source.
package waf

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

// Severity mirrors the ModSecurity scale.
type Severity string

const (
	SevInfo     Severity = "info"
	SevNotice   Severity = "notice"
	SevWarning  Severity = "warning"
	SevError    Severity = "error"
	SevCritical Severity = "critical"
)

// MatchExpr is the runtime-compiled operator used by the L7 engine.
type MatchExpr struct {
	Type  string // "rx" | "contains" | "streq" | "beginsWith" | "endsWith"
	Value string

	rx *regexp.Regexp
}

// Operator is a readable alias for MatchExpr used when constructing rules.
type Operator = MatchExpr

// Rule is one WAF rule (compiled). Distinct from the Wave D wire-format WafRule:
// this type carries a compiled regex and a runtime Action; the Wave D type is the
// JSON-serialisable form. Use Compile() to convert between them.
type Rule struct {
	ID              int
	Msg             string
	Phase           string   // "request" | "response"
	Severity        Severity
	Transformations []string // "lowercase" | "urlDecode" | "trim" | "removeWhitespace"
	Target          string   // see package comment
	Operator        MatchExpr
	Tags            []string
	Action          string   // "block" | "alert"
}

// CfgType mirrors the NeuVector sensor library shape: federal, predefined, user.
type CfgType string

const (
	CfgFederal    CfgType = "federal"
	CfgPredefined CfgType = "predefined"
	CfgUser       CfgType = "user"
)

// Sensor is a named bundle of rules. Multiple sensors compose at evaluation time.
type Sensor struct {
	Name    string
	Group   string
	Type    CfgType
	Comment string
	Rules   []Rule
}

// Verdict is the decision the engine returns for one request.
type Verdict struct {
	Action   string // "allow" | "alert" | "block"
	Matches  []Match
	Mode     baseline.Mode
}

// Match is one rule fire.
type Match struct {
	RuleID   int
	Msg      string
	Severity Severity
	Target   string
	Captured string // first 80 chars of the matched substring
}

// Engine is the compiled rule set + mode-per-workload registry.
type Engine struct {
	mu      sync.RWMutex
	sensors map[string]Sensor // by name
	modes   map[string]baseline.Mode
}

// NewEngine builds an empty engine. Call AddSensor + SetMode to populate.
func NewEngine() *Engine {
	return &Engine{
		sensors: map[string]Sensor{},
		modes:   map[string]baseline.Mode{},
	}
}

// AddSensor registers a sensor. Returns an error if the sensor contains an invalid
// operator (e.g. a malformed regex).
func (e *Engine) AddSensor(s Sensor) error {
	for i := range s.Rules {
		if err := compileRule(&s.Rules[i]); err != nil {
			return fmt.Errorf("waf: sensor %q rule %d: %w", s.Name, s.Rules[i].ID, err)
		}
	}
	e.mu.Lock()
	e.sensors[s.Name] = s
	e.mu.Unlock()
	return nil
}

// RemoveSensor deletes a sensor by name. No-op if missing.
func (e *Engine) RemoveSensor(name string) {
	e.mu.Lock()
	delete(e.sensors, name)
	e.mu.Unlock()
}

// SetMode binds a workload to a baseline mode.
func (e *Engine) SetMode(workload string, mode baseline.Mode) {
	e.mu.Lock()
	e.modes[workload] = mode
	e.mu.Unlock()
}

// Sensors returns a snapshot of sensors in name order — useful for the UI.
func (e *Engine) Sensors() []Sensor {
	e.mu.RLock()
	out := make([]Sensor, 0, len(e.sensors))
	for _, s := range e.sensors {
		out = append(out, s)
	}
	e.mu.RUnlock()
	// Predefined first, then alphabetical (mirrors NeuVector ordering).
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return rank(out[i].Type) < rank(out[j].Type)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func rank(t CfgType) int {
	switch t {
	case CfgFederal:
		return 0
	case CfgPredefined:
		return 1
	default:
		return 2
	}
}

// Evaluate runs every sensor's rules against the HTTP event. Returns a Verdict.
// Block is only set if Mode==enforce and any rule has Action=="block".
func (e *Engine) Evaluate(workload string, evt dpi.L7Event) Verdict {
	if evt.HTTP == nil {
		return Verdict{Action: "allow"}
	}
	e.mu.RLock()
	mode := e.modes[workload]
	if mode == "" {
		mode = baseline.ModeMonitor
	}
	sensors := make([]Sensor, 0, len(e.sensors))
	for _, s := range e.sensors {
		sensors = append(sensors, s)
	}
	e.mu.RUnlock()

	verdict := Verdict{Action: "allow", Mode: mode}
	for _, s := range sensors {
		for _, r := range s.Rules {
			match, ok := evalRule(r, evt)
			if !ok {
				continue
			}
			verdict.Matches = append(verdict.Matches, match)
		}
	}
	if len(verdict.Matches) == 0 {
		return verdict
	}
	switch mode {
	case baseline.ModeLearn:
		// Don't even surface the match in learn mode.
		return Verdict{Action: "allow", Mode: mode}
	case baseline.ModeMonitor:
		verdict.Action = "alert"
	case baseline.ModeEnforce:
		blocked := false
		for _, m := range verdict.Matches {
			if findRuleAction(sensors, m.RuleID) == "block" {
				blocked = true
				break
			}
		}
		if blocked {
			verdict.Action = "block"
		} else {
			verdict.Action = "alert"
		}
	}
	return verdict
}

func findRuleAction(sensors []Sensor, id int) string {
	for _, s := range sensors {
		for _, r := range s.Rules {
			if r.ID == id {
				return r.Action
			}
		}
	}
	return "alert"
}

func compileRule(r *Rule) error {
	switch r.Operator.Type {
	case "rx":
		rx, err := regexp.Compile(r.Operator.Value)
		if err != nil {
			return fmt.Errorf("compile regex: %w", err)
		}
		r.Operator.rx = rx
	case "contains", "streq", "beginsWith", "endsWith":
		// nothing to compile
	default:
		return fmt.Errorf("unknown operator: %q", r.Operator.Type)
	}
	if r.Action == "" {
		r.Action = "alert"
	}
	return nil
}

// evalRule runs one rule against an HTTP event.
func evalRule(r Rule, evt dpi.L7Event) (Match, bool) {
	subjects := targetValues(r.Target, evt)
	for _, raw := range subjects {
		v := applyTransforms(r.Transformations, raw)
		if matches(r.Operator, v) {
			capt := raw
			if len(capt) > 80 {
				capt = capt[:80]
			}
			return Match{
				RuleID:   r.ID,
				Msg:      r.Msg,
				Severity: r.Severity,
				Target:   r.Target,
				Captured: capt,
			}, true
		}
	}
	return Match{}, false
}

// targetValues returns every concrete string that should be matched against `target`.
// "ARGS" expands to every query-arg value; REQUEST_HEADERS:Name to that header's values.
func targetValues(target string, evt dpi.L7Event) []string {
	switch target {
	case "REQUEST_URI":
		return []string{evt.HTTP.Path + "?" + evt.HTTP.Query}
	case "REQUEST_LINE":
		return []string{evt.HTTP.Method + " " + evt.HTTP.Path + "?" + evt.HTTP.Query}
	case "ARGS":
		vals, err := url.ParseQuery(evt.HTTP.Query)
		if err != nil {
			return nil
		}
		out := []string{}
		for _, vs := range vals {
			out = append(out, vs...)
		}
		return out
	case "ARGS_NAMES":
		vals, err := url.ParseQuery(evt.HTTP.Query)
		if err != nil {
			return nil
		}
		out := []string{}
		for k := range vals {
			out = append(out, k)
		}
		return out
	case "REQUEST_HEADERS":
		out := []string{}
		for _, vs := range evt.HTTP.Headers {
			out = append(out, vs...)
		}
		return out
	case "REQUEST_BODY":
		return []string{string(evt.HTTP.Body)}
	case "REQUEST_METHOD":
		return []string{evt.HTTP.Method}
	}
	if strings.HasPrefix(target, "REQUEST_HEADERS:") {
		name := strings.ToLower(strings.TrimPrefix(target, "REQUEST_HEADERS:"))
		return evt.HTTP.Headers[name]
	}
	if strings.HasPrefix(target, "ARGS:") {
		name := strings.TrimPrefix(target, "ARGS:")
		vals, err := url.ParseQuery(evt.HTTP.Query)
		if err != nil {
			return nil
		}
		return vals[name]
	}
	return nil
}

func applyTransforms(ts []string, s string) string {
	for _, t := range ts {
		switch t {
		case "lowercase":
			s = strings.ToLower(s)
		case "trim":
			s = strings.TrimSpace(s)
		case "urlDecode":
			if dec, err := url.QueryUnescape(s); err == nil {
				s = dec
			}
		case "removeWhitespace":
			s = strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
					return -1
				}
				return r
			}, s)
		}
	}
	return s
}

func matches(op MatchExpr, s string) bool {
	switch op.Type {
	case "rx":
		return op.rx != nil && op.rx.MatchString(s)
	case "contains":
		return strings.Contains(s, op.Value)
	case "streq":
		return s == op.Value
	case "beginsWith":
		return strings.HasPrefix(s, op.Value)
	case "endsWith":
		return strings.HasSuffix(s, op.Value)
	}
	return false
}

// ErrUnknownOperator is returned by AddSensor when a rule's operator is unrecognized.
var ErrUnknownOperator = errors.New("waf: unknown operator")
