// Package dlp implements the Data Loss Prevention rule engine. Mirrors WAF in shape:
//
//	Sensor (federal | predefined | user) ──► Pattern (compiled regex + validator)
//	Engine.Inspect(workload, evt) returns Verdict{allow|alert|block, []Match}
//
// The validator step is what distinguishes "looks like a credit card" from "actually a
// credit card": Luhn for CC#, ABN check digit for AWS keys, SSN area-group bounds, etc.
// All patterns + validators are pluggable; the BuiltinSensor() factory ships a
// reasonable starter pack (CCs, US SSNs, common cloud-provider API keys).
package dlp

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

// CfgType, CfgFederal/Predefined/User live in store.go (Wave D wire types).
// We re-use them here so the runtime engine and the persisted catalog share a vocab.

// Severity copies the ModSecurity scale so DLP findings line up with WAF in the UI.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevError    Severity = "error"
	SevCritical Severity = "critical"
)

// Pattern is one DLP signature.
type Pattern struct {
	ID       int
	Msg      string
	Severity Severity
	// Regex is the PCRE-flavoured pattern. Compiled lazily on Sensor add.
	Regex string
	// Validator is an optional post-match check (e.g. Luhn for CC numbers). When nil
	// the regex match alone fires the rule.
	Validator func(captured string) bool
	// Targets enumerates the dpi.L7Event fields to inspect. Same vocabulary as the
	// WAF Rule.Target: REQUEST_URI, ARGS, REQUEST_BODY, REQUEST_HEADERS, RESPONSE_BODY.
	Targets []string
	// Action: "block" | "alert".
	Action string
	rx     *regexp.Regexp
}

// Sensor is a named pattern bundle.
type Sensor struct {
	Name     string
	Group    string
	Type     CfgType
	Comment  string
	Patterns []Pattern
}

// Match is one DLP hit.
type Match struct {
	PatternID int
	Msg       string
	Severity  Severity
	Target    string
	Sample    string // redacted preview (first/last 4 chars + masked middle)
}

// Verdict is the engine output.
type Verdict struct {
	Action  string // allow | alert | block
	Matches []Match
	Mode    baseline.Mode
}

// Engine is the DLP rule engine — analogous to waf.Engine but DLP-flavored.
type Engine struct {
	mu      sync.RWMutex
	sensors map[string]Sensor
	modes   map[string]baseline.Mode
}

// NewEngine builds an empty DLP engine.
func NewEngine() *Engine {
	return &Engine{
		sensors: map[string]Sensor{},
		modes:   map[string]baseline.Mode{},
	}
}

// AddSensor compiles + registers a sensor.
func (e *Engine) AddSensor(s Sensor) error {
	for i := range s.Patterns {
		rx, err := regexp.Compile(s.Patterns[i].Regex)
		if err != nil {
			return fmt.Errorf("dlp: sensor %q pattern %d: %w", s.Name, s.Patterns[i].ID, err)
		}
		s.Patterns[i].rx = rx
		if s.Patterns[i].Action == "" {
			s.Patterns[i].Action = "alert"
		}
	}
	e.mu.Lock()
	e.sensors[s.Name] = s
	e.mu.Unlock()
	return nil
}

// SetMode binds a workload to a baseline mode.
func (e *Engine) SetMode(workload string, m baseline.Mode) {
	e.mu.Lock()
	e.modes[workload] = m
	e.mu.Unlock()
}

// Sensors returns the registered sensors in (Type, Name) order.
func (e *Engine) Sensors() []Sensor {
	e.mu.RLock()
	out := make([]Sensor, 0, len(e.sensors))
	for _, s := range e.sensors {
		out = append(out, s)
	}
	e.mu.RUnlock()
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

// Inspect runs every registered sensor's patterns against the event. For HTTP events
// it inspects URI, query args, headers, and body; for SQL events (MySQL/Postgres) it
// inspects the query string; for Redis it inspects the joined args. The verdict
// composes with mode the same way as waf.
func (e *Engine) Inspect(workload string, evt dpi.L7Event) Verdict {
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
		for _, p := range s.Patterns {
			for _, t := range p.Targets {
				for _, raw := range targetValues(t, evt) {
					if m := matchPattern(p, t, raw); m != nil {
						verdict.Matches = append(verdict.Matches, *m)
					}
				}
			}
		}
	}
	if len(verdict.Matches) == 0 {
		return verdict
	}
	switch mode {
	case baseline.ModeLearn:
		return Verdict{Action: "allow", Mode: mode}
	case baseline.ModeMonitor:
		verdict.Action = "alert"
	case baseline.ModeEnforce:
		blocked := false
		for _, m := range verdict.Matches {
			for _, s := range sensors {
				for _, p := range s.Patterns {
					if p.ID == m.PatternID && p.Action == "block" {
						blocked = true
					}
				}
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

func matchPattern(p Pattern, target, raw string) *Match {
	if p.rx == nil {
		return nil
	}
	hits := p.rx.FindAllString(raw, -1)
	for _, h := range hits {
		if p.Validator != nil && !p.Validator(h) {
			continue
		}
		return &Match{
			PatternID: p.ID,
			Msg:       p.Msg,
			Severity:  p.Severity,
			Target:    target,
			Sample:    redact(h),
		}
	}
	return nil
}

// redact masks a captured string for safe logging.
func redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

func targetValues(target string, evt dpi.L7Event) []string {
	if evt.HTTP != nil {
		switch target {
		case "REQUEST_URI":
			return []string{evt.HTTP.Path + "?" + evt.HTTP.Query}
		case "ARGS":
			return []string{evt.HTTP.Query}
		case "REQUEST_HEADERS":
			out := []string{}
			for _, vs := range evt.HTTP.Headers {
				out = append(out, vs...)
			}
			return out
		case "REQUEST_BODY":
			return []string{string(evt.HTTP.Body)}
		}
	}
	if evt.MySQL != nil && target == "QUERY" {
		return []string{evt.MySQL.Query}
	}
	if evt.Postgres != nil && target == "QUERY" {
		return []string{evt.Postgres.Query}
	}
	if evt.Redis != nil && target == "REDIS_ARGS" {
		return evt.Redis.Args
	}
	if evt.DNS != nil && target == "DNS_NAME" {
		return []string{evt.DNS.QName}
	}
	return nil
}

// ErrInvalidPattern is returned by AddSensor when a pattern's regex doesn't compile.
var ErrInvalidPattern = errors.New("dlp: invalid pattern")
