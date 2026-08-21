// Package response implements the NeuVector-style response rule condition catalog
// and engine that maps fired Findings / RuntimeEvents to notification or runtime
// actions (slack/jira/etc. or quarantine / netpolicy isolate).
//
// Conditions mirror NeuVector's EventCond* discriminators:
//
//	CondName        — event name regex
//	CondLevel       — severity threshold (info < low < medium < high < critical)
//	CondCVECritical — CVE criticality + score floor (matches when event carries CVEs)
//	CondProc        — process name pattern (regex)
//	CondEventType   — admission|runtime|scan|compliance
//
// A WorkloadSelector adds optional cluster / namespace / labels narrowing.
//
// The engine is intentionally storage-agnostic; rules are passed in by the API layer
// (which loads them from the response_rules_v2 table). This keeps the package
// trivially unit-testable and reusable from the runtime + admission webhooks.
package response

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/alphabravocompany/constellation/pkg/notify"
)

// CondType is the discriminator for a Condition.
type CondType string

const (
	CondName        CondType = "name"         // event name regex
	CondLevel       CondType = "level"        // severity threshold
	CondCVECritical CondType = "cve_critical" // CVE criticality + score floor
	CondProc        CondType = "proc"         // process name pattern
	CondEventType   CondType = "event_type"   // admission|runtime|scan|compliance

	// Count-based CVE conditions (RSP-CVE-52) mirror NeuVector's vulnerability
	// count/age gates. Value is an integer N; the condition matches when the
	// event carries at least N qualifying CVEs (or, for the age gate, a fixable
	// CVE older than N days).
	CondCVECriticalCount CondType = "cve_critical_count" // >= N critical CVEs
	CondCVEHighCount     CondType = "cve_high_count"     // >= N high-or-above CVEs
	CondCVEWithFixCount  CondType = "cve_with_fix_count" // >= N CVEs with a fix available
	CondCVEMaxAgeDays    CondType = "cve_max_age_days"   // a fixable CVE older than N days
)

// EventType is the canonical event category.
type EventType string

const (
	EventAdmission  EventType = "admission"
	EventRuntime    EventType = "runtime"
	EventScan       EventType = "scan"
	EventCompliance EventType = "compliance"
)

// Severity ordering (lowest → highest).
var severityRank = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Condition is one match clause on a fired event.
type Condition struct {
	Type  CondType `json:"type"`
	Op    string   `json:"op,omitempty"` // optional comparator (>=, ==, regex, contains)
	Value string   `json:"value"`        // RHS — regex for name/proc, severity for level, score for cve
}

// ActionKind is the kind of effect a rule produces when it fires.
type ActionKind string

const (
	ActionNotify     ActionKind = "notify"     // dispatch via pkg/notify
	ActionQuarantine ActionKind = "quarantine" // runtime quarantine (Wave A data plane)
	ActionIsolate    ActionKind = "isolate"    // network policy isolate
	ActionKill       ActionKind = "kill"       // sever a live process/session (RT-KILL-02 responder)
	ActionTicket     ActionKind = "ticket"     // create ITSM ticket (alias for notify w/ Jira/SNOW)
)

// Action is a structured response action.
type Action struct {
	Kind   ActionKind        `json:"kind"`
	Target string            `json:"target,omitempty"` // e.g. slack receiver name
	Params map[string]string `json:"params,omitempty"`
}

// WorkloadSelector narrows a rule to a subset of workloads.
type WorkloadSelector struct {
	Cluster   string            `json:"cluster,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Rule is a NeuVector-style response rule.
type Rule struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Enabled    bool             `json:"enabled"`
	EventType  EventType        `json:"event_type"`
	Conditions []Condition      `json:"conditions"`
	Actions    []Action         `json:"actions"`
	Selector   WorkloadSelector `json:"workload_match"`
}

// Event is the normalized event that the engine matches against. Constellation's
// Finding and RuntimeEvent both fold down to this shape at the alert router.
type Event struct {
	ID          string
	Name        string
	Type        EventType
	Severity    string
	Cluster     string
	Namespace   string
	Workload    string
	Labels      map[string]string
	ProcessName string
	CVEs        []CVERef
	Title       string
	URL         string
}

// CVERef is a CVE reference attached to an Event.
type CVERef struct {
	ID        string  // CVE-2024-1234
	Severity  string  // info|low|medium|high|critical
	BaseScore float64 // CVSS base score
	Fixed     bool    // a fix (patched version) is available
	AgeDays   int     // days since the CVE was published/disclosed (0 = unknown)
}

// Match returns true if every condition + the selector matches the event.
func (r *Rule) Match(ev *Event) bool {
	if !r.Enabled {
		return false
	}
	if string(r.EventType) != "" && r.EventType != "*" && r.EventType != ev.Type {
		return false
	}
	if !matchSelector(&r.Selector, ev) {
		return false
	}
	for _, c := range r.Conditions {
		if !matchCondition(&c, ev) {
			return false
		}
	}
	return true
}

func matchSelector(s *WorkloadSelector, ev *Event) bool {
	if s.Cluster != "" && s.Cluster != ev.Cluster {
		return false
	}
	if s.Namespace != "" && s.Namespace != ev.Namespace {
		return false
	}
	for k, v := range s.Labels {
		if ev.Labels[k] != v {
			return false
		}
	}
	return true
}

func matchCondition(c *Condition, ev *Event) bool {
	switch c.Type {
	case CondName:
		return regexMatch(c.Value, ev.Name) || regexMatch(c.Value, ev.Title)
	case CondLevel:
		threshold := severityRank[strings.ToLower(c.Value)]
		got := severityRank[strings.ToLower(ev.Severity)]
		return got >= threshold
	case CondCVECritical:
		floor := parseFloat(c.Value)
		for _, cv := range ev.CVEs {
			if severityRank[strings.ToLower(cv.Severity)] >= severityRank["critical"] && cv.BaseScore >= floor {
				return true
			}
		}
		return false
	case CondCVECriticalCount:
		return countCVEsAtLeast(ev, "critical") >= parseInt(c.Value)
	case CondCVEHighCount:
		return countCVEsAtLeast(ev, "high") >= parseInt(c.Value)
	case CondCVEWithFixCount:
		n := 0
		for _, cv := range ev.CVEs {
			if cv.Fixed {
				n++
			}
		}
		return n >= parseInt(c.Value)
	case CondCVEMaxAgeDays:
		maxAge := parseInt(c.Value)
		for _, cv := range ev.CVEs {
			// A fixable CVE left unpatched beyond the window is the risk NeuVector's
			// age gate targets — an available fix that has not been applied in N days.
			if cv.Fixed && cv.AgeDays > maxAge {
				return true
			}
		}
		return false
	case CondProc:
		return regexMatch(c.Value, ev.ProcessName)
	case CondEventType:
		return strings.EqualFold(c.Value, string(ev.Type))
	}
	return false
}

// countCVEsAtLeast returns the number of the event's CVEs whose severity is at
// least minSeverity (using the shared severity ranking).
func countCVEsAtLeast(ev *Event, minSeverity string) int {
	floor := severityRank[minSeverity]
	n := 0
	for _, cv := range ev.CVEs {
		if severityRank[strings.ToLower(cv.Severity)] >= floor {
			n++
		}
	}
	return n
}

func regexMatch(pattern, s string) bool {
	if pattern == "" {
		return false
	}
	re, err := compileCached(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func parseFloat(s string) float64 {
	var f float64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%f", &f); err != nil {
		return 0
	}
	return f
}

func parseInt(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// ----------------------------- regex cache -----------------------------------

var (
	regexCache   = map[string]*regexp.Regexp{}
	regexCacheMu sync.RWMutex
)

func compileCached(pattern string) (*regexp.Regexp, error) {
	regexCacheMu.RLock()
	if re, ok := regexCache[pattern]; ok {
		regexCacheMu.RUnlock()
		return re, nil
	}
	regexCacheMu.RUnlock()
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("response: compile regex %q: %w", pattern, err)
	}
	regexCacheMu.Lock()
	regexCache[pattern] = re
	regexCacheMu.Unlock()
	return re, nil
}

// ----------------------------- Engine ----------------------------------------

// Runtime is the optional interface a runtime data-plane bridge implements so the
// engine can dispatch quarantine / isolate actions. Wave A's data plane provides
// the concrete implementation; tests use a fake.
type Runtime interface {
	Quarantine(ctx context.Context, workload string, reason string) error
	Isolate(ctx context.Context, workload string, reason string) error
	// Kill enqueues a targeted kill_process response action for the workload, which the
	// runtime-agent responder pulls and executes (SIGKILL). Mirrors Isolate: the bridge
	// captures org/cluster at construction, so the workload + reason are all it needs.
	Kill(ctx context.Context, workload string, reason string) error
}

// Engine evaluates events against a rule set and dispatches actions.
type Engine struct {
	rules    []Rule
	receiver map[string]notify.Receiver
	runtime  Runtime
	log      *slog.Logger
	mu       sync.RWMutex
}

// NewEngine constructs an Engine. Pass nil log to fall back to slog.Default().
func NewEngine(receivers map[string]notify.Receiver, runtime Runtime, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	if receivers == nil {
		receivers = map[string]notify.Receiver{}
	}
	return &Engine{receiver: receivers, runtime: runtime, log: log}
}

// SetRules replaces the live rule set atomically.
func (e *Engine) SetRules(rules []Rule) {
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
}

// Rules returns a defensive copy of the active rule set.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Dispatched is the receipt for a single rule firing.
type Dispatched struct {
	RuleID   string
	Actions  []string
	Warnings []string
}

// Dispatch evaluates the event against every rule and fires matching rules' actions.
// Returns one Dispatched per matched rule.
func (e *Engine) Dispatch(ctx context.Context, ev *Event) []Dispatched {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()
	out := []Dispatched{}
	for i := range rules {
		r := &rules[i]
		if !r.Match(ev) {
			continue
		}
		out = append(out, e.fire(ctx, r, ev))
	}
	return out
}

func (e *Engine) fire(ctx context.Context, r *Rule, ev *Event) Dispatched {
	d := Dispatched{RuleID: r.ID}
	for _, act := range r.Actions {
		switch act.Kind {
		case ActionNotify, ActionTicket:
			recv, ok := e.receiver[act.Target]
			if !ok {
				d.Warnings = append(d.Warnings, fmt.Sprintf("unknown receiver %q", act.Target))
				continue
			}
			alert := notify.Alert{
				ID: ev.ID, Severity: ev.Severity, Kind: string(ev.Type),
				Title: ev.Title, Cluster: ev.Cluster, Workload: ev.Workload,
				Labels: ev.Labels, URL: ev.URL,
			}
			if err := recv.Send(ctx, []notify.Alert{alert}); err != nil {
				d.Warnings = append(d.Warnings, fmt.Sprintf("notify %s: %v", act.Target, err))
				continue
			}
			d.Actions = append(d.Actions, string(act.Kind)+":"+act.Target)
		case ActionQuarantine:
			if e.runtime == nil {
				d.Warnings = append(d.Warnings, "runtime bridge unavailable (Wave A data plane required)")
				continue
			}
			if err := e.runtime.Quarantine(ctx, ev.Workload, r.Name); err != nil {
				d.Warnings = append(d.Warnings, fmt.Sprintf("quarantine: %v", err))
				continue
			}
			d.Actions = append(d.Actions, "quarantine")
		case ActionIsolate:
			if e.runtime == nil {
				d.Warnings = append(d.Warnings, "runtime bridge unavailable (Wave A data plane required)")
				continue
			}
			if err := e.runtime.Isolate(ctx, ev.Workload, r.Name); err != nil {
				d.Warnings = append(d.Warnings, fmt.Sprintf("isolate: %v", err))
				continue
			}
			d.Actions = append(d.Actions, "isolate")
		case ActionKill:
			if e.runtime == nil {
				d.Warnings = append(d.Warnings, "runtime bridge unavailable (Wave A data plane required)")
				continue
			}
			if err := e.runtime.Kill(ctx, ev.Workload, r.Name); err != nil {
				d.Warnings = append(d.Warnings, fmt.Sprintf("kill: %v", err))
				continue
			}
			d.Actions = append(d.Actions, "kill")
		default:
			d.Warnings = append(d.Warnings, fmt.Sprintf("unknown action %q", act.Kind))
		}
	}
	return d
}

// Validate returns an error if r is malformed.
func (r *Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("response: rule name required")
	}
	if r.EventType != "" && r.EventType != "*" &&
		r.EventType != EventAdmission && r.EventType != EventRuntime &&
		r.EventType != EventScan && r.EventType != EventCompliance {
		return fmt.Errorf("response: invalid event_type %q", r.EventType)
	}
	for _, c := range r.Conditions {
		switch c.Type {
		case CondName, CondLevel, CondCVECritical, CondProc, CondEventType,
			CondCVECriticalCount, CondCVEHighCount, CondCVEWithFixCount, CondCVEMaxAgeDays:
		default:
			return fmt.Errorf("response: invalid condition type %q", c.Type)
		}
		if c.Type == CondName || c.Type == CondProc {
			if _, err := regexp.Compile(c.Value); err != nil {
				return fmt.Errorf("response: invalid regex on %s: %w", c.Type, err)
			}
		}
		switch c.Type {
		case CondCVECriticalCount, CondCVEHighCount, CondCVEWithFixCount, CondCVEMaxAgeDays:
			n, err := strconv.Atoi(strings.TrimSpace(c.Value))
			if err != nil || n < 0 {
				return fmt.Errorf("response: %s requires a non-negative integer value, got %q", c.Type, c.Value)
			}
		}
	}
	for _, a := range r.Actions {
		switch a.Kind {
		case ActionNotify, ActionQuarantine, ActionIsolate, ActionKill, ActionTicket:
		default:
			return fmt.Errorf("response: invalid action kind %q", a.Kind)
		}
	}
	return nil
}
