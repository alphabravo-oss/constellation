// Package responserule implements the E1 declarative response-rule engine — the
// server-side model + evaluation for NeuVector's CLUSResponseRule parity.
//
// A ResponseRule binds a runtime event_type (process|file|network|admission|scan|compliance) to an
// ordered set of conditions (generic field/op/value clauses) and an ordered set of actions
// (quarantine|suppress_log|webhook|tag). The engine is storage-agnostic and pure: rules are
// passed in by the API layer (which loads them from the response_rules table), so condition
// matching, priority ordering, and the enabled filter are trivially unit-testable and reused
// from both the ingest evaluator and the agent :sync bundle serializer.
//
// This is distinct from pkg/response (migration 021 / response_rules_v2), which is the
// typed condition-catalog engine. E1 is the generic field/op model with explicit priority
// ordering that the runtime-agent stream evaluator will consume.
package responserule

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// EventType is the runtime event category a rule triggers on.
type EventType string

const (
	EventProcess    EventType = "process"
	EventFile       EventType = "file"
	EventNetwork    EventType = "network"
	EventAdmission  EventType = "admission"
	EventScan       EventType = "scan"
	EventCompliance EventType = "compliance"
)

// validEventTypes is the closed set accepted by Validate.
var validEventTypes = map[EventType]bool{
	EventProcess: true, EventFile: true, EventNetwork: true,
	EventAdmission: true, EventScan: true, EventCompliance: true,
}

// Op is a condition comparator.
type Op string

const (
	OpEq       Op = "eq"
	OpNe       Op = "ne"
	OpContains Op = "contains"
	OpRegex    Op = "regex"
	OpGt       Op = "gt"
	OpLt       Op = "lt"
)

var validOps = map[Op]bool{
	OpEq: true, OpNe: true, OpContains: true, OpRegex: true, OpGt: true, OpLt: true,
}

// ActionType is the kind of effect a rule produces when it fires.
type ActionType string

const (
	ActionQuarantine  ActionType = "quarantine"
	ActionSuppressLog ActionType = "suppress_log"
	ActionWebhook     ActionType = "webhook"
	ActionTag         ActionType = "tag"
)

var validActionTypes = map[ActionType]bool{
	ActionQuarantine: true, ActionSuppressLog: true, ActionWebhook: true, ActionTag: true,
}

// Condition is one match clause on a runtime event. Field names the event attribute
// (e.g. "process_name", "path", "severity", "cvss"); Op is the comparator; Value is the
// RHS, interpreted as a string (eq/ne/contains/regex) or a number (gt/lt).
type Condition struct {
	Field string `json:"field"`
	Op    Op     `json:"op"`
	Value string `json:"value"`
}

// Action is a structured response action. Params carries action-specific knobs
// (e.g. {"receiver":"sec-webhook"} for webhook, {"key":"team","value":"sec"} for tag).
type Action struct {
	Type   ActionType        `json:"type"`
	Params map[string]string `json:"params,omitempty"`
}

// ResponseRule is the typed E1 model — one row of response_rules.
type ResponseRule struct {
	ID         uuid.UUID   `json:"id"`
	OrgID      uuid.UUID   `json:"org_id"`
	Name       string      `json:"name"`
	Enabled    bool        `json:"enabled"`
	Priority   int         `json:"priority"`
	EventType  EventType   `json:"event_type"`
	Conditions []Condition `json:"conditions"`
	Actions    []Action    `json:"actions"`
}

// Event is the normalized runtime event the engine matches against. Constellation's
// runtime events fold down to this shape at the ingest path. Fields holds arbitrary
// string-valued attributes a Condition.Field can reference.
type Event struct {
	Type   EventType
	Fields map[string]string
}

// Validate returns an error if r is malformed. Used by the CRUD handler before persisting.
func (r *ResponseRule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("responserule: name required")
	}
	if !validEventTypes[r.EventType] {
		return fmt.Errorf("responserule: invalid event_type %q", r.EventType)
	}
	if len(r.Actions) == 0 {
		return fmt.Errorf("responserule: at least one action required")
	}
	for _, c := range r.Conditions {
		if strings.TrimSpace(c.Field) == "" {
			return fmt.Errorf("responserule: condition field required")
		}
		if !validOps[c.Op] {
			return fmt.Errorf("responserule: invalid op %q", c.Op)
		}
		if c.Op == OpRegex {
			if _, err := regexp.Compile(c.Value); err != nil {
				return fmt.Errorf("responserule: invalid regex %q: %w", c.Value, err)
			}
		}
		if c.Op == OpGt || c.Op == OpLt {
			if _, err := strconv.ParseFloat(strings.TrimSpace(c.Value), 64); err != nil {
				return fmt.Errorf("responserule: op %s requires a numeric value, got %q", c.Op, c.Value)
			}
		}
	}
	for _, a := range r.Actions {
		if !validActionTypes[a.Type] {
			return fmt.Errorf("responserule: invalid action type %q", a.Type)
		}
		if a.Type == ActionWebhook && strings.TrimSpace(a.Params["receiver"]) == "" {
			return fmt.Errorf("responserule: webhook action requires a 'receiver' param")
		}
	}
	return nil
}

// Match reports whether the rule fires for ev: the rule must be enabled, its event_type
// must equal ev.Type, and EVERY condition must match (AND semantics, NeuVector-style).
func (r *ResponseRule) Match(ev *Event) bool {
	if !r.Enabled {
		return false
	}
	if r.EventType != ev.Type {
		return false
	}
	for i := range r.Conditions {
		if !matchCondition(&r.Conditions[i], ev) {
			return false
		}
	}
	return true
}

func matchCondition(c *Condition, ev *Event) bool {
	got := ev.Fields[c.Field]
	switch c.Op {
	case OpEq:
		return got == c.Value
	case OpNe:
		return got != c.Value
	case OpContains:
		return strings.Contains(got, c.Value)
	case OpRegex:
		re, err := compileCached(c.Value)
		if err != nil {
			return false
		}
		return re.MatchString(got)
	case OpGt, OpLt:
		gotF, err1 := strconv.ParseFloat(strings.TrimSpace(got), 64)
		wantF, err2 := strconv.ParseFloat(strings.TrimSpace(c.Value), 64)
		if err1 != nil || err2 != nil {
			return false
		}
		if c.Op == OpGt {
			return gotF > wantF
		}
		return gotF < wantF
	}
	return false
}

// Match is a free function over a rule slice: it returns, in priority order (lowest
// Priority first, ties broken by Name for determinism), the ordered actions of every
// ENABLED rule whose conditions match ev. This is the pure evaluation helper the ingest
// path calls to obtain "the ordered matching rules' actions".
//
// The returned slice flattens each matched rule's actions in declaration order, with
// higher-priority rules' actions appearing first.
func Match(rules []ResponseRule, ev *Event) []Action {
	matched := MatchRules(rules, ev)
	out := []Action{}
	for i := range matched {
		out = append(out, matched[i].Actions...)
	}
	return out
}

// MatchRules returns the matching rules themselves in priority order (lowest Priority
// first, ties broken by Name). Callers that need rule identity (e.g. for audit / webhook
// reason strings) use this; Match is the action-only convenience wrapper.
func MatchRules(rules []ResponseRule, ev *Event) []ResponseRule {
	ordered := make([]ResponseRule, len(rules))
	copy(ordered, rules)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].Name < ordered[j].Name
	})
	out := []ResponseRule{}
	for i := range ordered {
		if ordered[i].Match(ev) {
			out = append(out, ordered[i])
		}
	}
	return out
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
		return nil, err
	}
	regexCacheMu.Lock()
	regexCache[pattern] = re
	regexCacheMu.Unlock()
	return re, nil
}
