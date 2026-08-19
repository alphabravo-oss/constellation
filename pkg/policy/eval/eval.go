// Package eval evaluates a Constellation policy DSL tree against a record (a
// Finding, Deployment, or Image flattened to a string-keyed map). The record
// representation is intentionally trivial — callers normalize their domain object
// into a flat path -> string map before invoking Match.
package eval

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/pkg/policy/dsl"
)

// Record is a flattened view of the entity being evaluated.
// Keys follow the dot-path syntax of the field registry (e.g.
// "container.securityContext.privileged"). Multi-valued fields are joined with
// "," — for collection semantics use the special "list:" prefix where each
// element is a separate "list:<field>:<index>" key.
type Record map[string]string

// Result captures the policy outcome for a single record.
type Result struct {
	Matched      bool     `json:"matched"`
	FailedFields []string `json:"failed_fields,omitempty"`
}

// Match runs the policy's PolicyGroup tree against the record. Scopes and
// exclusions are applied first; matching is only attempted if scope-includes
// AND exclusion-does-not-match.
func Match(p dsl.Policy, r Record) Result {
	if !inScope(p, r) {
		return Result{}
	}
	if excluded(p, r, time.Now()) {
		return Result{}
	}
	matched, evidence := evalGroup(p.Group, r)
	return Result{Matched: matched, FailedFields: evidence}
}

func inScope(p dsl.Policy, r Record) bool {
	if len(p.Scopes) == 0 {
		return true
	}
	for _, s := range p.Scopes {
		if s.Cluster != "" && r["cluster"] != s.Cluster {
			continue
		}
		if s.Namespace != "" && r["namespace"] != s.Namespace {
			continue
		}
		ok := true
		for k, v := range s.Labels {
			if r["labels."+k] != v {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func excluded(p dsl.Policy, r Record, now time.Time) bool {
	for _, e := range p.Exclusions {
		if e.Expiration != "" {
			if t, err := time.Parse(time.RFC3339, e.Expiration); err == nil && now.After(t) {
				continue
			}
		}
		if e.Deployment != "" && r["deployment"] != e.Deployment {
			continue
		}
		if e.Image != "" && !strings.Contains(r["image"], e.Image) {
			continue
		}
		if e.Namespace != "" && r["namespace"] != e.Namespace {
			continue
		}
		return true
	}
	return false
}

func evalGroup(g dsl.PolicyGroup, r Record) (bool, []string) {
	if len(g.Criteria) == 0 && len(g.Children) == 0 {
		return false, nil
	}
	var evidence []string
	op := g.Operator
	if op == "" {
		op = dsl.OpAnd
	}
	matches := make([]bool, 0)
	switch {
	case len(g.Criteria) > 0:
		for _, c := range g.Criteria {
			ok := evalCriterion(c, r)
			matches = append(matches, ok)
			if ok {
				evidence = append(evidence, c.Field)
			}
		}
	default:
		for _, ch := range g.Children {
			ok, ev := evalGroup(ch, r)
			matches = append(matches, ok)
			evidence = append(evidence, ev...)
		}
	}
	return combine(op, matches), evidence
}

func combine(op dsl.BooleanOperator, m []bool) bool {
	if len(m) == 0 {
		return false
	}
	switch op {
	case dsl.OpOr:
		for _, v := range m {
			if v {
				return true
			}
		}
		return false
	case dsl.OpNot:
		return !m[0]
	default: // AND
		for _, v := range m {
			if !v {
				return false
			}
		}
		return true
	}
}

func evalCriterion(c dsl.Criterion, r Record) bool {
	v, present := r[c.Field]
	out := false
	switch strings.ToUpper(c.Operator) {
	case "EXISTS":
		out = present
	case "EQ":
		out = present && len(c.Values) > 0 && v == c.Values[0]
	case "NEQ":
		out = !present || (len(c.Values) > 0 && v != c.Values[0])
	case "IN":
		for _, val := range c.Values {
			if v == val {
				out = true
				break
			}
		}
	case "NOTIN":
		out = true
		for _, val := range c.Values {
			if v == val {
				out = false
				break
			}
		}
	case "CONTAINS":
		for _, val := range c.Values {
			if strings.Contains(v, val) {
				out = true
				break
			}
		}
	case "REGEX":
		for _, val := range c.Values {
			re, err := regexp.Compile(val)
			if err != nil {
				continue
			}
			if re.MatchString(v) {
				out = true
				break
			}
		}
	case "GT", "GTE", "LT", "LTE":
		out = numericCompare(v, c.Operator, c.Values)
	}
	if c.Negate {
		out = !out
	}
	return out
}

func numericCompare(have, op string, vals []string) bool {
	if len(vals) == 0 {
		return false
	}
	a, err1 := strconv.ParseFloat(have, 64)
	b, err2 := strconv.ParseFloat(vals[0], 64)
	if err1 != nil || err2 != nil {
		return false
	}
	switch strings.ToUpper(op) {
	case "GT":
		return a > b
	case "GTE":
		return a >= b
	case "LT":
		return a < b
	case "LTE":
		return a <= b
	}
	return false
}
