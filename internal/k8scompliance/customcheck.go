// User-supplied custom compliance checks.
//
// Parity with NeuVector's per-group custom check scripts (neuvector/controller/rest/bench.go
// handlerCustomCheckConfig + neuvector/agent/bench.go runCustomScript): an operator writes a
// check as a CEL expression that is evaluated over a collected Kubernetes object. The
// expression returns bool — true means the object is compliant (pass), false means it
// violates the check (fail). Unlike NeuVector we evaluate a sandboxed CEL expression instead
// of executing an arbitrary shell script, so there is no host/container exec surface; the same
// evaluator already backs the admission CEL engine (pkg/admission/cel.go).
package k8scompliance

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

// CustomCheck is a user-defined compliance check. Expression is a CEL program evaluated with a
// single `object` variable bound to the collected Kubernetes object (as a decoded JSON map).
// It must return a bool: true = compliant (pass), false = violation (fail).
type CustomCheck struct {
	ID          string // stable identifier, used as the compliance control_id
	Name        string // display title
	Severity    string // info|low|medium|high|critical (defaults to medium)
	TargetKind  string // Namespace|ClusterRole|Deployment|StatefulSet|DaemonSet
	Expression  string // CEL bool expression; true = compliant
	Remediation string
}

// compiledCustomCheck pairs a check with its compiled CEL program.
type compiledCustomCheck struct {
	CustomCheck
	program cel.Program
}

// customTarget is one collected object a custom check can run against.
type customTarget struct {
	kind      string
	namespace string
	name      string
	object    map[string]any
}

// compileCustomChecks compiles each check's CEL program. It returns the successfully compiled
// checks plus a map of check-ID -> compile error for the ones that failed, so one malformed
// expression never sinks the whole set.
func compileCustomChecks(checks []CustomCheck) ([]compiledCustomCheck, map[string]error, error) {
	env, err := cel.NewEnv(cel.Variable("object", cel.DynType))
	if err != nil {
		return nil, nil, fmt.Errorf("cel: env: %w", err)
	}
	errs := map[string]error{}
	out := make([]compiledCustomCheck, 0, len(checks))
	for _, c := range checks {
		if c.Expression == "" {
			errs[c.ID] = fmt.Errorf("empty expression")
			continue
		}
		ast, iss := env.Compile(c.Expression)
		if iss != nil && iss.Err() != nil {
			errs[c.ID] = iss.Err()
			continue
		}
		prg, err := env.Program(ast)
		if err != nil {
			errs[c.ID] = err
			continue
		}
		out = append(out, compiledCustomCheck{CustomCheck: c, program: prg})
	}
	return out, errs, nil
}

// evaluateCustomChecks compiles the supplied checks and runs each one against every collected
// target whose kind matches the check's TargetKind, producing one Evidence per (check, object).
// A CEL evaluation error is treated as a violation (fail-closed) so a broken expression can
// never silently pass the object it was meant to guard — the same policy the admission engine
// uses. Checks that fail to compile are skipped.
func evaluateCustomChecks(checks []CustomCheck, targets []customTarget, observedAt time.Time) []Evidence {
	compiled, _, err := compileCustomChecks(checks)
	if err != nil || len(compiled) == 0 {
		return nil
	}
	out := []Evidence{}
	for _, chk := range compiled {
		severity := chk.Severity
		if severity == "" {
			severity = "medium"
		}
		for _, tgt := range targets {
			if tgt.kind != chk.TargetKind {
				continue
			}
			status := "pass"
			detail := "custom check satisfied"
			val, _, evalErr := chk.program.Eval(map[string]any{"object": tgt.object})
			switch {
			case evalErr != nil:
				status = "fail"
				detail = "expression error (failed closed): " + evalErr.Error()
			default:
				if b, ok := val.(types.Bool); !ok || !bool(b) {
					status = "fail"
					detail = "object violates custom check expression"
				}
			}
			out = append(out, Evidence{
				InternalID:  chk.ID,
				Custom:      true,
				Title:       chk.Name,
				Severity:    severity,
				Status:      status,
				TargetKind:  chk.TargetKind,
				Target:      targetName(tgt),
				Evidence:    detail,
				Remediation: chk.Remediation,
				ObservedAt:  observedAt,
			})
		}
	}
	return out
}

// ValidateExpression reports whether expr compiles as a CEL check. The CRUD handler calls it
// so a syntactically broken expression is rejected at create time instead of failing silently
// (fail-closed) on every collector pass.
func ValidateExpression(expr string) error {
	_, errs, err := compileCustomChecks([]CustomCheck{{ID: "_validate", Expression: expr}})
	if err != nil {
		return err
	}
	if e, ok := errs["_validate"]; ok {
		return e
	}
	return nil
}

func targetName(t customTarget) string {
	if t.namespace != "" {
		return t.namespace + "/" + t.name
	}
	return t.name
}

// toUnstructured renders a typed Kubernetes object into the generic map CEL expressions see,
// matching how the admission CEL engine feeds decoded JSON objects to expressions.
func toUnstructured(obj any) (map[string]any, error) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
