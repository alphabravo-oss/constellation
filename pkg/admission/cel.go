// K8s CEL (Common Expression Language) admission engine.
//
// Implements the validation half of K8s ValidatingAdmissionPolicy: each CELRule has an
// `expression` returning bool (true = allow), and a `messageExpression` returning the
// denial string. Plugs into the existing admission Engine interface.
//
// Reference: github.com/google/cel-go + K8s ValidatingAdmissionPolicy doc shape.
package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CELRule mirrors the subset of ValidatingAdmissionPolicy fields we evaluate.
type CELRule struct {
	ID                string
	Expression        string // bool expression; true means allow
	MessageExpression string // string expression returning the deny message; optional
	Mode              string // monitor | enforce

	program           cel.Program
	messageProgram    cel.Program
}

// CELEngine compiles a set of CELRule entries and evaluates each on incoming requests.
type CELEngine struct {
	Rules []*CELRule
}

// NewCELEngine compiles the supplied rules. Returns per-rule compile errors so the caller
// can surface them in the UI without rejecting the whole set.
func NewCELEngine(rules []*CELRule) (*CELEngine, map[string]error, error) {
	env, err := cel.NewEnv(
		cel.Variable("request", cel.DynType),
		cel.Variable("object",  cel.DynType),
		cel.Variable("oldObject", cel.DynType),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("cel: env: %w", err)
	}
	errs := map[string]error{}
	out := &CELEngine{}
	for _, r := range rules {
		ast, iss := env.Compile(r.Expression)
		if iss != nil && iss.Err() != nil {
			errs[r.ID] = iss.Err()
			continue
		}
		prg, err := env.Program(ast)
		if err != nil {
			errs[r.ID] = err
			continue
		}
		r.program = prg
		if r.MessageExpression != "" {
			ast2, iss := env.Compile(r.MessageExpression)
			if iss == nil || iss.Err() == nil {
				if prg2, err := env.Program(ast2); err == nil {
					r.messageProgram = prg2
				}
			}
		}
		if r.Mode == "" {
			r.Mode = "enforce"
		}
		out.Rules = append(out.Rules, r)
	}
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].ID < out.Rules[j].ID })
	return out, errs, nil
}

// Evaluate runs all rules. Any enforce-mode rule whose expression evaluates to false
// denies the request; monitor-mode failures become warnings.
func (e *CELEngine) Evaluate(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	resp, _ := e.evaluate(ctx, req)
	return resp
}

// evaluate is Evaluate plus the id of the rule that produced an enforce-mode
// deny (empty when the request is allowed). ChainEngine uses the rule id to
// attribute the deny in audit/response-rule events.
func (e *CELEngine) evaluate(_ context.Context, req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, string) {
	resp := &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	if len(e.Rules) == 0 {
		return resp, ""
	}
	inputs := buildCELInputs(req)
	var warnings []string
	for _, r := range e.Rules {
		val, _, err := r.program.Eval(inputs)
		if err != nil {
			// Fail CLOSED on an enforce-mode eval error. A CEL expression that
			// errors (e.g. "no such key" on an absent securityContext) is NOT a
			// pass — treating it as a warning would admit the very pod the rule
			// is meant to reject. Monitor-mode rules keep warning so a broken
			// expression can't start blocking traffic before it's promoted.
			if r.Mode == "enforce" {
				resp.Allowed = false
				resp.Result = &metav1.Status{Message: fmt.Sprintf("CEL policy %q evaluation error (denied fail-closed): %s", r.ID, err)}
				resp.Warnings = warnings
				return resp, r.ID
			}
			warnings = append(warnings, fmt.Sprintf("cel/%s (monitor) eval error: %s", r.ID, err))
			continue
		}
		ok, _ := val.(types.Bool)
		if bool(ok) {
			continue
		}
		msg := fmt.Sprintf("CEL policy %q denied request", r.ID)
		if r.messageProgram != nil {
			if v, _, err := r.messageProgram.Eval(inputs); err == nil {
				if s, isStr := v.Value().(string); isStr {
					msg = s
				}
			}
		}
		if r.Mode == "enforce" {
			resp.Allowed = false
			resp.Result = &metav1.Status{Message: msg}
			resp.Warnings = warnings
			return resp, r.ID
		}
		warnings = append(warnings, fmt.Sprintf("cel/%s (monitor): %s", r.ID, msg))
	}
	resp.Warnings = warnings
	return resp, ""
}

// buildCELInputs marshals the AdmissionRequest into the variable map CEL expressions see.
func buildCELInputs(req *admissionv1.AdmissionRequest) map[string]any {
	in := map[string]any{
		"request": map[string]any{
			"uid":  string(req.UID),
			"kind": map[string]any{
				"group":   req.Kind.Group,
				"version": req.Kind.Version,
				"kind":    req.Kind.Kind,
			},
			"namespace":   req.Namespace,
			"operation":   string(req.Operation),
			"userInfo":    map[string]any{"username": req.UserInfo.Username, "groups": req.UserInfo.Groups},
		},
	}
	if len(req.Object.Raw) > 0 {
		var obj map[string]any
		if err := json.Unmarshal(req.Object.Raw, &obj); err == nil {
			in["object"] = obj
		}
	}
	if len(req.OldObject.Raw) > 0 {
		var old map[string]any
		if err := json.Unmarshal(req.OldObject.Raw, &old); err == nil {
			in["oldObject"] = old
		}
	}
	return in
}
