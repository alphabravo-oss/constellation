// Rego (OPA) policy evaluator that plugs into the existing admission Engine interface.
//
// Customers ship Rego policies via the policies table (engine="opa"). At evaluation
// time we compile each Rego module once and run them against the AdmissionRequest. A
// policy is a violation iff its `deny` rule produces a non-empty set, mirroring the
// Gatekeeper convention.
//
//	package constellation.admission
//	deny[msg] {
//	  input.request.kind.kind == "Pod"
//	  input.request.object.spec.hostNetwork == true
//	  msg := "hostNetwork is forbidden"
//	}
package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/open-policy-agent/opa/rego"
)

// RegoPolicy wraps one Rego module compiled at registration time.
type RegoPolicy struct {
	ID     string
	Module string // the Rego source
	Mode   string // monitor | enforce

	query rego.PreparedEvalQuery
}

// RegoEngine implements the Engine interface using a set of compiled Rego policies.
type RegoEngine struct {
	Policies []*RegoPolicy
}

// NewRegoEngine compiles `modules` into RegoPolicy entries. Compilation errors are
// returned per policy so the caller can surface them in the UI without rejecting the
// whole set.
func NewRegoEngine(ctx context.Context, modules map[string]string, modes map[string]string) (*RegoEngine, map[string]error, error) {
	e := &RegoEngine{}
	errs := map[string]error{}
	for id, src := range modules {
		q, err := rego.New(
			rego.Query("data.constellation.admission.deny"),
			rego.Module(id+".rego", src),
		).PrepareForEval(ctx)
		if err != nil {
			errs[id] = err
			continue
		}
		mode := modes[id]
		if mode == "" {
			mode = "enforce"
		}
		e.Policies = append(e.Policies, &RegoPolicy{ID: id, Module: src, Mode: mode, query: q})
	}
	sort.Slice(e.Policies, func(i, j int) bool { return e.Policies[i].ID < e.Policies[j].ID })
	return e, errs, nil
}

// Evaluate runs all compiled Rego policies against the admission request. Returns a
// denial when any enforce-mode policy emits a non-empty deny set; monitor-mode hits
// become warnings.
func (e *RegoEngine) Evaluate(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	resp, _ := e.evaluate(ctx, req)
	return resp
}

// evaluate is Evaluate plus the id of the policy that produced an enforce-mode
// deny (empty when the request is allowed). ChainEngine uses the policy id to
// attribute the deny in audit/response-rule events.
func (e *RegoEngine) evaluate(ctx context.Context, req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, string) {
	resp := &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	if len(e.Policies) == 0 {
		return resp, ""
	}
	input := map[string]any{
		"request": map[string]any{
			"uid":  req.UID,
			"kind": req.Kind,
		},
	}
	if len(req.Object.Raw) > 0 {
		var obj any
		if err := json.Unmarshal(req.Object.Raw, &obj); err == nil {
			input["request"].(map[string]any)["object"] = obj
		}
	}

	var warnings []string
	for _, p := range e.Policies {
		rs, err := p.query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			// Fail CLOSED on an enforce-mode eval error. An OPA query that errors
			// out leaves the policy's verdict unknown; admitting on the error path
			// would let a runtime fault silently disable an enforce rule. Monitor
			// rules keep warning so they can never start blocking on an error.
			if p.Mode == "enforce" {
				resp.Allowed = false
				resp.Result = &metav1.Status{
					Message: fmt.Sprintf("rego policy %q evaluation error (denied fail-closed): %s", p.ID, err),
				}
				resp.Warnings = warnings
				return resp, p.ID
			}
			warnings = append(warnings, fmt.Sprintf("rego/%s (monitor) eval error: %s", p.ID, err))
			continue
		}
		denials := flattenDenials(rs)
		if len(denials) == 0 {
			continue
		}
		if p.Mode == "enforce" {
			resp.Allowed = false
			resp.Result = &metav1.Status{
				Message: fmt.Sprintf("rego policy %q denied: %v", p.ID, denials),
			}
			resp.Warnings = warnings
			return resp, p.ID
		}
		for _, msg := range denials {
			warnings = append(warnings, fmt.Sprintf("rego/%s (monitor): %s", p.ID, msg))
		}
	}
	resp.Warnings = warnings
	return resp, ""
}

// flattenDenials extracts the deny[msg] message set from a rego.ResultSet.
func flattenDenials(rs rego.ResultSet) []string {
	out := []string{}
	for _, r := range rs {
		for _, exp := range r.Expressions {
			switch v := exp.Value.(type) {
			case []any:
				for _, item := range v {
					out = append(out, fmt.Sprint(item))
				}
			case string:
				out = append(out, v)
			}
		}
	}
	return out
}
