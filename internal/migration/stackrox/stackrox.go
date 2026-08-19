// Package stackrox migrates a StackRox policy + exception export into Constellation
// policy + finding-lifecycle records.
//
// Input format: the JSON dump produced by `roxctl central debug dump --policy-violations`
// or the `/v1/policies` REST endpoint. We accept either:
//
//	{"policies":[{"id":"…","name":"…","lifecycleStages":[…],"policySections":[…]}, …]}
//	or
//	[{"id":"…","name":"…", …}]
//
// Output: a slice of Constellation Policy structs ready for INSERT into the policies
// table + a slice of acceptance records to seed findings.lifecycle='accepted'.
package stackrox

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// SourcePolicy mirrors the subset of a StackRox policy we consume.
type SourcePolicy struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Rationale       string            `json:"rationale"`
	Categories      []string          `json:"categories"`
	LifecycleStages []string          `json:"lifecycleStages"`
	Severity        string            `json:"severity"`
	Disabled        bool              `json:"disabled"`
	EnforcementActs []string          `json:"enforcementActions"`
	PolicySections  []PolicySection   `json:"policySections"`
	Exclusions      []json.RawMessage `json:"exclusions"`
}

type PolicySection struct {
	SectionName  string        `json:"sectionName"`
	PolicyGroups []PolicyGroup `json:"policyGroups"`
}

type PolicyGroup struct {
	FieldName string        `json:"fieldName"`
	BoolOp    string        `json:"booleanOperator"`
	Negate    bool          `json:"negate"`
	Values    []PolicyValue `json:"values"`
}

type PolicyValue struct {
	Value string `json:"value"`
}

// TargetPolicy is the Constellation-shaped row we emit.
type TargetPolicy struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Engine      string            `json:"engine"` // kyverno | opa | constellation-builtin
	Category    string            `json:"category"`
	Enabled     bool              `json:"enabled"`
	Mode        string            `json:"mode"` // monitor | enforce
	SpecYAML    string            `json:"spec_yaml"`
	Imported    map[string]string `json:"imported_from,omitempty"`
}

// Convert parses a StackRox export and returns Constellation TargetPolicy records.
//
// We pick the most appropriate Constellation engine per source policy:
//   - LifecycleStages includes "DEPLOY"  → engine=kyverno (admission-time)
//   - LifecycleStages includes "BUILD"   → engine=constellation-builtin (image-check)
//   - LifecycleStages includes "RUNTIME" → engine=constellation-builtin (runtime rule)
//
// Field-level translation is best-effort: where StackRox's policyGroups map cleanly to a
// Kyverno rule (e.g. "Privileged", "Host Mounts", "Image Tag") we emit a Kyverno
// ClusterPolicy. Otherwise we emit a constellation-builtin rule that the agent
// interprets via its rule fields.
func Convert(raw []byte) ([]TargetPolicy, error) {
	policies, err := decodeSource(raw)
	if err != nil {
		return nil, err
	}
	out := make([]TargetPolicy, 0, len(policies))
	for _, src := range policies {
		t := translatePolicy(src)
		out = append(out, t)
	}
	return out, nil
}

func decodeSource(raw []byte) ([]SourcePolicy, error) {
	// Try {"policies":[…]} first.
	var wrap struct {
		Policies []SourcePolicy `json:"policies"`
	}
	if err := json.Unmarshal(raw, &wrap); err == nil && wrap.Policies != nil {
		return wrap.Policies, nil
	}
	// Fall back to top-level array.
	var arr []SourcePolicy
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("stackrox: decode export: %w", err)
	}
	return arr, nil
}

func translatePolicy(src SourcePolicy) TargetPolicy {
	// Mode ladder: a disabled policy is never "enforce". Only a non-disabled
	// policy that carries a hard enforcement action enforces; everything else
	// (including build/runtime alert-only and disabled policies) is monitor.
	mode := "monitor"
	if !src.Disabled && hasAny(src.EnforcementActs, "FAIL_BUILD_ENFORCEMENT", "SCALE_TO_ZERO_ENFORCEMENT") {
		mode = "enforce"
	}
	out := TargetPolicy{
		Name:        slug(src.Name),
		Description: nonEmpty(src.Description, src.Rationale),
		Category:    firstOrDefault(src.Categories, "imported"),
		Enabled:     !src.Disabled,
		Mode:        mode,
		Imported: map[string]string{
			"source":    "stackrox",
			"source_id": src.ID,
			"name":      src.Name,
		},
	}

	switch {
	case contains(src.LifecycleStages, "DEPLOY") && canEmitKyverno(src):
		out.Engine = "kyverno"
		out.SpecYAML = emitKyverno(src, mode)
	case contains(src.LifecycleStages, "BUILD"):
		out.Engine = "constellation-builtin"
		out.SpecYAML = emitBuiltinBuild(src)
	case contains(src.LifecycleStages, "RUNTIME"):
		out.Engine = "constellation-builtin"
		out.SpecYAML = emitBuiltinRuntime(src)
	default:
		out.Engine = "constellation-builtin"
		out.SpecYAML = emitBuiltinFallback(src)
	}
	return out
}

// canEmitKyverno returns true when the source has at least one policyGroup and
// every policyGroup has a Kyverno mapping that renders a real validate pattern.
// A policy with an unmapped criterion (or no criteria at all) is routed to the
// constellation-builtin/manual-review path instead of a no-op enforce ClusterPolicy.
func canEmitKyverno(src SourcePolicy) bool {
	mapped := 0
	for _, section := range src.PolicySections {
		for _, g := range section.PolicyGroups {
			if kyvernoMapping(g.FieldName) == "" {
				return false
			}
			mapped++
		}
	}
	return mapped > 0
}

// kyvernoMapping returns the Kyverno field path for a StackRox policy field, or "" when
// no mapping is defined yet. Add entries here as we expand coverage.
func kyvernoMapping(field string) string {
	switch field {
	case "Privileged":
		return "spec.containers[*].securityContext.privileged"
	case "Host Network":
		return "spec.hostNetwork"
	case "Host PID":
		return "spec.hostPID"
	case "Read-Only Root Filesystem":
		return "spec.containers[*].securityContext.readOnlyRootFilesystem"
	case "Image Tag":
		return "spec.containers[*].image"
	}
	return ""
}

// emitKyverno renders a minimal Kyverno ClusterPolicy that mirrors the StackRox policy.
// validationFailureAction is derived from the computed mode (enforce->enforce,
// monitor->audit) so a monitor-only or disabled policy never embeds an enforce spec.
func emitKyverno(src SourcePolicy, mode string) string {
	failureAction := "audit"
	if mode == "enforce" {
		failureAction = "enforce"
	}
	policy := map[string]any{
		"apiVersion": "kyverno.io/v1",
		"kind":       "ClusterPolicy",
		"metadata": map[string]any{
			"name": slug(src.Name),
			"annotations": map[string]string{
				"constellation.alphabravo.io/imported-from": "stackrox",
				"constellation.alphabravo.io/imported-id":   src.ID,
			},
		},
		"spec": map[string]any{
			"validationFailureAction": failureAction,
			"rules": []map[string]any{{
				"name":  slug(src.Name) + "-rule",
				"match": map[string]any{"any": []map[string]any{{"resources": map[string]any{"kinds": []string{"Pod"}}}}},
				"validate": map[string]any{
					"message": nonEmpty(src.Description, src.Name),
					"pattern": kyvernoPattern(src),
				},
			}},
		},
	}
	b, _ := yaml.Marshal(policy)
	return string(b)
}

// kyvernoPattern produces a validate pattern dict from the policy groups. Every
// mapped field contributes a real constraint; the constraints are merged into a
// single conjunctive pattern (Kyverno validate patterns are AND by default).
// canEmitKyverno guarantees every group here is mapped, so the result is never
// an empty/no-op pattern.
func kyvernoPattern(src SourcePolicy) map[string]any {
	spec := map[string]any{}
	container := map[string]any{}
	securityContext := map[string]any{}
	for _, section := range src.PolicySections {
		for _, g := range section.PolicyGroups {
			switch g.FieldName {
			case "Privileged":
				securityContext["=(privileged)"] = "false"
			case "Read-Only Root Filesystem":
				securityContext["readOnlyRootFilesystem"] = "true"
			case "Host Network":
				spec["=(hostNetwork)"] = "false"
			case "Host PID":
				spec["=(hostPID)"] = "false"
			case "Image Tag":
				container["image"] = imageTagPattern(g)
			}
		}
	}
	if len(securityContext) > 0 {
		container["securityContext"] = securityContext
	}
	if len(container) > 0 {
		spec["containers"] = []map[string]any{container}
	}
	return map[string]any{"spec": spec}
}

// imageTagPattern renders a Kyverno image pattern that rejects the blocked tag
// (default "latest") on any container image.
func imageTagPattern(g PolicyGroup) string {
	tag := "latest"
	for _, v := range g.Values {
		if t := strings.TrimSpace(v.Value); t != "" {
			tag = t
			break
		}
	}
	return "!*:" + tag
}

func emitBuiltinBuild(src SourcePolicy) string {
	return marshalBuiltin("scan-finding-policy", src)
}

func emitBuiltinRuntime(src SourcePolicy) string {
	return marshalBuiltin("runtime-rule", src)
}

func emitBuiltinFallback(src SourcePolicy) string {
	return marshalBuiltin("imported-fallback", src)
}

func marshalBuiltin(kind string, src SourcePolicy) string {
	rule := map[string]any{
		"apiVersion": "constellation.alphabravo.io/v1",
		"kind":       "BuiltinRule",
		"metadata": map[string]string{
			"name":          slug(src.Name),
			"imported.from": "stackrox",
			"imported.id":   src.ID,
		},
		"spec": map[string]any{
			"kind":        kind,
			"categories":  src.Categories,
			"severity":    src.Severity,
			"description": nonEmpty(src.Description, src.Rationale),
			"sections":    src.PolicySections,
		},
	}
	b, _ := yaml.Marshal(rule)
	return string(b)
}

func slug(s string) string {
	s = strings.ToLower(s)
	out := make([]byte, 0, len(s))
	prevDash := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
			prevDash = false
		default:
			if !prevDash {
				out = append(out, '-')
				prevDash = true
			}
		}
	}
	return strings.Trim(string(out), "-")
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func hasAny(haystack []string, needles ...string) bool {
	for _, n := range needles {
		if contains(haystack, n) {
			return true
		}
	}
	return false
}

func firstOrDefault(arr []string, def string) string {
	if len(arr) > 0 {
		return arr[0]
	}
	return def
}

func nonEmpty(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}
