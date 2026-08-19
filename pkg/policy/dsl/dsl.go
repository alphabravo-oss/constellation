// Package dsl implements the Constellation Boolean policy DSL.
//
// Inspired by stackrox/proto/storage/policy.proto (PolicyGroup + BooleanOperator),
// re-expressed in idiomatic Go. A policy is a tree of PolicyGroup nodes combined
// with AND / OR / NOT operators. Each leaf has a typed field reference, an operator
// and one or more values. The evaluator (pkg/policy/eval) matches a tree against a
// record (a Finding, Deployment, or Image).
//
// This DSL is the fourth engine option alongside Kyverno, OPA/Rego, and K8s CEL —
// it is intended for high-level "compliance-style" policies (e.g. "any privileged
// container in production with an unsigned image MUST trip a violation").
package dsl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// BooleanOperator combines a PolicyGroup's children. NOT inverts a single child.
type BooleanOperator string

const (
	OpAnd BooleanOperator = "AND"
	OpOr  BooleanOperator = "OR"
	OpNot BooleanOperator = "NOT"
)

// LifecycleStage is the deployment lifecycle a policy applies to. Aligned with
// StackRox's lifecycleStage but kept simple — we only need the three Constellation
// uses: BUILD (image scan), DEPLOY (admission), RUNTIME (live workload events).
type LifecycleStage string

const (
	StageBuild   LifecycleStage = "BUILD"
	StageDeploy  LifecycleStage = "DEPLOY"
	StageRuntime LifecycleStage = "RUNTIME"
)

// Source records whether the policy was authored imperatively (via the UI/API)
// or declaratively (committed as YAML/manifest and reconciled by the operator).
// Declarative policies are read-only in the UI by design — editing forces a fork.
type Source string

const (
	SourceImperative  Source = "imperative"
	SourceDeclarative Source = "declarative"
)

// Criterion is a leaf: a field reference + operator + values. Multi-value lists are
// combined as OR for IN/CONTAINS/REGEX-anyof, AND for ALLOF-style operators.
type Criterion struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"` // EQ, NEQ, IN, NOTIN, GT, GTE, LT, LTE, CONTAINS, REGEX, EXISTS
	Values   []string `json:"values,omitempty"`
	Negate   bool     `json:"negate,omitempty"` // applied AFTER the operator
}

// PolicyGroup is one node of the boolean tree. Leaves have Criteria; branches have
// Children. A non-empty PolicyGroup must have exactly one of (Criteria, Children).
type PolicyGroup struct {
	Operator BooleanOperator `json:"operator"`
	Criteria []Criterion     `json:"criteria,omitempty"`
	Children []PolicyGroup   `json:"children,omitempty"`
}

// Policy is the full DSL document.
type Policy struct {
	ID                 string           `json:"id,omitempty"`
	Name               string           `json:"name"`
	Description        string           `json:"description,omitempty"`
	Severity           string           `json:"severity"` // info|low|medium|high|critical
	Source             Source           `json:"source"`
	LifecycleStages    []LifecycleStage `json:"lifecycle_stages"`
	MITREAttackVectors []string         `json:"mitre_attack_vectors,omitempty"`
	CriteriaLocked     bool             `json:"criteria_locked"`
	MITREVectorsLocked bool             `json:"mitre_vectors_locked"`
	Scopes             []Scope          `json:"scopes,omitempty"`
	Exclusions         []Exclusion      `json:"exclusions,omitempty"`
	Group              PolicyGroup      `json:"group"`
	EnforcementMode    string           `json:"enforcement_mode,omitempty"` // monitor|enforce
	Actions            []string         `json:"actions,omitempty"`
}

// Scope narrows the set of records a policy matches against. All non-empty fields
// AND together. Label values prefix-match (key=value).
type Scope struct {
	Cluster   string            `json:"cluster,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Exclusion suppresses matches for a specific deployment / image / namespace.
// Expiration is a hard cutoff: once past, the exclusion is no longer honored.
type Exclusion struct {
	Name        string     `json:"name,omitempty"`
	Deployment  string     `json:"deployment,omitempty"`
	Image       string     `json:"image,omitempty"`
	Namespace   string     `json:"namespace,omitempty"`
	Expiration  string     `json:"expiration,omitempty"` // RFC3339; empty => never expires
}

// Validate returns nil if the policy is structurally well-formed. Callers should
// validate before persisting; the database layer enforces NOT NULL on key columns.
func (p Policy) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("policy: name is required")
	}
	if p.Severity == "" {
		return errors.New("policy: severity is required")
	}
	if len(p.LifecycleStages) == 0 {
		return errors.New("policy: at least one lifecycle stage is required")
	}
	for _, s := range p.LifecycleStages {
		switch s {
		case StageBuild, StageDeploy, StageRuntime:
		default:
			return fmt.Errorf("policy: invalid lifecycle stage %q", s)
		}
	}
	if p.Source != "" && p.Source != SourceImperative && p.Source != SourceDeclarative {
		return fmt.Errorf("policy: invalid source %q", p.Source)
	}
	return p.Group.Validate(0)
}

// Validate returns nil if the PolicyGroup tree is well-formed.
func (g PolicyGroup) Validate(depth int) error {
	if depth > 16 {
		return errors.New("policygroup: nesting exceeds 16 levels")
	}
	switch g.Operator {
	case OpAnd, OpOr, OpNot, "":
	default:
		return fmt.Errorf("policygroup: invalid operator %q", g.Operator)
	}
	if g.Operator == OpNot && len(g.Children)+len(g.Criteria) != 1 {
		return errors.New("policygroup: NOT requires exactly one child or criterion")
	}
	if len(g.Children) > 0 && len(g.Criteria) > 0 {
		return errors.New("policygroup: cannot mix children and criteria on a single node")
	}
	for _, c := range g.Criteria {
		if c.Field == "" || c.Operator == "" {
			return errors.New("criterion: field and operator are required")
		}
	}
	for _, c := range g.Children {
		if err := c.Validate(depth + 1); err != nil {
			return err
		}
	}
	return nil
}

// Marshal serializes a policy to JSON (canonical form used by storage + UI).
func (p Policy) Marshal() ([]byte, error) {
	return json.Marshal(p)
}

// Unmarshal parses a policy JSON document into a Policy.
func Unmarshal(b []byte) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return Policy{}, err
	}
	return p, nil
}
