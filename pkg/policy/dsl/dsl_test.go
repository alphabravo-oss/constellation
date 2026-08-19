package dsl

import "testing"

func TestPolicyValidate(t *testing.T) {
	good := Policy{
		Name:            "deny-privileged",
		Severity:        "high",
		Source:          SourceImperative,
		LifecycleStages: []LifecycleStage{StageDeploy},
		Group: PolicyGroup{Operator: OpAnd, Criteria: []Criterion{
			{Field: "container.securityContext.privileged", Operator: "EQ", Values: []string{"true"}},
		}},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	bad := Policy{Name: ""}
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected error for empty name")
	}
	mixed := Policy{
		Name: "x", Severity: "low", LifecycleStages: []LifecycleStage{StageBuild},
		Group: PolicyGroup{
			Operator: OpAnd,
			Criteria: []Criterion{{Field: "a", Operator: "EQ", Values: []string{"1"}}},
			Children: []PolicyGroup{{Operator: OpAnd, Criteria: []Criterion{{Field: "b", Operator: "EQ", Values: []string{"1"}}}}},
		},
	}
	if err := mixed.Validate(); err == nil {
		t.Fatalf("expected error mixing children + criteria")
	}
}

func TestPolicyMarshalRoundtrip(t *testing.T) {
	p := Policy{
		Name: "p", Severity: "medium", Source: SourceDeclarative,
		LifecycleStages: []LifecycleStage{StageBuild, StageDeploy},
		Group: PolicyGroup{Operator: OpOr, Children: []PolicyGroup{
			{Operator: OpAnd, Criteria: []Criterion{{Field: "image.tag", Operator: "EQ", Values: []string{"latest"}}}},
			{Operator: OpAnd, Criteria: []Criterion{{Field: "image.signature.verified", Operator: "EQ", Values: []string{"false"}}}},
		}},
	}
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Name != p.Name || len(p2.Group.Children) != 2 {
		t.Fatalf("roundtrip mismatch: %+v", p2)
	}
}
