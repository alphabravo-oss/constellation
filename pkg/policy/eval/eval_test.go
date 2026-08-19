package eval

import (
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/pkg/policy/dsl"
)

func TestMatchAndOr(t *testing.T) {
	p := dsl.Policy{
		Name:            "deny-priv-and-unsigned",
		Severity:        "high",
		LifecycleStages: []dsl.LifecycleStage{dsl.StageDeploy},
		Group: dsl.PolicyGroup{Operator: dsl.OpAnd, Criteria: []dsl.Criterion{
			{Field: "container.securityContext.privileged", Operator: "EQ", Values: []string{"true"}},
			{Field: "image.signature.verified", Operator: "EQ", Values: []string{"false"}},
		}},
	}
	if !Match(p, Record{
		"container.securityContext.privileged": "true",
		"image.signature.verified":             "false",
	}).Matched {
		t.Fatalf("expected match")
	}
	if Match(p, Record{
		"container.securityContext.privileged": "false",
		"image.signature.verified":             "false",
	}).Matched {
		t.Fatalf("expected no match (priv=false)")
	}
}

func TestMatchOperators(t *testing.T) {
	p := dsl.Policy{
		Name: "a", Severity: "low", LifecycleStages: []dsl.LifecycleStage{dsl.StageBuild},
		Group: dsl.PolicyGroup{Operator: dsl.OpOr, Criteria: []dsl.Criterion{
			{Field: "image.tag", Operator: "REGEX", Values: []string{`^latest$`}},
			{Field: "cvss", Operator: "GTE", Values: []string{"7"}},
		}},
	}
	if !Match(p, Record{"image.tag": "latest"}).Matched {
		t.Fatalf("regex match expected")
	}
	if !Match(p, Record{"image.tag": "1.0", "cvss": "9.8"}).Matched {
		t.Fatalf("gte match expected")
	}
}

func TestScopeAndExclusion(t *testing.T) {
	p := dsl.Policy{
		Name: "scoped", Severity: "low", LifecycleStages: []dsl.LifecycleStage{dsl.StageDeploy},
		Scopes:     []dsl.Scope{{Namespace: "prod"}},
		Exclusions: []dsl.Exclusion{{Deployment: "legacy", Expiration: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}},
		Group: dsl.PolicyGroup{Operator: dsl.OpAnd, Criteria: []dsl.Criterion{
			{Field: "k", Operator: "EQ", Values: []string{"v"}},
		}},
	}
	if Match(p, Record{"namespace": "staging", "k": "v"}).Matched {
		t.Fatalf("staging should be out of scope")
	}
	if Match(p, Record{"namespace": "prod", "deployment": "legacy", "k": "v"}).Matched {
		t.Fatalf("legacy should be excluded")
	}
	if !Match(p, Record{"namespace": "prod", "deployment": "shop", "k": "v"}).Matched {
		t.Fatalf("expected match for prod/shop")
	}
}
