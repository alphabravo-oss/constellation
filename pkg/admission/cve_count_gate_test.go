package admission

import "testing"

func TestRuleFromYAMLParsesCVECountGate(t *testing.T) {
	rule, supported, err := RuleFromYAML("cve-count", "cve-count", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: cve-count
spec:
  vulnerability:
    maxCriticalCount: 0
    maxHighCount: 5
    honorActiveExceptions: true
`)
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("count gate rule should be supported")
	}
	if len(rule.Conditions.EvidenceGates) != 1 {
		t.Fatalf("gates = %+v", rule.Conditions.EvidenceGates)
	}
	g := rule.Conditions.EvidenceGates[0]
	if g.Type != "vulnerability" {
		t.Fatalf("type = %q", g.Type)
	}
	if g.MaxCriticalCVEs == nil || *g.MaxCriticalCVEs != 0 {
		t.Fatalf("maxCriticalCVEs = %v (want 0)", g.MaxCriticalCVEs)
	}
	if g.MaxHighCVEs == nil || *g.MaxHighCVEs != 5 {
		t.Fatalf("maxHighCVEs = %v (want 5)", g.MaxHighCVEs)
	}
	if g.MaxAllowedSeverity != "" {
		t.Fatalf("count-only gate should not set MaxAllowedSeverity, got %q", g.MaxAllowedSeverity)
	}
}
