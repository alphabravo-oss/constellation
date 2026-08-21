package admission

import "testing"

// ADM-26: long-tail pod criteria parse into the right RuleConditions.
func TestRuleFromYAMLParsesLongTailPodCriteria(t *testing.T) {
	rule, supported, err := RuleFromYAML("long-tail", "long-tail", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: long-tail
spec:
  conditions:
    any:
      - field: spec.hostIPC
        equals: true
      - field: spec.containers[*].securityContext.allowPrivilegeEscalation
        equals: true
      - field: spec.imageNoOS
        equals: true
  pod:
    resourceLimit:
      requireCpuLimit: true
      requireMemoryLimit: true
      maxCpuLimit: "1"
      maxMemoryLimit: 512Mi
`)
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("long-tail pod rule should be supported by the local engine")
	}
	c := rule.Conditions
	if c.HostIPC == nil || !*c.HostIPC {
		t.Fatalf("HostIPC = %v (want true)", c.HostIPC)
	}
	if c.AllowPrivilegeEscalation == nil || !*c.AllowPrivilegeEscalation {
		t.Fatalf("AllowPrivilegeEscalation = %v (want true)", c.AllowPrivilegeEscalation)
	}
	if c.ImageNoOS == nil || !*c.ImageNoOS {
		t.Fatalf("ImageNoOS = %v (want true)", c.ImageNoOS)
	}
	if c.ResourceLimit == nil || !c.ResourceLimit.RequireCPULimit || !c.ResourceLimit.RequireMemoryLimit {
		t.Fatalf("ResourceLimit require flags not parsed: %+v", c.ResourceLimit)
	}
	if c.ResourceLimit.MaxCPULimit != "1" || c.ResourceLimit.MaxMemoryLimit != "512Mi" {
		t.Fatalf("ResourceLimit max thresholds = %+v", c.ResourceLimit)
	}
}

// ADM-26: a malformed resourceLimit quantity is rejected at load time.
func TestRuleFromYAMLRejectsBadResourceQuantity(t *testing.T) {
	_, _, err := RuleFromYAML("bad-q", "bad-q", "", "enforce", `spec:
  pod:
    resourceLimit:
      maxCpuLimit: "not-a-quantity"
`)
	if err == nil {
		t.Fatal("expected an error for an unparseable maxCpuLimit quantity")
	}
}

// ADM-29: CVE granularity fields parse into the vulnerability EvidenceGate.
func TestRuleFromYAMLParsesCVEGranularityGate(t *testing.T) {
	rule, supported, err := RuleFromYAML("cve-gran", "cve-gran", "", "enforce", `spec:
  vulnerability:
    maxMediumCount: 20
    maxCriticalWithFixCount: 0
    maxHighWithFixCount: 3
`)
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("CVE granularity gate rule should be supported")
	}
	if len(rule.Conditions.EvidenceGates) != 1 {
		t.Fatalf("gates = %+v", rule.Conditions.EvidenceGates)
	}
	g := rule.Conditions.EvidenceGates[0]
	if g.MaxMediumCVEs == nil || *g.MaxMediumCVEs != 20 {
		t.Fatalf("MaxMediumCVEs = %v (want 20)", g.MaxMediumCVEs)
	}
	if g.MaxCriticalWithFixCVEs == nil || *g.MaxCriticalWithFixCVEs != 0 {
		t.Fatalf("MaxCriticalWithFixCVEs = %v (want 0)", g.MaxCriticalWithFixCVEs)
	}
	if g.MaxHighWithFixCVEs == nil || *g.MaxHighWithFixCVEs != 3 {
		t.Fatalf("MaxHighWithFixCVEs = %v (want 3)", g.MaxHighWithFixCVEs)
	}
	if g.MaxAllowedSeverity != "" {
		t.Fatalf("count-only gate should not set MaxAllowedSeverity, got %q", g.MaxAllowedSeverity)
	}
}
