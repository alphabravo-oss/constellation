package policy

import (
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

func bodyWith(pairs ...[2]string) createAdmissionRuleBody {
	b := createAdmissionRuleBody{Name: "t", Mode: "enforce"}
	for _, p := range pairs {
		b.Criteria = append(b.Criteria, struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}{Key: p[0], Value: p[1]})
	}
	return b
}

// The DTO builder translates the new ADM-26/ADM-29 criteria keys into YAML that
// the engine parser accepts and maps onto the expected conditions.
func TestBuildAdmissionSpecYAML_NewCriteriaRoundTrip(t *testing.T) {
	body := bodyWith(
		[2]string{"host_ipc", ""},
		[2]string{"allow_privilege_escalation", ""},
		[2]string{"image_no_os", ""},
		[2]string{"require_resource_limits", ""},
		[2]string{"max_medium_cves", "20"},
		[2]string{"max_critical_with_fix_cves", "0"},
		[2]string{"max_high_with_fix_cves", "3"},
	)
	specYAML, err := buildAdmissionSpecYAML(body)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rule, supported, err := admission.RuleFromYAML("t", "t", "", "enforce", specYAML)
	if err != nil {
		t.Fatalf("RuleFromYAML(%s): %v", specYAML, err)
	}
	if !supported {
		t.Fatal("generated rule must be supported by the engine")
	}
	c := rule.Conditions
	if c.HostIPC == nil || c.AllowPrivilegeEscalation == nil || c.ImageNoOS == nil {
		t.Fatalf("boolean long-tail conditions not set: %+v", c)
	}
	if c.ResourceLimit == nil || !c.ResourceLimit.RequireCPULimit {
		t.Fatalf("resourceLimit require flags not set: %+v", c.ResourceLimit)
	}
	if len(c.EvidenceGates) != 1 {
		t.Fatalf("expected one vulnerability gate, got %+v", c.EvidenceGates)
	}
	g := c.EvidenceGates[0]
	if g.MaxMediumCVEs == nil || g.MaxCriticalWithFixCVEs == nil || g.MaxHighWithFixCVEs == nil {
		t.Fatalf("CVE granularity gate fields not set: %+v", g)
	}
}

func TestBuildAdmissionSpecYAML_RejectsBadCVECount(t *testing.T) {
	if _, err := buildAdmissionSpecYAML(bodyWith([2]string{"max_medium_cves", "-1"})); err == nil {
		t.Fatal("negative max_medium_cves must be rejected")
	}
}

func TestBuildAdmissionSpecYAML_GroupRoundTrip(t *testing.T) {
	body := bodyWith([2]string{"run_as_privileged", ""})
	body.Group = "payments"
	specYAML, err := buildAdmissionSpecYAML(body)
	if err != nil {
		t.Fatalf("buildAdmissionSpecYAML: %v", err)
	}
	rule, supported, err := admission.RuleFromYAML("t", "t", "", "enforce", specYAML)
	if err != nil || !supported {
		t.Fatalf("RuleFromYAML supported=%v err=%v\n%s", supported, err, specYAML)
	}
	if len(rule.Groups) != 1 || rule.Groups[0] != "payments" {
		t.Fatalf("groups = %#v", rule.Groups)
	}
	action, groupName, criteria := summarizeAdmissionSpec(specYAML)
	if action != "deny" || groupName != "payments" {
		t.Fatalf("summary action=%q group=%q criteria=%v", action, groupName, criteria)
	}
	if !containsString(criteria, "group in payments") {
		t.Fatalf("summary criteria missing group: %v", criteria)
	}
}

// Every catalog key must have a builder case (the comment in admission_options.go
// requires the two stay in lockstep).
func TestAdmissionCatalogKeysHaveBuilderCases(t *testing.T) {
	for _, opt := range admissionCriteriaCatalog() {
		val := ""
		switch opt.ValueType {
		case "int":
			val = "1"
		case "float":
			val = "1.0"
		case "severity":
			val = "high"
		case "pss":
			val = "baseline"
		case "csv":
			val = "a,b"
		}
		if _, err := buildAdmissionSpecYAML(bodyWith([2]string{opt.Key, val})); err != nil && strings.Contains(err.Error(), "unknown criterion") {
			t.Errorf("catalog key %q has no builder case: %v", opt.Key, err)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
