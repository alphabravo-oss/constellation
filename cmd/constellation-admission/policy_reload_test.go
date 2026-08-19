package main

import (
	"testing"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

func TestAdmissionPolicyRowsToRulesParsesSupportedRows(t *testing.T) {
	profile, ok := admission.BuiltInAdmissionProfile("strict-hardening")
	if !ok {
		t.Fatal("strict-hardening profile missing")
	}
	rows := make([]admissionPolicyRow, 0, len(profile.Rules))
	for _, rule := range profile.Rules {
		rows = append(rows, admissionPolicyRow{
			Name:        profile.ID + "/" + rule.Name,
			Description: rule.Description,
			Mode:        rule.Mode,
			SpecYAML:    rule.SpecYAML,
		})
	}
	got, err := admissionPolicyRowsToRules(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(rows) {
		t.Fatalf("parsed rules=%d want %d", len(got), len(rows))
	}
	if got[0].ID == "" || got[0].Mode == "" {
		t.Fatalf("bad parsed rule: %+v", got[0])
	}
}

func TestAdmissionPolicyRowsToRulesParsesEvidenceBackedRows(t *testing.T) {
	profile, ok := admission.BuiltInAdmissionProfile("critical-vulnerabilities-blocked")
	if !ok {
		t.Fatal("critical profile missing")
	}
	got, err := admissionPolicyRowsToRules([]admissionPolicyRow{{
		Name:        profile.ID + "/" + profile.Rules[0].Name,
		Description: profile.Rules[0].Description,
		Mode:        profile.Rules[0].Mode,
		SpecYAML:    profile.Rules[0].SpecYAML,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed rules=%d want 1", len(got))
	}
	if len(got[0].Conditions.EvidenceGates) != 1 {
		t.Fatalf("missing evidence gate: %+v", got[0])
	}
}

func TestAdmissionPolicyRowsToRulesRejectsInvalidYAML(t *testing.T) {
	_, err := admissionPolicyRowsToRules([]admissionPolicyRow{{
		Name:     "bad",
		Mode:     "enforce",
		SpecYAML: "kind: [",
	}})
	if err == nil {
		t.Fatal("expected invalid YAML error")
	}
}
