package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
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

func TestCELPolicyParseErrorRemainsFailClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rules := celPolicyRowsToRules([]admissionPolicyRow{{Name: "broken", Mode: "enforce", SpecYAML: "spec: ["}}, logger)
	if len(rules) != 1 {
		t.Fatalf("rules=%d, want malformed rule retained", len(rules))
	}
	engine, diagnostics, err := admission.NewCELEngine(rules)
	if err != nil || diagnostics["broken"] == nil {
		t.Fatalf("compile diagnostic missing: %v %v", err, diagnostics)
	}
	if resp := engine.Evaluate(context.Background(), &admissionv1.AdmissionRequest{}); resp.Allowed {
		t.Fatal("malformed enforce YAML must deny rather than disappear")
	}
}
