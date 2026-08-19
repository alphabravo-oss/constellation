package policydb

import (
	"context"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// TestStore_ListAdmissionRulesExport seeds admission policies (one with multiple versions) and
// verifies ListAdmissionRules returns the latest version per name, and that AdmissionCR renders a
// CR whose spec carries the row's columns verbatim — the GitOps export read path.
func TestStore_ListAdmissionRulesExport(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()
	org := seedOrg(t, pool)
	ctx := context.Background()
	s := New(pool)

	if err := s.UpsertAdmissionRule(ctx, AdmissionRuleRow{
		OrgID: org, Name: "no-privileged", Description: "block privileged", Engine: "kyverno",
		Mode: "enforce", Enabled: true, SpecYAML: "a: 1",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// A second version of the same name (REST-side history) must collapse to the latest on export.
	if _, err := pool.Exec(ctx, `INSERT INTO policies (org_id, name, description, engine, category, spec_yaml, enabled, mode, version, source)
		VALUES ($1,'no-privileged','old','kyverno','admission','old: 1',false,'monitor',0,'imperative')`, org); err != nil {
		t.Fatalf("seed v0: %v", err)
	}
	// A non-admission policy must not appear in the admission export.
	if _, err := pool.Exec(ctx, `INSERT INTO policies (org_id, name, engine, category, spec_yaml, enabled, mode)
		VALUES ($1,'some-runtime','kyverno','runtime','x: 1',true,'monitor')`, org); err != nil {
		t.Fatalf("seed runtime: %v", err)
	}
	// An imperative (REST/UI-authored) admission policy must NOT be exported: emitting it as a CR
	// would adopt it into the operator's delete-on-removal lifecycle.
	if _, err := pool.Exec(ctx, `INSERT INTO policies (org_id, name, engine, category, spec_yaml, enabled, mode, source)
		VALUES ($1,'rest-authored','kyverno','admission','y: 1',true,'enforce','imperative')`, org); err != nil {
		t.Fatalf("seed imperative admission: %v", err)
	}

	rows, err := s.ListAdmissionRules(ctx, org)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d admission rows, want 1 (declarative + admission category, latest version only)", len(rows))
	}
	r := rows[0]
	if r.Name != "no-privileged" || r.Mode != "enforce" || !r.Enabled || r.SpecYAML != "a: 1" || r.Description != "block privileged" {
		t.Fatalf("latest-version row wrong: %+v", r)
	}

	cr := AdmissionCR(r)
	if cr.APIVersion != APIVersion || cr.Kind != KindAdmissionRule {
		t.Fatalf("CR TypeMeta %s/%s", cr.APIVersion, cr.Kind)
	}
	if cr.Name != "no-privileged" || cr.Spec.OrgID != org.String() || cr.Spec.Mode != "enforce" || !cr.Spec.Enabled {
		t.Fatalf("CR spec wrong: %+v", cr.Spec)
	}
}

// TestStore_ListResponseRulesExport seeds response rules and verifies ListResponseRules returns
// them priority-ordered with conditions/actions decoded, and ResponseCR renders a matching CR.
func TestStore_ListResponseRulesExport(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()
	org := seedOrg(t, pool)
	ctx := context.Background()
	s := New(pool)

	if err := s.UpsertResponseRule(ctx, responserule.ResponseRule{
		OrgID: org, Name: "low-prio", Enabled: true, Priority: 100, EventType: responserule.EventFile,
		Conditions: []responserule.Condition{{Field: "path", Op: responserule.OpEq, Value: "/etc/shadow"}},
		Actions:    []responserule.Action{{Type: responserule.ActionTag, Params: map[string]string{"key": "sensitive"}}},
	}); err != nil {
		t.Fatalf("upsert low: %v", err)
	}
	if err := s.UpsertResponseRule(ctx, responserule.ResponseRule{
		OrgID: org, Name: "high-prio", Enabled: true, Priority: 10, EventType: responserule.EventProcess,
		Conditions: []responserule.Condition{{Field: "process_name", Op: responserule.OpContains, Value: "nc"}},
		Actions:    []responserule.Action{{Type: responserule.ActionQuarantine}},
	}); err != nil {
		t.Fatalf("upsert high: %v", err)
	}

	// An imperative response rule must NOT be exported (declarative-only export).
	if _, err := pool.Exec(ctx, `INSERT INTO response_rules (org_id, name, event_type, actions, source)
		VALUES ($1,'rest-rr','process','[{"type":"tag"}]'::jsonb,'imperative')`, org); err != nil {
		t.Fatalf("seed imperative rr: %v", err)
	}

	rules, err := s.ListResponseRules(ctx, org)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d response rules, want 2 (declarative only)", len(rules))
	}
	// Ordered by priority ascending.
	if rules[0].Name != "high-prio" || rules[1].Name != "low-prio" {
		t.Fatalf("priority order wrong: %s, %s", rules[0].Name, rules[1].Name)
	}
	if len(rules[0].Conditions) != 1 || rules[0].Conditions[0].Field != "process_name" {
		t.Fatalf("conditions not decoded: %+v", rules[0].Conditions)
	}
	if len(rules[0].Actions) != 1 || rules[0].Actions[0].Type != responserule.ActionQuarantine {
		t.Fatalf("actions not decoded: %+v", rules[0].Actions)
	}

	cr := ResponseCR(rules[1])
	if cr.Kind != KindResponseRule || cr.Name != "low-prio" || cr.Spec.OrgID != org.String() {
		t.Fatalf("CR wrong: kind=%s name=%s org=%s", cr.Kind, cr.Name, cr.Spec.OrgID)
	}
	if len(cr.Spec.Actions) != 1 || cr.Spec.Actions[0].Type != "tag" || cr.Spec.Actions[0].Params["key"] != "sensitive" {
		t.Fatalf("CR actions wrong: %+v", cr.Spec.Actions)
	}
}
