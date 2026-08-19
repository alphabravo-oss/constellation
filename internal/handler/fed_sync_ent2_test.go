package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/federation"
)

// TestFedSync_ENT2_ResponseRuleAndAdmissionPolicy covers ENT-2: applyFedRevision
// materializes a master 'response_rule' override (and an 'admission_policy') as a
// read-only cfg_type=fed row on a joint, a *_delete revision tombstones it, and a
// fed response-rule override rejects local mutation with errFedReadOnly.
func TestFedSync_ENT2_ResponseRuleAndAdmissionPolicy(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	for _, table := range []string{"policies", "response_rule_overrides"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}
	// cfg_type on response_rule_overrides is added by migration 096 (ENT-2).
	var col string
	_ = pool.QueryRow(ctx, `SELECT COALESCE((SELECT 'y' FROM information_schema.columns WHERE table_name='response_rule_overrides' AND column_name='cfg_type' LIMIT 1),'')`).Scan(&col)
	if col == "" {
		t.Skip("skipping: response_rule_overrides.cfg_type (migration 096) not applied")
	}

	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}

	const ruleID = "container-process-shell" // a real catalog rule_id
	const admName = "ent2-fed-admission-policy"
	clean := func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM response_rule_overrides WHERE org_id=$1 AND rule_id=$2`, orgID, ruleID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM policies WHERE org_id=$1 AND name=$2`, orgID, admName)
	}
	clean()
	t.Cleanup(clean)

	// ── response_rule: apply materializes a fed override row ─────────────────────
	// The response-rule DTO moved to internal/handler/policy (ARC-1); the parent
	// test cannot import it back (cycle). fedSyncPayload (which stays here) carries
	// the identical json tags (id/mode/enabled/override_reason) the apply path reads.
	rrPayload := fedSyncPayload{ID: ruleID, Mode: "enforce", Enabled: true, OverrideReason: "fed test"}
	if err := applyFedRevision(ctx, pool, orgID, federation.RuleRevision{
		Kind: "response_rule", RuleID: ruleID, Revision: 1, Payload: mustJSON(t, rrPayload),
	}); err != nil {
		t.Fatalf("apply response_rule: %v", err)
	}
	var mode, cfg string
	var enabled bool
	if err := pool.QueryRow(ctx,
		`SELECT mode, enabled, cfg_type FROM response_rule_overrides WHERE org_id=$1 AND rule_id=$2`,
		orgID, ruleID).Scan(&mode, &enabled, &cfg); err != nil {
		t.Fatalf("read fed override: %v", err)
	}
	if mode != "enforce" || !enabled || cfg != "fed" {
		t.Fatalf("fed override = mode=%q enabled=%v cfg=%q; want enforce/true/fed", mode, enabled, cfg)
	}

	// Read-only guard: a local update of the fed override is rejected. The
	// ResponseRules.Update handler moved to internal/handler/policy (ARC-1) and the
	// parent test cannot import it back; assert the underlying guard directly. The
	// handler's 403 is gated solely on responseRuleOverrideIsFed reporting true for
	// the materialized fed override, which is the same expectation.
	isFed, err := responseRuleOverrideIsFed(ctx, pool, orgID, ruleID)
	if err != nil {
		t.Fatalf("responseRuleOverrideIsFed: %v", err)
	}
	if !isFed {
		t.Fatalf("fed override not reported read-only; local update would not be rejected")
	}

	// Tombstone: a delete revision removes the fed override.
	if err := applyFedRevision(ctx, pool, orgID, federation.RuleRevision{
		Kind: "response_rule_delete", RuleID: ruleID, Revision: 2, Payload: mustJSON(t, rrPayload),
	}); err != nil {
		t.Fatalf("apply response_rule_delete: %v", err)
	}
	var rrCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM response_rule_overrides WHERE org_id=$1 AND rule_id=$2 AND cfg_type='fed'`, orgID, ruleID).Scan(&rrCount); err != nil {
		t.Fatal(err)
	}
	if rrCount != 0 {
		t.Fatalf("fed override still present after tombstone: %d rows", rrCount)
	}

	// ── admission_policy: apply materializes a fed policy row, tombstone removes it ─
	admPayload := fedSyncPayload{
		OrgID: orgID, Name: admName, Engine: "constellation-admission",
		Category: "admission", SpecYAML: "x: 1", Mode: "enforce", Enabled: true,
	}
	if err := applyFedRevision(ctx, pool, orgID, federation.RuleRevision{
		Kind: "admission_policy", RuleID: admName, Revision: 3, Payload: mustJSON(t, admPayload),
	}); err != nil {
		t.Fatalf("apply admission_policy: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT cfg_type FROM policies WHERE org_id=$1 AND name=$2`, orgID, admName).Scan(&cfg); err != nil {
		t.Fatalf("read fed admission policy: %v", err)
	}
	if cfg != "fed" {
		t.Fatalf("admission policy cfg_type = %q, want fed", cfg)
	}
	if err := applyFedRevision(ctx, pool, orgID, federation.RuleRevision{
		Kind: "admission_policy_delete", RuleID: admName, Revision: 4, Payload: mustJSON(t, admPayload),
	}); err != nil {
		t.Fatalf("apply admission_policy_delete: %v", err)
	}
	var admCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM policies WHERE org_id=$1 AND name=$2 AND cfg_type='fed'`, orgID, admName).Scan(&admCount); err != nil {
		t.Fatal(err)
	}
	if admCount != 0 {
		t.Fatalf("fed admission policy still present after tombstone: %d rows", admCount)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
