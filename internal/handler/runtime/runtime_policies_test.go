package runtime

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// TestRuntimePolicy_RoundTrip — Wave A2 schema + DecodeRules + ToWorkloadPolicy.
// Hits the DB if available; skips otherwise.
func TestRuntimePolicy_RoundTrip(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID, clusterID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	_ = pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 LIMIT 1`, orgID).Scan(&clusterID)
	if clusterID == uuid.Nil {
		t.Skip("no seed cluster")
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM runtime_policies WHERE org_id=$1 AND name LIKE 'a2-test-%'`, orgID)
	})

	store := NewRuntimePolicyStore(d, nil)

	// Round-trip the rule set we'd hand to dp.
	rules := []*dp.PolicyRule{
		{ID: 1, Ingress: true, SrcIP: net.ParseIP("10.0.0.0"), SrcIPR: net.ParseIP("10.255.255.255"),
			DstIP: net.ParseIP("10.42.0.5"), Port: 80, IPProto: 6, Action: dp.PolicyActionAllow},
		{ID: 2, Ingress: false, SrcIP: net.ParseIP("10.42.0.5"), DstIP: net.ParseIP("0.0.0.0"),
			Port: 443, IPProto: 6, Action: dp.PolicyActionDeny},
	}
	rulesJSON, _ := json.Marshal(rules)

	p := &RuntimePolicy{
		OrgID: orgID, ClusterID: clusterID,
		Workload: "default/api", Namespace: "default", Name: "a2-test-1",
		Mode:      PolicyModeMonitor,
		DefAction: dp.PolicyActionAllow,
		ApplyDir:  dp.ApplyDirBoth,
		Rules:     rulesJSON,
	}
	id, err := store.Insert(ctx, p, "test-req-1")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := store.Get(ctx, orgID, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Mode != PolicyModeMonitor || got.Version != 1 {
		t.Errorf("mode=%s version=%d want monitor/1", got.Mode, got.Version)
	}
	decoded, err := got.DecodeRules()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("decoded %d rules, want 2", len(decoded))
	}
	if decoded[1].Action != dp.PolicyActionDeny {
		t.Errorf("rule[1].Action = %d, want Deny (raw should preserve deny)", decoded[1].Action)
	}

	// In monitor mode, ToWorkloadPolicy MUST demote deny → violate.
	wp, err := got.ToWorkloadPolicy([]string{"aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatalf("ToWorkloadPolicy: %v", err)
	}
	if len(wp.Rules) != 2 {
		t.Fatalf("wp rules=%d want 2", len(wp.Rules))
	}
	if wp.Rules[1].Action != dp.PolicyActionViolate {
		t.Errorf("monitor-mode demote: rule[1].Action = %d, want Violate", wp.Rules[1].Action)
	}

	// Flip to enforce — version bumps, deny stays deny.
	user := uuid.New()
	if err := store.SetMode(ctx, orgID, id, PolicyModeEnforce, user, false, "test-req-2"); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	got2, err := store.Get(ctx, orgID, id)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Mode != PolicyModeEnforce {
		t.Errorf("mode after promote: %s want enforce", got2.Mode)
	}
	if got2.Version != 2 {
		t.Errorf("version after promote: %d want 2 (trigger should bump)", got2.Version)
	}
	wp2, _ := got2.ToWorkloadPolicy([]string{"aa:bb:cc:dd:ee:ff"})
	if wp2.Rules[1].Action != dp.PolicyActionDeny {
		t.Errorf("enforce-mode: rule[1].Action = %d, want Deny preserved", wp2.Rules[1].Action)
	}

	// Disabled mode → empty rules pushed to dp regardless of stored ones.
	if err := store.SetMode(ctx, orgID, id, PolicyModeDisabled, user, false, "test-req-3"); err != nil {
		t.Fatal(err)
	}
	got3, _ := store.Get(ctx, orgID, id)
	wp3, _ := got3.ToWorkloadPolicy(nil)
	if len(wp3.Rules) != 0 {
		t.Errorf("disabled mode: wp.Rules=%d want 0", len(wp3.Rules))
	}

	if err := store.Delete(ctx, orgID, id, &user, "test-req-4"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// TestToWorkloadPolicy_StampsRuleIDs — Wave A6: every rule pushed to dp
// gets its wire ID overwritten with dp_policy_id so the policy_id field
// echoed in DPMsgConnect joins back to runtime_policies. Pure-Go test;
// no DB.
func TestToWorkloadPolicy_StampsRuleIDs(t *testing.T) {
	rules := []*dp.PolicyRule{
		{ID: 999 /* caller-supplied junk */, Action: dp.PolicyActionAllow, Port: 80},
		{ID: 0 /* unset */, Action: dp.PolicyActionDeny, Port: 443},
	}
	rulesJSON, _ := json.Marshal(rules)
	p := &RuntimePolicy{
		Workload: "default/api", Namespace: "default", Name: "stamp",
		Mode:       PolicyModeEnforce,
		DPPolicyID: 42, // sequence-assigned
		Rules:      rulesJSON,
	}
	wp, err := p.ToWorkloadPolicy([]string{"aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatalf("ToWorkloadPolicy: %v", err)
	}
	if len(wp.Rules) != 2 {
		t.Fatalf("rules=%d want 2", len(wp.Rules))
	}
	for i, r := range wp.Rules {
		if r.ID != 42 {
			t.Errorf("rule[%d].ID=%d, want 42 (== dp_policy_id, regardless of caller-supplied value)", i, r.ID)
		}
	}
	// Rules with DPPolicyID=0 are left alone (caller may be reading a
	// pre-A6 stored row; we don't corrupt).
	p.DPPolicyID = 0
	wp2, _ := p.ToWorkloadPolicy([]string{"aa:bb:cc:dd:ee:ff"})
	if wp2.Rules[0].ID == 42 {
		t.Errorf("with DPPolicyID=0, rule.ID should not be overwritten")
	}
}

// TestRuntimePolicy_InvalidMode catches a bad mode on insert.
func TestRuntimePolicy_InvalidMode(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	store := NewRuntimePolicyStore(d, nil)
	_, err := store.Insert(context.Background(), &RuntimePolicy{
		OrgID: uuid.New(), ClusterID: uuid.New(),
		Workload: "x", Namespace: "x", Name: "x",
		Mode: PolicyMode("garbage"),
	}, "test-req-bad-2")
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}
