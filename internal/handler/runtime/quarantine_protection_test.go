package runtime

import (
	"context"
	"fmt"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestAutomaticResponseProtectionRefusesBeforeAnyWrite(t *testing.T) {
	cluster, other := uuid.New(), uuid.New()
	t.Setenv("CONSTELLATION_QUARANTINE_PROTECTED_NAMESPACES", fmt.Sprintf(`{%q:["custom-system","cnpg-system"]}`, cluster))
	for _, workload := range []string{"custom-system/api", "cnpg-system/Deployment/controller", "kube-system/dns", "kube-public/a", "kube-node-lease/a", "unknown", "", "/api", "payments/"} {
		t.Run(workload, func(t *testing.T) {
			// No DB is deliberately supplied: any attempted side effect panics.
			q := &quarantineRuntime{clusterID: cluster}
			engine := response.NewEngine(nil, q, nil)
			engine.SetRules([]response.Rule{{ID: "protect", Enabled: true, EventType: response.EventRuntime, Actions: []response.Action{{Kind: response.ActionQuarantine}, {Kind: response.ActionIsolate}, {Kind: response.ActionKill}}}})
			got := engine.Dispatch(t.Context(), &response.Event{ID: "event", Type: response.EventRuntime, Workload: workload, Severity: "high"})
			if len(got) != 1 || len(got[0].Actions) != 0 || len(got[0].Warnings) != 3 {
				t.Fatalf("incorrect action results: %+v", got)
			}
			for _, warning := range got[0].Warnings {
				if !strings.Contains(warning, "response action refused:") {
					t.Fatalf("missing refusal: %s", warning)
				}
			}
		})
	}
	for _, tc := range []struct {
		cluster  uuid.UUID
		workload string
	}{{cluster, "payments/api"}, {other, "custom-system/api"}} {
		if err := checkResponseWorkloadProtection(tc.cluster, tc.workload); err != nil {
			t.Fatalf("application or unrelated cluster exempted: %v", err)
		}
	}
	t.Setenv("CONSTELLATION_QUARANTINE_PROTECTED_NAMESPACES", `{"invalid":["system"]}`)
	if err := checkResponseWorkloadProtection(cluster, "payments/api"); err == nil {
		t.Fatal("malformed protection allowed action")
	}
}

func TestAutomaticResponseProtectionDispatchDatabase(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := t.Context()
	org, cluster := uuid.New(), uuid.New()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "auto-protection-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM network_policy_lifecycle_states WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM quarantine_entries WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM response_rules_v2 WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := d.Pool().Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'protected')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO response_rules_v2(org_id,cluster_id,name,description,enabled,event_type,conditions,actions,workload_match) VALUES($1,$2,'protect-system','',true,'runtime','[]','[{"kind":"quarantine"},{"kind":"isolate"},{"kind":"kill"}]','{}')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTELLATION_QUARANTINE_PROTECTED_NAMESPACES", fmt.Sprintf(`{%q:["custom-system"]}`, cluster))
	dispatch := NewResponseDispatch(d, nil)
	dispatch(ctx, org, cluster, response.Event{ID: "system", Type: response.EventRuntime, Severity: "high", Workload: "custom-system/api"})
	for _, table := range []string{"quarantine_entries", "network_policy_lifecycle_states", "runtime_response_actions_v2"} {
		var count int
		if err := d.Pool().QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE org_id=$1", org).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s rows=%d err=%v", table, count, err)
		}
	}
	var summary string
	if err := d.Pool().QueryRow(ctx, `SELECT after->>'refusal_summary' FROM audit_events WHERE org_id=$1 AND action='runtime.response_rule.refused' AND target_id=$2`, org, cluster.String()).Scan(&summary); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"custom-system/api", "quarantine:", "isolate:", "kill:", "protected system namespace"} {
		if !strings.Contains(summary, part) {
			t.Fatalf("missing %s in durable refusal: %s", part, summary)
		}
	}
	dispatch(ctx, org, cluster, response.Event{ID: "app", Type: response.EventRuntime, Severity: "high", Workload: "payments/api"})
	for _, table := range []string{"quarantine_entries", "network_policy_lifecycle_states"} {
		var count int
		if err := d.Pool().QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE org_id=$1", org).Scan(&count); err != nil || count != 1 {
			t.Fatalf("application %s rows=%d err=%v", table, count, err)
		}
	}
}
