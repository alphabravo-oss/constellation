package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func edgeRetractionFixture(t *testing.T) (*GroupEdgeStore, uuid.UUID, uuid.UUID, GroupEdgeRow) {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	orgID, clusterID := uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM runtime_policies WHERE org_id=$1`, orgID)
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	if _, err := database.Pool().Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Edge Retract')`, orgID, "edge-retract-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, orgID, "edge-retract-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	for _, group := range []struct{ name, members string }{
		{"front", `["default/front-a","default/front-b"]`},
		{"back", `["default/back"]`},
	} {
		if _, err := database.Pool().Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind, members) VALUES ($1,$2,$3,'ground',$4::jsonb)`, orgID, clusterID, group.name, group.members); err != nil {
			t.Fatal(err)
		}
	}
	store := NewGroupEdgeStore(database, NewRuntimePolicyStore(database, nil))
	row, result, err := store.UpsertAndExpand(ctx, orgID, clusterID, netpolicy.GroupEdge{
		FromGroup: "front", ToGroup: "back", Mode: "protect", Ports: []netpolicy.PortSpec{{Protocol: "TCP", Port: 443}},
	}, nil)
	if err != nil || len(result.Policies) != 3 {
		t.Fatalf("expand: row=%+v result=%+v err=%v", row, result, err)
	}
	return store, orgID, clusterID, row
}

func TestGroupEdgeDeleteRetractsOnlyOwnedRules(t *testing.T) {
	store, orgID, clusterID, edge := edgeRetractionFixture(t)
	otherStore, otherOrgID, _, otherEdge := edgeRetractionFixture(t)
	ctx := context.Background()
	pool := store.db.Pool()
	name := edgePolicyName(netpolicy.GroupEdge{ID: edge.ID.String(), FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	var originalID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM runtime_policies WHERE org_id=$1 AND workload='default/front-a' AND name=$2`, orgID, name).Scan(&originalID); err != nil {
		t.Fatal(err)
	}
	user := `{"cfg":"user","port":80,"proto":6,"action":3,"ingress":false}`
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_policies (org_id, cluster_id, workload, namespace, name, mode, rules)
 VALUES ($1,$2,'default/front-a','default','unrelated','enforce',$3::jsonb)`, orgID, clusterID, `[ `+user+` ]`); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, otherOrgID, edge.ID); !errors.Is(err, errEdgeNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if err := store.Delete(ctx, orgID, edge.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE id=$1`, edge.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("edge remains: count=%d err=%v", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND name=$2`, orgID, name).Scan(&count); err != nil || count != 0 {
		t.Fatalf("edge policies remaining: count=%d err=%v", count, err)
	}
	if _, err := store.pol.Get(ctx, orgID, originalID); err == nil {
		t.Fatal("edge-owned policy was not retracted")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND name='unrelated'`, orgID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("unrelated policy changed: count=%d err=%v", count, err)
	}
	if _, err := otherStore.get(ctx, otherOrgID, otherEdge.ID); err != nil {
		t.Fatalf("other tenant edge changed: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1`, otherOrgID).Scan(&count); err != nil || count != 3 {
		t.Fatalf("other tenant policies changed: count=%d err=%v", count, err)
	}
}

func TestGroupEdgeDeleteRefusesMixedAuthoredPolicyWithoutWeakeningPosture(t *testing.T) {
	store, orgID, _, edge := edgeRetractionFixture(t)
	ctx := context.Background()
	pool := store.db.Pool()
	name := edgePolicyName(netpolicy.GroupEdge{ID: edge.ID.String(), FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	var policyID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM runtime_policies WHERE org_id=$1 AND workload='default/front-a' AND name=$2`, orgID, name).Scan(&policyID); err != nil {
		t.Fatal(err)
	}
	user := `{"cfg":"user","port":80,"proto":6,"action":3,"ingress":false}`
	fed := `{"cfg":"fed","port":81,"proto":6,"action":3,"ingress":false}`
	if _, err := pool.Exec(ctx, `UPDATE runtime_policies SET rules=rules || $1::jsonb WHERE id=$2`, `[ `+user+`,`+fed+` ]`, policyID); err != nil {
		t.Fatal(err)
	}
	before, err := store.pol.Get(ctx, orgID, policyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, orgID, edge.ID); !errors.Is(err, errEdgePolicyOwnership) {
		t.Fatalf("mixed policy deletion: %v", err)
	}
	if _, err := store.get(ctx, orgID, edge.ID); err != nil {
		t.Fatalf("edge removed on conflict: %v", err)
	}
	after, err := store.pol.Get(ctx, orgID, policyID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode != before.Mode || after.DefAction != before.DefAction || string(after.Rules) != string(before.Rules) {
		t.Fatalf("mixed authored policy changed on conflict: before=%+v after=%+v", before, after)
	}
}

func TestGroupEdgeDeleteRefusesEditedPolicyPosture(t *testing.T) {
	store, orgID, _, edge := edgeRetractionFixture(t)
	ctx := context.Background()
	pool := store.db.Pool()
	name := edgePolicyName(netpolicy.GroupEdge{ID: edge.ID.String(), FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	if _, err := pool.Exec(ctx, `UPDATE runtime_policies SET mode='monitor', def_action=2
 WHERE org_id=$1 AND name=$2 AND workload='default/front-a'`, orgID, name); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, orgID, edge.ID); !errors.Is(err, errEdgePolicyOwnership) {
		t.Fatalf("edited posture deletion: %v", err)
	}
	var edges, policies int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE id=$1`, edge.ID).Scan(&edges); err != nil || edges != 1 {
		t.Fatalf("edge changed after posture conflict: %d, %v", edges, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND name=$2`, orgID, name).Scan(&policies); err != nil || policies != 3 {
		t.Fatalf("policies changed after posture conflict: %d, %v", policies, err)
	}
}

func TestGroupEdgeExpansionPreservesOwnershipAndRefusesAuthoredCollision(t *testing.T) {
	store, orgID, clusterID, edge := edgeRetractionFixture(t)
	ctx := context.Background()
	pool := store.db.Pool()
	name := edgePolicyName(netpolicy.GroupEdge{ID: edge.ID.String(), FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	if _, err := store.Expand(ctx, orgID, clusterID, netpolicy.GroupEdge{ID: edge.ID.String(), FromGroup: edge.FromGroup, ToGroup: edge.ToGroup}, nil); err != nil {
		t.Fatalf("repeat expansion: %v", err)
	}
	var raw json.RawMessage
	if err := pool.QueryRow(ctx, `SELECT rules FROM runtime_policies WHERE org_id=$1 AND name=$2 AND workload='default/front-a'`, orgID, name).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if _, owned, err := splitEdgeRules(raw, edge.ID); err != nil || !owned {
		t.Fatalf("ownership lost after re-expansion: owned=%v err=%v", owned, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE runtime_policies SET rules='[{"cfg":"user","port":8080,"proto":6,"action":3}]'::jsonb
 WHERE org_id=$1 AND name=$2 AND workload='default/front-a'`, orgID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Expand(ctx, orgID, clusterID, netpolicy.GroupEdge{ID: edge.ID.String(), FromGroup: edge.FromGroup, ToGroup: edge.ToGroup}, nil); !errors.Is(err, errEdgePolicyOwnership) {
		t.Fatalf("authored collision expansion: %v", err)
	}
	if err := store.Delete(ctx, orgID, edge.ID); !errors.Is(err, errEdgePolicyOwnership) {
		t.Fatalf("authored collision deletion: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT rules FROM runtime_policies WHERE org_id=$1 AND name=$2 AND workload='default/front-a'`, orgID, name).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) == "[]" {
		t.Fatal("authored rule was lost")
	}
}

func TestGroupEdgeDeleteRollsBackOnPolicyFailure(t *testing.T) {
	store, orgID, clusterID, edge := edgeRetractionFixture(t)
	ctx := context.Background()
	pool := store.db.Pool()
	name := edgePolicyName(netpolicy.GroupEdge{ID: edge.ID.String(), FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	var blockedPolicyID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM runtime_policies WHERE org_id=$1 AND cluster_id=$2 AND workload='default/front-b' AND name=$3`, orgID, clusterID, name).Scan(&blockedPolicyID); err != nil {
		t.Fatal(err)
	}
	holdTable := "edge_retract_hold_" + orgID.String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS `+holdTable)
	})
	if _, err := pool.Exec(ctx, `CREATE TABLE `+holdTable+` (policy_id uuid REFERENCES runtime_policies(id) ON DELETE RESTRICT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+holdTable+` (policy_id) VALUES ($1)`, blockedPolicyID); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, orgID, edge.ID); err == nil {
		t.Fatal("deletion succeeded despite policy retraction failure")
	}
	var edges, policies int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE id=$1`, edge.ID).Scan(&edges); err != nil || edges != 1 {
		t.Fatalf("edge after rollback: %d, %v", edges, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND name=$2`, orgID, name).Scan(&policies); err != nil || policies != 3 {
		t.Fatalf("policies after rollback: %d, %v", policies, err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE `+holdTable); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, orgID, edge.ID); err != nil {
		t.Fatalf("retry delete: %v", err)
	}
}

func TestGroupEdgeDeleteRefusesAmbiguousLegacyPolicy(t *testing.T) {
	store, orgID, clusterID, edge := edgeRetractionFixture(t)
	ctx := context.Background()
	pool := store.db.Pool()
	legacy := edgePolicyName(netpolicy.GroupEdge{FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_policies (org_id, cluster_id, workload, namespace, name, mode, rules)
 VALUES ($1,$2,'default/legacy','default',$3,'enforce','[{"cfg":"learned","port":443}]'::jsonb)`, orgID, clusterID, legacy); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, orgID, edge.ID); !errors.Is(err, errEdgePolicyOwnership) {
		t.Fatalf("ambiguous legacy deletion: %v", err)
	}
	var edges int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE id=$1`, edge.ID).Scan(&edges); err != nil || edges != 1 {
		t.Fatalf("edge lost after conflict: %d, %v", edges, err)
	}
	if _, err := store.Expand(ctx, orgID, clusterID, netpolicy.GroupEdge{ID: edge.ID.String(), FromGroup: edge.FromGroup, ToGroup: edge.ToGroup}, nil); !errors.Is(err, errEdgePolicyOwnership) {
		t.Fatalf("ambiguous legacy expansion: %v", err)
	}
}

func TestGroupEdgeExpandedEditsReplacePolicies(t *testing.T) {
	for _, expand := range []bool{false, true} {
		t.Run(fmt.Sprintf("expand=%v", expand), func(t *testing.T) {
			store, orgID, clusterID, original := edgeRetractionFixture(t)
			ctx := context.Background()
			name := edgePolicyName(netpolicy.GroupEdge{FromGroup: original.FromGroup, ToGroup: original.ToGroup})
			for _, change := range []struct {
				mode string
				port int
			}{
				{"monitor", 443},
				{"monitor", 8443},
				{"protect", 8443},
			} {
				requested := netpolicy.GroupEdge{FromGroup: original.FromGroup, ToGroup: original.ToGroup,
					Mode: change.mode, Ports: []netpolicy.PortSpec{{Protocol: "TCP", Port: change.port}}}
				var row GroupEdgeRow
				var err error
				if expand {
					var result ExpandResult
					row, result, err = store.UpsertAndExpand(ctx, orgID, clusterID, requested, nil)
					if err == nil && len(result.Policies) != 3 {
						t.Fatalf("expanded workloads = %v", result.Policies)
					}
				} else {
					row, err = store.Upsert(ctx, orgID, clusterID, requested, nil)
				}
				if err != nil || row.ID != original.ID || row.Mode != change.mode || len(row.Ports) != 1 || row.Ports[0].Port != change.port {
					t.Fatalf("edit row=%+v err=%v", row, err)
				}
				policies, err := store.db.Pool().Query(ctx, `SELECT rules, mode, def_action FROM runtime_policies WHERE org_id=$1 AND cluster_id=$2 AND name=$3`, orgID, clusterID, name)
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for policies.Next() {
					var raw json.RawMessage
					var mode PolicyMode
					var defaultAction uint8
					if err := policies.Scan(&raw, &mode, &defaultAction); err != nil {
						policies.Close()
						t.Fatal(err)
					}
					if _, owned, err := splitEdgeRules(raw, original.ID); err != nil || !owned {
						policies.Close()
						t.Fatalf("policy ownership: owned=%v err=%v", owned, err)
					}
					var rules []struct {
						Port int `json:"port"`
					}
					if err := json.Unmarshal(raw, &rules); err != nil {
						policies.Close()
						t.Fatal(err)
					}
					foundPort := false
					for _, rule := range rules {
						if rule.Port == change.port {
							foundPort = true
						}
						if rule.Port == 443 && change.port != 443 {
							policies.Close()
							t.Fatal("stale port retained")
						}
					}
					if !foundPort {
						policies.Close()
						t.Fatalf("new port %d missing: %s", change.port, raw)
					}
					wantMode, wantAction := PolicyModeMonitor, uint8(dp.PolicyActionAllow)
					if change.mode == "protect" {
						wantMode, wantAction = PolicyModeEnforce, dp.PolicyActionDeny
					}
					if mode != wantMode || defaultAction != wantAction {
						policies.Close()
						t.Fatalf("posture mode=%s action=%d", mode, defaultAction)
					}
					count++
				}
				err = policies.Err()
				policies.Close()
				if err != nil || count != 3 {
					t.Fatalf("policies=%d err=%v", count, err)
				}
			}
		})
	}
}

func TestGroupEdgeExpandedEditRefusesAmbiguousOwnership(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			store, orgID, clusterID, edge := edgeRetractionFixture(t)
			ctx := context.Background()
			pool := store.db.Pool()
			name := edgePolicyName(netpolicy.GroupEdge{FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
			var before json.RawMessage
			if legacy {
				if _, err := pool.Exec(ctx, `INSERT INTO runtime_policies (org_id, cluster_id, workload, namespace, name, mode, rules)
 VALUES ($1,$2,'default/legacy','default',$3,'enforce','[{"cfg":"learned","port":443}]'::jsonb)`, orgID, clusterID, name); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := pool.Exec(ctx, `UPDATE runtime_policies SET rules=rules || '[{"cfg":"user","port":80}]'::jsonb
 WHERE org_id=$1 AND name=$2 AND workload='default/front-a'`, orgID, name); err != nil {
					t.Fatal(err)
				}
			}
			if err := pool.QueryRow(ctx, `SELECT rules FROM runtime_policies WHERE org_id=$1 AND name=$2 AND workload='default/front-a'`, orgID, name).Scan(&before); err != nil {
				t.Fatal(err)
			}
			change := netpolicy.GroupEdge{FromGroup: edge.FromGroup, ToGroup: edge.ToGroup, Mode: "monitor", Ports: []netpolicy.PortSpec{{Protocol: "TCP", Port: 8443}}}
			for _, expand := range []bool{false, true} {
				var err error
				if expand {
					_, _, err = store.UpsertAndExpand(ctx, orgID, clusterID, change, nil)
				} else {
					_, err = store.Upsert(ctx, orgID, clusterID, change, nil)
				}
				if !errors.Is(err, errEdgePolicyOwnership) {
					t.Fatalf("ambiguous edit expand=%v err=%v", expand, err)
				}
			}
			current, err := store.get(ctx, orgID, edge.ID)
			if err != nil || current.Mode != "protect" || current.Ports[0].Port != 443 {
				t.Fatalf("edge changed: %+v err=%v", current, err)
			}
			var after json.RawMessage
			if err := pool.QueryRow(ctx, `SELECT rules FROM runtime_policies WHERE org_id=$1 AND name=$2 AND workload='default/front-a'`, orgID, name).Scan(&after); err != nil || string(after) != string(before) {
				t.Fatalf("policy changed: before=%s after=%s err=%v", before, after, err)
			}
		})
	}
}
