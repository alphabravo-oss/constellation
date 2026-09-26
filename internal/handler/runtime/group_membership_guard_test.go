package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/group"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func membershipGuardFixture(t *testing.T, database *db.DB) (uuid.UUID, uuid.UUID, uuid.UUID, *GroupMembershipReconciler) {
	t.Helper()
	ctx := context.Background()
	orgID, clusterID, groupID := uuid.New(), uuid.New(), uuid.New()
	if _, err := database.Pool().Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,$2)`, orgID, "membership-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = database.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID) })
	if _, err := database.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, orgID, "membership-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool().Exec(ctx, `INSERT INTO groups (id, org_id, cluster_id, name, kind, criteria, members) VALUES ($1,$2,$3,'membership-guard','ground','[{"key":"namespace","op":"eq","value":"default"}]','["default/old"]')`, groupID, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	return orgID, clusterID, groupID, NewGroupMembershipReconciler(database, nil, nil)
}

func membershipGuardWorkloads(clusterID uuid.UUID) []group.Workload {
	return []group.Workload{{ID: "default/new", Cluster: clusterID.String(), Namespace: "default"}}
}

func TestMembershipReconcileRejectsReferencedMemberChange(t *testing.T) {
	for _, reference := range []string{"network", "dpi", "response", "admission"} {
		t.Run(reference, func(t *testing.T) {
			database := openTestDB(t)
			t.Cleanup(database.Close)
			orgID, clusterID, groupID, reconciler := membershipGuardFixture(t, database)
			ctx := context.Background()
			var err error
			switch reference {
			case "network":
				_, err = database.Pool().Exec(ctx, `INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group) VALUES ($1,$2,'membership-guard','external')`, orgID, clusterID)
			case "dpi":
				_, err = database.Pool().Exec(ctx, `INSERT INTO group_dpi_sensor_bindings (org_id, group_id, sensor_kind, sensor_id) VALUES ($1,$2,'dlp',$3)`, orgID, groupID, uuid.New())
			case "response":
				_, err = database.Pool().Exec(ctx, `INSERT INTO response_rules_v2 (org_id, name, event_type, workload_match) VALUES ($1,$2,'runtime',$3)`, orgID, "membership-response", `{"group":"membership-guard"}`)
			case "admission":
				_, err = database.Pool().Exec(ctx, `INSERT INTO policies (org_id, cluster_id, name, engine, category, spec_yaml) VALUES ($1,$2,$3,'constellation-admission','admission',$4)`, orgID, clusterID, "membership-admission", "spec:\n  match:\n    groups: [membership-guard]\n")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, changed, err := reconciler.reconcileMembership(ctx, orgID, groupID, membershipGuardWorkloads(clusterID)); err == nil || !strings.Contains(err.Error(), "policy references") || changed {
				t.Fatalf("referenced refresh: changed=%v err=%v", changed, err)
			}
			var members []byte
			if err := database.Pool().QueryRow(ctx, `SELECT members FROM groups WHERE id=$1`, groupID).Scan(&members); err != nil || string(members) != `["default/old"]` {
				t.Fatalf("referenced members changed: %s err=%v", members, err)
			}
		})
	}
}

func TestMembershipReconcileRefreshesUnreferencedCurrentSelector(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, clusterID, groupID, reconciler := membershipGuardFixture(t, database)
	ctx := context.Background()
	if _, err := database.Pool().Exec(ctx, `UPDATE groups SET criteria='[{"key":"namespace","op":"eq","value":"data"}]' WHERE id=$1`, groupID); err != nil {
		t.Fatal(err)
	}
	workloads := append(membershipGuardWorkloads(clusterID), group.Workload{ID: "data/current", Cluster: clusterID.String(), Namespace: "data"})
	name, changed, err := reconciler.reconcileMembership(ctx, orgID, groupID, workloads)
	if err != nil || !changed || name != "membership-guard" {
		t.Fatalf("unreferenced refresh: name=%q changed=%v err=%v", name, changed, err)
	}
	var members []byte
	if err := database.Pool().QueryRow(ctx, `SELECT members FROM groups WHERE id=$1`, groupID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	var actual []string
	if err := json.Unmarshal(members, &actual); err != nil || len(actual) != 1 || actual[0] != "data/current" {
		t.Fatalf("current selector not used: %s err=%v", members, err)
	}
}

func TestMembershipReconcileDoesNotLowerExistingMemberProfile(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, clusterID, groupID, reconciler := membershipGuardFixture(t, database)
	ctx := context.Background()
	if _, err := database.Pool().Exec(ctx, `INSERT INTO process_baseline_states (org_id, cluster_id, workload_id, namespace, name, mode) VALUES ($1,$2,'default/new','default','new','enforce')`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := reconciler.reconcileMembership(ctx, orgID, groupID, membershipGuardWorkloads(clusterID)); err != nil || !changed {
		t.Fatalf("membership: changed=%v err=%v", changed, err)
	}
	var mode string
	if err := database.Pool().QueryRow(ctx, `SELECT mode FROM process_baseline_states WHERE org_id=$1 AND cluster_id=$2 AND workload_id='default/new'`, orgID, clusterID).Scan(&mode); err != nil || mode != "enforce" {
		t.Fatalf("member mode=%q err=%v", mode, err)
	}
}

func TestMembershipReconcileWaitsForReferenceInsert(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, clusterID, groupID, reconciler := membershipGuardFixture(t, database)
	ctx := context.Background()
	writer, err := database.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	if _, err := writer.Exec(ctx, `INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group) VALUES ($1,$2,'membership-guard','external')`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := reconciler.reconcileMembership(ctx, orgID, groupID, membershipGuardWorkloads(clusterID))
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("refresh finished before reference commit: %v", err)
	case <-time.After(120 * time.Millisecond):
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "policy references") {
			t.Fatalf("refresh error=%v, want policy references", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not finish after reference commit")
	}
	var members []byte
	if err := database.Pool().QueryRow(ctx, `SELECT members FROM groups WHERE id=$1`, groupID).Scan(&members); err != nil || string(members) != `["default/old"]` {
		t.Fatalf("members changed after reference insert: %s err=%v", members, err)
	}
}

func membershipEdgeFixture(t *testing.T, database *db.DB) (uuid.UUID, uuid.UUID, uuid.UUID, GroupEdgeRow, *GroupMembershipReconciler) {
	t.Helper()
	orgID, clusterID, groupID, reconciler := membershipGuardFixture(t, database)
	ctx := context.Background()
	if _, err := database.Pool().Exec(ctx, `UPDATE groups SET profile_mode='protect' WHERE id=$1`, groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool().Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind, members) VALUES ($1,$2,'membership-dest','ground','["default/back"]')`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	reconciler.edges = NewGroupEdgeStore(database, NewRuntimePolicyStore(database, nil))
	edge, result, err := reconciler.edges.UpsertAndExpand(ctx, orgID, clusterID, netpolicy.GroupEdge{
		FromGroup: "membership-guard", ToGroup: "membership-dest", Mode: "protect",
		Ports: []netpolicy.PortSpec{{Protocol: "TCP", Port: 443}},
	}, nil)
	if err != nil || len(result.Policies) != 2 {
		t.Fatalf("initial expansion: edge=%+v result=%+v err=%v", edge, result, err)
	}
	return orgID, clusterID, groupID, edge, reconciler
}

func TestMembershipReconcileTransitionsOwnedEdgeAndProfile(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, clusterID, groupID, edge, reconciler := membershipEdgeFixture(t, database)
	ctx := context.Background()
	name, changed, err := reconciler.reconcileMembership(ctx, orgID, groupID, membershipGuardWorkloads(clusterID))
	if err != nil || !changed || name != "membership-guard" {
		t.Fatalf("membership transition: name=%q changed=%v err=%v", name, changed, err)
	}
	var members []byte
	if err := database.Pool().QueryRow(ctx, `SELECT members FROM groups WHERE id=$1`, groupID).Scan(&members); err != nil || string(members) != `["default/new"]` {
		t.Fatalf("members=%s err=%v", members, err)
	}
	var oldPolicies, newPolicies int
	policyName := edgePolicyName(netpolicy.GroupEdge{FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND name=$2 AND workload='default/old'`, orgID, policyName).Scan(&oldPolicies); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND name=$2 AND workload='default/new' AND mode='enforce'`, orgID, policyName).Scan(&newPolicies); err != nil || oldPolicies != 0 || newPolicies != 1 {
		t.Fatalf("old policies=%d new enforcing policies=%d err=%v", oldPolicies, newPolicies, err)
	}
	var baselineMode string
	if err := database.Pool().QueryRow(ctx, `SELECT mode FROM process_baseline_states WHERE org_id=$1 AND cluster_id=$2 AND workload_id='default/new'`, orgID, clusterID).Scan(&baselineMode); err != nil || baselineMode != "enforce" {
		t.Fatalf("new member baseline=%q err=%v", baselineMode, err)
	}
}

func TestMembershipReconcileOnceFollowsDiscoveredDeployment(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, clusterID, groupID, edge, reconciler := membershipEdgeFixture(t, database)
	ctx := context.Background()
	if _, err := database.Pool().Exec(ctx, `UPDATE groups SET criteria='[{"key":"role","op":"eq","value":"frontend"}]' WHERE id=$1`, groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool().Exec(ctx, `UPDATE groups SET criteria='[{"key":"role","op":"eq","value":"backend"}]' WHERE org_id=$1 AND name='membership-dest'`, orgID); err != nil {
		t.Fatal(err)
	}
	for _, workload := range []struct{ name, role string }{{"new", "frontend"}, {"back", "backend"}} {
		if _, err := database.Pool().Exec(ctx, `INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels) VALUES ($1,$2,'default',$3,'Deployment',jsonb_build_object('role',$4::text))`, orgID, clusterID, workload.name, workload.role); err != nil {
			t.Fatal(err)
		}
	}
	changed, err := reconciler.reconcileOnce(ctx)
	if err != nil || changed < 1 {
		t.Fatalf("reconcile changed=%d err=%v", changed, err)
	}
	var members []byte
	if err := database.Pool().QueryRow(ctx, `SELECT members FROM groups WHERE id=$1`, groupID).Scan(&members); err != nil || string(members) != `["default/new"]` {
		t.Fatalf("discovered members=%s err=%v", members, err)
	}
	policyName := edgePolicyName(netpolicy.GroupEdge{FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	var count int
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND name=$2 AND workload='default/new' AND mode='enforce'`, orgID, policyName).Scan(&count); err != nil || count != 1 {
		t.Fatalf("discovered member policies=%d err=%v", count, err)
	}
}

func TestMembershipReconcileRollsBackEdgeAndProfileOnExpansionFailure(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, clusterID, groupID, edge, reconciler := membershipEdgeFixture(t, database)
	ctx := context.Background()
	constraint := "membership_edge_" + orgID.String()[:8]
	t.Cleanup(func() {
		_, _ = database.Pool().Exec(context.Background(), `ALTER TABLE runtime_policies DROP CONSTRAINT IF EXISTS `+constraint)
	})
	check := fmt.Sprintf(`ALTER TABLE runtime_policies ADD CONSTRAINT %s CHECK (NOT (org_id='%s'::uuid AND workload='default/new')) NOT VALID`, constraint, orgID)
	if _, err := database.Pool().Exec(ctx, check); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := reconciler.reconcileMembership(ctx, orgID, groupID, membershipGuardWorkloads(clusterID)); err == nil || changed {
		t.Fatalf("transition should roll back: changed=%v err=%v", changed, err)
	}
	var members []byte
	if err := database.Pool().QueryRow(ctx, `SELECT members FROM groups WHERE id=$1`, groupID).Scan(&members); err != nil || string(members) != `["default/old"]` {
		t.Fatalf("members after rollback=%s err=%v", members, err)
	}
	var oldPolicies, newBaselines int
	policyName := edgePolicyName(netpolicy.GroupEdge{FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND name=$2 AND workload='default/old'`, orgID, policyName).Scan(&oldPolicies); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM process_baseline_states WHERE org_id=$1 AND workload_id='default/new'`, orgID).Scan(&newBaselines); err != nil || oldPolicies != 1 || newBaselines != 0 {
		t.Fatalf("old policies=%d new baselines=%d err=%v", oldPolicies, newBaselines, err)
	}
}

func TestMembershipReconcileRefusesAmbiguousEdgePolicy(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, clusterID, groupID, edge, reconciler := membershipEdgeFixture(t, database)
	ctx := context.Background()
	policyName := edgePolicyName(netpolicy.GroupEdge{FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
	if _, err := database.Pool().Exec(ctx, `UPDATE runtime_policies SET rules=rules || '[{"cfg":"user","port":80}]'::jsonb WHERE org_id=$1 AND name=$2 AND workload='default/old'`, orgID, policyName); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := reconciler.reconcileMembership(ctx, orgID, groupID, membershipGuardWorkloads(clusterID)); !errors.Is(err, errEdgePolicyOwnership) || changed {
		t.Fatalf("ambiguous transition: changed=%v err=%v", changed, err)
	}
	var members []byte
	if err := database.Pool().QueryRow(ctx, `SELECT members FROM groups WHERE id=$1`, groupID).Scan(&members); err != nil || string(members) != `["default/old"]` {
		t.Fatalf("members after conflict=%s err=%v", members, err)
	}
}

func TestMembershipReconcileRefusesEdgeWithOtherReferences(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, clusterID, groupID, _, reconciler := membershipEdgeFixture(t, database)
	ctx := context.Background()
	if _, err := database.Pool().Exec(ctx, `INSERT INTO response_rules_v2 (org_id, cluster_id, name, event_type, workload_match) VALUES ($1,$2,'membership-response','runtime',$3)`, orgID, clusterID, `{"group":"membership-guard"}`); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := reconciler.reconcileMembership(ctx, orgID, groupID, membershipGuardWorkloads(clusterID)); err == nil || !strings.Contains(err.Error(), "policy references") || changed {
		t.Fatalf("mixed references: changed=%v err=%v", changed, err)
	}
	var members []byte
	if err := database.Pool().QueryRow(ctx, `SELECT members FROM groups WHERE id=$1`, groupID).Scan(&members); err != nil || string(members) != `["default/old"]` {
		t.Fatalf("members after conflict=%s err=%v", members, err)
	}
}

func TestMembershipReconcileRefusesOrgWideReferencedGroup(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, clusterID, groupID, _, reconciler := membershipEdgeFixture(t, database)
	ctx := context.Background()
	if _, err := database.Pool().Exec(ctx, `UPDATE groups SET cluster_id=NULL WHERE id=$1`, groupID); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := reconciler.reconcileMembership(ctx, orgID, groupID, membershipGuardWorkloads(clusterID)); err == nil || !strings.Contains(err.Error(), "policy references") || changed {
		t.Fatalf("org-wide referenced group: changed=%v err=%v", changed, err)
	}
}
