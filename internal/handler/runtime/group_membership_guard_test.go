package runtime

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/group"
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
