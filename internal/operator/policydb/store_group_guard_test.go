package policydb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/group"
)

func TestOperatorGroupReferenceGuard(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	orgID := seedOrg(t, pool)
	store := New(pool)
	row := GroupRow{OrgID: orgID, Name: "operator-" + uuid.NewString(), Kind: "ground", PolicyMode: "monitor", ProfileMode: "monitor",
		Criteria: []group.Criterion{{Key: "namespace", Op: group.OpEq, Value: "web"}}}
	if err := store.UpsertGroup(ctx, row); err != nil {
		t.Fatal(err)
	}
	var groupID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM groups WHERE org_id=$1 AND name=$2`, orgID, row.Name).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"network", "dpi", "response", "admission"} {
		t.Run(family, func(t *testing.T) {
			switch family {
			case "network":
				clusterID := seedOperatorCluster(t, pool, orgID)
				if _, err := pool.Exec(ctx, `INSERT INTO group_rule_edges (org_id,cluster_id,from_group,to_group) VALUES ($1,$2,$3,'external')`, orgID, clusterID, row.Name); err != nil {
					t.Fatal(err)
				}
				defer pool.Exec(ctx, `DELETE FROM group_rule_edges WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID)
			case "dpi":
				if _, err := pool.Exec(ctx, `INSERT INTO group_dpi_sensor_bindings (org_id,group_id,sensor_kind,sensor_id) VALUES ($1,$2,'dlp',$3)`, orgID, groupID, uuid.New()); err != nil {
					t.Fatal(err)
				}
				defer pool.Exec(ctx, `DELETE FROM group_dpi_sensor_bindings WHERE org_id=$1 AND group_id=$2`, orgID, groupID)
			case "response":
				if _, err := pool.Exec(ctx, `INSERT INTO response_rules_v2 (org_id,name,event_type,workload_match,actions) VALUES ($1,$2,'process',$3::jsonb,'[]'::jsonb)`, orgID, uuid.NewString(), `{"group":"`+groupID.String()+`"}`); err != nil {
					t.Fatal(err)
				}
				defer pool.Exec(ctx, `DELETE FROM response_rules_v2 WHERE org_id=$1`, orgID)
			case "admission":
				if _, err := pool.Exec(ctx, `INSERT INTO policies (org_id,name,engine,category,spec_yaml) VALUES ($1,$2,'constellation-admission','admission',$3)`, orgID, uuid.NewString(), "spec:\n  match:\n    groups: ["+row.Name+"]\n"); err != nil {
					t.Fatal(err)
				}
				defer pool.Exec(ctx, `DELETE FROM policies WHERE org_id=$1`, orgID)
			}
			changed := row
			changed.Criteria = []group.Criterion{{Key: "namespace", Op: group.OpEq, Value: "other"}}
			if err := store.UpsertGroup(ctx, changed); !errors.Is(err, ErrGroupReferenced) {
				t.Fatalf("changed referenced criteria: %v", err)
			}
			changed = row
			changed.Comment = "safe description"
			if err := store.UpsertGroup(ctx, changed); err != nil {
				t.Fatalf("comment update: %v", err)
			}
			if deleted, err := store.DeleteGroup(ctx, orgID, row.Name); deleted || !errors.Is(err, ErrGroupReferenced) {
				t.Fatalf("referenced delete: deleted=%v err=%v", deleted, err)
			}
		})
	}
	if deleted, err := store.DeleteGroup(ctx, orgID, row.Name); err != nil || !deleted {
		t.Fatalf("unreferenced delete: deleted=%v err=%v", deleted, err)
	}
}

func TestOperatorNetworkRuleScopeAndPolicyGuard(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	orgID := seedOrg(t, pool)
	otherOrg := seedOrg(t, pool)
	clusterID := seedOperatorCluster(t, pool, orgID)
	otherCluster := seedOperatorCluster(t, pool, otherOrg)
	store := New(pool)
	from := "operator-" + uuid.NewString()
	to := "operator-" + uuid.NewString()
	for _, name := range []string{from, to} {
		if err := store.UpsertGroup(ctx, GroupRow{OrgID: orgID, Name: name, Kind: "ground", PolicyMode: "monitor", ProfileMode: "monitor"}); err != nil {
			t.Fatal(err)
		}
	}
	row := NetworkRuleRow{OrgID: orgID, ClusterID: otherCluster, FromGroup: from, ToGroup: to, Mode: "monitor"}
	if err := store.UpsertNetworkRule(ctx, row); !errors.Is(err, ErrGroupScope) {
		t.Fatalf("cross-org cluster: %v", err)
	}
	row.ClusterID = clusterID
	row.ToGroup = "missing"
	if err := store.UpsertNetworkRule(ctx, row); !errors.Is(err, ErrGroupScope) {
		t.Fatalf("missing endpoint: %v", err)
	}
	foreignName := "foreign-" + uuid.NewString()
	if err := store.UpsertGroup(ctx, GroupRow{OrgID: otherOrg, Name: foreignName, Kind: "ground", PolicyMode: "monitor", ProfileMode: "monitor"}); err != nil {
		t.Fatal(err)
	}
	row.ToGroup = foreignName
	if err := store.UpsertNetworkRule(ctx, row); !errors.Is(err, ErrGroupScope) {
		t.Fatalf("cross-org endpoint: %v", err)
	}
	row.ToGroup = to
	if err := store.UpsertNetworkRule(ctx, row); err != nil {
		t.Fatal(err)
	}
	var edgeID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM group_rule_edges WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3 AND to_group=$4`, orgID, clusterID, from, to).Scan(&edgeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_policies (org_id,cluster_id,workload,namespace,name,rules) VALUES ($1,$2,'default/example','default',$3,$4::jsonb)`, orgID, clusterID, "edge-"+from+"-to-"+to+"-"+edgeID.String(), `[{"cfg":"learned","edge_id":"`+edgeID.String()+`"}]`); err != nil {
		t.Fatal(err)
	}
	changed := row
	changed.Mode = "protect"
	if err := store.UpsertNetworkRule(ctx, changed); !errors.Is(err, ErrGroupReferenced) {
		t.Fatalf("referenced mode change: %v", err)
	}
	if deleted, err := store.DeleteNetworkRule(ctx, orgID, clusterID, from, to); deleted || !errors.Is(err, ErrGroupReferenced) {
		t.Fatalf("referenced delete: deleted=%v err=%v", deleted, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM runtime_policies WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.DeleteNetworkRule(ctx, orgID, clusterID, from, to); err != nil || !deleted {
		t.Fatalf("unreferenced delete: deleted=%v err=%v", deleted, err)
	}
}

func TestOperatorGroupScopeCollision(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	orgID := seedOrg(t, pool)
	clusterID := seedOperatorCluster(t, pool, orgID)
	name := "operator-" + uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id,cluster_id,name,kind,policy_mode,profile_mode) VALUES ($1,$2,$3,'ground','monitor','monitor')`, orgID, clusterID, name); err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	row := GroupRow{OrgID: orgID, Name: name, Kind: "ground", PolicyMode: "protect", ProfileMode: "monitor"}
	if err := store.UpsertGroup(ctx, row); !errors.Is(err, ErrGroupScope) {
		t.Fatalf("cluster-scoped collision: %v", err)
	}
	if deleted, err := store.DeleteGroup(ctx, orgID, name); deleted || err != nil {
		t.Fatalf("cluster-scoped delete: deleted=%v err=%v", deleted, err)
	}
	var mode string
	if err := pool.QueryRow(ctx, `SELECT policy_mode FROM groups WHERE org_id=$1 AND name=$2`, orgID, name).Scan(&mode); err != nil || mode != "monitor" {
		t.Fatalf("cluster-scoped row changed: mode=%q err=%v", mode, err)
	}
}

func TestOperatorGroupReferenceInsertRace(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	orgID := seedOrg(t, pool)
	clusterID := seedOperatorCluster(t, pool, orgID)
	store := New(pool)
	row := GroupRow{OrgID: orgID, Name: "operator-" + uuid.NewString(), Kind: "ground", PolicyMode: "monitor", ProfileMode: "monitor"}
	if err := store.UpsertGroup(ctx, row); err != nil {
		t.Fatal(err)
	}
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(context.Background())
	if _, err := writer.Exec(ctx, `INSERT INTO group_rule_edges (org_id,cluster_id,from_group,to_group) VALUES ($1,$2,$3,'external')`, orgID, clusterID, row.Name); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		changed := row
		changed.PolicyMode = "protect"
		result <- store.UpsertGroup(ctx, changed)
	}()
	select {
	case err := <-result:
		t.Fatalf("group mutation bypassed in-flight reference insert: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrGroupReferenced) {
		t.Fatalf("group mutation after reference commit: %v", err)
	}
}

func seedOperatorCluster(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID) uuid.UUID {
	t.Helper()
	clusterID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO clusters (id,org_id,name) VALUES ($1,$2,$3)`, clusterID, orgID, "operator-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id=$1`, clusterID) })
	return clusterID
}
