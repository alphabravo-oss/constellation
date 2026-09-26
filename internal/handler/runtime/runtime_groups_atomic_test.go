package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func TestGroupEdgeExpansionRollsBackAllPoliciesOnLaterFailure(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, clusterID := uuid.New(), uuid.New()
	constraint := "edge_atomic_" + orgID.String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE runtime_policies DROP CONSTRAINT IF EXISTS `+constraint)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_policies WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Atomic Edge')`, orgID, "atomic-edge-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, orgID, "atomic-edge-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	for _, group := range []struct{ name, members string }{
		{"front", `["default/front-a","default/front-b"]`},
		{"back", `["default/back"]`},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind, members) VALUES ($1,$2,$3,'ground',$4::jsonb)`,
			orgID, clusterID, group.name, group.members); err != nil {
			t.Fatal(err)
		}
	}
	store := NewGroupEdgeStore(database, NewRuntimePolicyStore(database, nil))
	row, err := store.Upsert(ctx, orgID, clusterID, netpolicy.GroupEdge{
		FromGroup: "front", ToGroup: "back", Mode: "protect", Ports: []netpolicy.PortSpec{{Protocol: "TCP", Port: 443}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	check := fmt.Sprintf(`ALTER TABLE runtime_policies ADD CONSTRAINT %s CHECK (NOT (org_id='%s'::uuid AND workload='default/front-b')) NOT VALID`, constraint, orgID)
	if _, err := pool.Exec(ctx, check); err != nil {
		t.Fatal(err)
	}
	edge := netpolicy.GroupEdge{ID: row.ID.String(), FromGroup: "front", ToGroup: "back", Mode: "protect"}
	if _, err := store.Expand(ctx, orgID, clusterID, edge, nil); err == nil {
		t.Fatal("expansion succeeded despite a later policy write failure")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial policies persisted: count=%d err=%v", count, err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE runtime_policies DROP CONSTRAINT `+constraint); err != nil {
		t.Fatal(err)
	}
	result, err := store.Expand(ctx, orgID, clusterID, edge, nil)
	if err != nil || len(result.Policies) != 3 {
		t.Fatalf("retry expansion result=%+v err=%v", result, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND mode='enforce'`, orgID).Scan(&count); err != nil || count != 3 {
		t.Fatalf("enforcing policies after retry: count=%d err=%v", count, err)
	}
}

func TestGroupEdgeUpsertAndExpandRollsBackEdgeAndPolicies(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, clusterID := uuid.New(), uuid.New()
	constraint := "edge_create_atomic_" + orgID.String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE runtime_policies DROP CONSTRAINT IF EXISTS `+constraint)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Atomic Edge Create')`, orgID, "atomic-edge-create-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, orgID, "atomic-edge-create-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ name, members string }{
		{"front", `["default/front-a","default/front-b"]`},
		{"back", `["default/back"]`},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind, members) VALUES ($1,$2,$3,'ground',$4::jsonb)`, orgID, clusterID, item.name, item.members); err != nil {
			t.Fatal(err)
		}
	}
	store := NewGroupEdgeStore(database, NewRuntimePolicyStore(database, nil))
	edge := netpolicy.GroupEdge{FromGroup: "front", ToGroup: "back", Mode: "protect", Ports: []netpolicy.PortSpec{{Protocol: "TCP", Port: 443}}}
	check := fmt.Sprintf(`ALTER TABLE runtime_policies ADD CONSTRAINT %s CHECK (NOT (org_id='%s'::uuid AND workload='default/front-b')) NOT VALID`, constraint, orgID)
	if _, err := pool.Exec(ctx, check); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertAndExpand(ctx, orgID, clusterID, edge, nil); err == nil {
		t.Fatal("create with expansion succeeded despite a later policy failure")
	}
	var edges, policies int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1`, orgID).Scan(&edges); err != nil || edges != 0 {
		t.Fatalf("partial edge persisted: count=%d err=%v", edges, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1`, orgID).Scan(&policies); err != nil || policies != 0 {
		t.Fatalf("partial policies persisted: count=%d err=%v", policies, err)
	}
	previous, err := store.Upsert(ctx, orgID, clusterID, netpolicy.GroupEdge{FromGroup: "front", ToGroup: "back", Mode: "monitor", Comment: "previous"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertAndExpand(ctx, orgID, clusterID, edge, nil); err == nil {
		t.Fatal("update with expansion succeeded despite a later policy failure")
	}
	var mode, comment string
	if err := pool.QueryRow(ctx, `SELECT mode, comment FROM group_rule_edges WHERE id=$1`, previous.ID).Scan(&mode, &comment); err != nil || mode != "monitor" || comment != "previous" {
		t.Fatalf("edge update persisted: mode=%q comment=%q err=%v", mode, comment, err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE runtime_policies DROP CONSTRAINT `+constraint); err != nil {
		t.Fatal(err)
	}
	row, result, err := store.UpsertAndExpand(ctx, orgID, clusterID, edge, nil)
	if err != nil || row.ID != previous.ID || len(result.Policies) != 3 {
		t.Fatalf("retry row=%+v result=%+v err=%v", row, result, err)
	}
}

func TestGroupEdgeExpandedEditRollsBackRetractionOnExpansionFailure(t *testing.T) {
	for _, expand := range []bool{false, true} {
		t.Run(fmt.Sprintf("expand=%v", expand), func(t *testing.T) {
			store, orgID, clusterID, edge := edgeRetractionFixture(t)
			ctx := context.Background()
			pool := store.db.Pool()
			name := edgePolicyName(netpolicy.GroupEdge{FromGroup: edge.FromGroup, ToGroup: edge.ToGroup})
			var before json.RawMessage
			if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(p) ORDER BY workload) FROM runtime_policies p
 WHERE org_id=$1 AND cluster_id=$2 AND name=$3`, orgID, clusterID, name).Scan(&before); err != nil {
				t.Fatal(err)
			}
			constraint := "edge_edit_atomic_" + orgID.String()[:8]
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), `ALTER TABLE runtime_policies DROP CONSTRAINT IF EXISTS `+constraint)
			})
			check := fmt.Sprintf(`ALTER TABLE runtime_policies ADD CONSTRAINT %s CHECK (NOT (org_id='%s'::uuid AND workload='default/front-b')) NOT VALID`, constraint, orgID)
			if _, err := pool.Exec(ctx, check); err != nil {
				t.Fatal(err)
			}
			change := netpolicy.GroupEdge{FromGroup: edge.FromGroup, ToGroup: edge.ToGroup, Mode: "monitor", Ports: []netpolicy.PortSpec{{Protocol: "TCP", Port: 8443}}, Comment: "changed"}
			var err error
			if expand {
				_, _, err = store.UpsertAndExpand(ctx, orgID, clusterID, change, nil)
			} else {
				_, err = store.Upsert(ctx, orgID, clusterID, change, nil)
			}
			if err == nil {
				t.Fatal("edit succeeded despite expansion failure")
			}
			current, err := store.get(ctx, orgID, edge.ID)
			if err != nil || current.Mode != edge.Mode || current.Comment != edge.Comment || current.Ports[0].Port != edge.Ports[0].Port {
				t.Fatalf("edge after rollback: %+v err=%v", current, err)
			}
			var after json.RawMessage
			if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(p) ORDER BY workload) FROM runtime_policies p
 WHERE org_id=$1 AND cluster_id=$2 AND name=$3`, orgID, clusterID, name).Scan(&after); err != nil || string(after) != string(before) {
				t.Fatalf("policies changed after rollback: before=%s after=%s err=%v", before, after, err)
			}
			if _, err := pool.Exec(ctx, `ALTER TABLE runtime_policies DROP CONSTRAINT `+constraint); err != nil {
				t.Fatal(err)
			}
			if expand {
				_, _, err = store.UpsertAndExpand(ctx, orgID, clusterID, change, nil)
			} else {
				_, err = store.Upsert(ctx, orgID, clusterID, change, nil)
			}
			if err != nil {
				t.Fatalf("retry edit: %v", err)
			}
		})
	}
}
