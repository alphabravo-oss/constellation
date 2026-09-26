package runtime

import (
	"context"
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
