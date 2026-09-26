package network

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFlowBackfillDoesNotCrossClusterIPReuse(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID := uuid.New()
	clusterA, clusterB := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "backfill-scope-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM network_flows WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'a'), ($3, $2, 'b')`, clusterA, orgID, clusterB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO pod_ips (org_id, cluster_id, namespace, pod_name, deployment, ip)
VALUES ($1, $2, 'team', 'app-a', 'app-a', '10.42.0.6'::inet),
       ($1, $3, 'team', 'app-b', 'app-b', '10.42.0.5'::inet)`, orgID, clusterA, clusterB); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		clusterID uuid.UUID
		address   string
		want      string
		writes    int
	}{
		{clusterA, "10.42.0.5", "cluster/10.42.0.5", 0},
		{clusterA, "10.42.0.6", "team/app-a", 1},
		{clusterB, "10.42.0.5", "team/app-b", 1},
	} {
		var flowID uuid.UUID
		err := pool.QueryRow(ctx, `
INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, src_addr, protocol, at)
VALUES ($1, $2, $3, 'external/peer', $4, 'tcp', NOW()) RETURNING id`,
			orgID, testCase.clusterID, "cluster/"+testCase.address, testCase.address).Scan(&flowID)
		if err != nil {
			t.Fatal(err)
		}
		written, _, _, err := (&FlowBackfiller{db: database, window: time.Hour, limit: 100, batch: 100}).backfill(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if written != testCase.writes {
			t.Fatalf("rewrite count: got %d, want %d", written, testCase.writes)
		}
		var got string
		if err := pool.QueryRow(ctx, `SELECT src_workload FROM network_flows WHERE id = $1`, flowID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != testCase.want {
			t.Fatalf("cluster %s address %s: got %q, want %q", testCase.clusterID, testCase.address, got, testCase.want)
		}
	}
}
