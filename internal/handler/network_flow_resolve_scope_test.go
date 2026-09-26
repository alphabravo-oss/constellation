package handler

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIPResolverDoesNotCrossClusterIPReuse(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID := uuid.New()
	clusterA, clusterB := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "ip-scope-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'a'), ($3, $2, 'b')`, clusterA, orgID, clusterB); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		clusterID uuid.UUID
		name      string
	}{{clusterA, "app-a"}, {clusterB, "app-b"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO pod_ips (org_id, cluster_id, namespace, pod_name, deployment, ip) VALUES ($1, $2, 'team', $3, $3, '10.42.0.5'::inet)`, orgID, row.clusterID, row.name); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO cluster_services (org_id, cluster_id, namespace, name, cluster_ip) VALUES ($1, $2, 'team', $3, '10.43.0.5'::inet)`, orgID, row.clusterID, row.name+"-svc"); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC()
	rows := FlowIngestRequest{{SrcWorkload: "cluster/10.42.0.5", SrcAddr: "10.42.0.5", DstWorkload: "cluster/10.43.0.5", DstAddr: "10.43.0.5", At: at}}
	for _, testCase := range []struct {
		clusterID uuid.UUID
		name      string
	}{{clusterA, "app-a"}, {clusterB, "app-b"}} {
		resolver := NewIPResolverForCluster(ctx, database, orgID, testCase.clusterID, rows)
		if got, ok := resolver.Resolve("cluster/10.42.0.5", "10.42.0.5", "", at); !ok || got != "team/"+testCase.name {
			t.Fatalf("cluster %s pod=%q resolved=%t", testCase.clusterID, got, ok)
		}
		if got, ok := resolver.Resolve("cluster/10.43.0.5", "10.43.0.5", "", at); !ok || got != "team/"+testCase.name+"-svc" {
			t.Fatalf("cluster %s service=%q resolved=%t", testCase.clusterID, got, ok)
		}
	}
}
