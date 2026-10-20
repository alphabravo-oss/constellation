package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/netpolicyapply"
)

func TestLifecycleReconcileUsesLockedCurrentIntent(t *testing.T) {
	url := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CONSTELLATION_TEST_DATABASE_URL not set; integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("test DB unavailable: %v", err)
	}
	org, cluster := uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'lifecycle')`, org, org.String())
	defer func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org) }()
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'lifecycle')`, cluster, org)
	manifest := func(name string) string {
		return "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: " + name + "\n  namespace: team\nspec: {}"
	}
	exec(`INSERT INTO network_policy_lifecycle_states(org_id,cluster_id,workload,namespace,current_mode,approval_status,reason) VALUES($1,$2,'team/api','team','protect','applied','fixture')`, org, cluster)
	snapshot := netpolicyapply.LifecycleState{OrgID: org.String(), ClusterID: cluster.String(), Workload: "team/api", Namespace: "team", CurrentMode: "protect", ApprovalStatus: "applied", CandidateHash: "old", Manifests: map[string]string{"native": manifest("stale")}}
	for _, tc := range []struct{ name, mode, approval, action string }{{"demoted", "monitor", "demoted", "delete"}, {"rollback", "protect", "rolled_back", "apply"}, {"replacement", "protect", "applied", "apply"}, {"pending", "protect", "pending", "skip"}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]string{"native": manifest(tc.name)})
			exec(`UPDATE network_policy_lifecycle_states SET current_mode=$3,approval_status=$4,candidate_hash=$5,preview_manifests=$6::jsonb WHERE org_id=$1 AND cluster_id=$2`, org, cluster, tc.mode, tc.approval, tc.name, string(raw))
			client := &lifecycleTestClient{verifyLock: func() {
				var state string
				err := pool.QueryRow(ctx, `SELECT current_mode FROM network_policy_lifecycle_states WHERE org_id=$1 AND cluster_id=$2 AND workload='team/api' FOR UPDATE NOWAIT`, org, cluster).Scan(&state)
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
					t.Fatalf("operation ran without intent lock: %v", err)
				}
			}}
			result, err := reconcileLifecycleState(ctx, pool, client, snapshot, netpolicyapply.FlavorNative)
			if err != nil {
				t.Fatal(err)
			}
			if string(result.Action) != tc.action {
				t.Fatalf("stale action: %+v", result)
			}
			if tc.action == "skip" {
				if client.name != "" {
					t.Fatal("pending candidate executed")
				}
				return
			}
			if client.name != tc.name || client.action != tc.action {
				t.Fatalf("stale manifest: %+v", client)
			}
			var mode, approval, hash, ref, action string
			if err := pool.QueryRow(ctx, `SELECT desired_mode,approval_status,candidate_hash,resource_ref,last_action FROM network_policy_apply_status WHERE org_id=$1 AND cluster_id=$2 AND workload='team/api'`, org, cluster).Scan(&mode, &approval, &hash, &ref, &action); err != nil {
				t.Fatal(err)
			}
			if mode != tc.mode || approval != tc.approval || hash != tc.name || !strings.HasSuffix(ref, "/"+tc.name) || action != tc.action {
				t.Fatalf("stale status %s/%s/%s/%s/%s", mode, approval, hash, ref, action)
			}
		})
	}
	// A cluster/org mismatch must not reach any other policy with the same name.
	for _, foreignOrg := range []bool{false, true} {
		key := snapshot
		if foreignOrg {
			key.OrgID = uuid.NewString()
		} else {
			key.ClusterID = uuid.NewString()
		}
		client := &lifecycleTestClient{}
		result, err := reconcileLifecycleState(ctx, pool, client, key, netpolicyapply.FlavorNative)
		if err != nil || result.Action != netpolicyapply.ActionSkip || client.name != "" {
			t.Fatalf("foreign scope reconciled: %+v %v", result, err)
		}
	}
}

type lifecycleTestClient struct {
	verifyLock   func()
	name, action string
}

func (c *lifecycleTestClient) Apply(_ context.Context, r netpolicyapply.ManifestResource, _ []byte) error {
	c.verifyLock()
	c.name, c.action = r.Name, "apply"
	return nil
}
func (c *lifecycleTestClient) Delete(_ context.Context, r netpolicyapply.ManifestResource) error {
	c.verifyLock()
	c.name, c.action = r.Name, "delete"
	return nil
}
