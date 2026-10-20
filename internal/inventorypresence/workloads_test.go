package inventorypresence

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestWorkloadPresenceRequiresFreshCompleteEvidence(t *testing.T) {
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
	org, other, cluster := uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'presence'),($2::uuid,$2::text,'other')`, org, other)
	defer func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, other) }()
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'presence')`, cluster, org)
	for _, name := range []string{"live", "zero", "gone", "newer"} {
		exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,last_seen_at) VALUES($1,$2,'apps',$3,'Deployment',NOW()-INTERVAL '1 minute')`, org, cluster, name)
	}
	read := func() map[string]string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT name,`+WorkloadStatusSQL("d")+` FROM deployments d WHERE org_id=$1`, org)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var name, state string
			if err := rows.Scan(&name, &state); err != nil {
				t.Fatal(err)
			}
			out[name] = state
		}
		return out
	}
	for _, state := range read() {
		if state != "unverified" {
			t.Fatal("missing snapshot claimed presence")
		}
	}
	now := time.Now().UTC()
	states := map[string]string{"apps/Deployment/live": "present", "apps/Deployment/zero": "scaled_to_zero", "apps/StatefulSet/gone": "present"}
	if err := StoreWorkloads(ctx, pool, org, cluster, now, now.Add(time.Hour), states); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE deployments SET last_seen_at=$2 WHERE org_id=$1 AND name='newer'`, org, now.Add(time.Minute))
	got := read()
	for name, want := range map[string]string{"live": "present", "zero": "scaled_to_zero", "gone": "absent", "newer": "unverified"} {
		if got[name] != want {
			t.Fatalf("%s=%s want %s", name, got[name], want)
		}
	}
	if err := StoreWorkloads(ctx, pool, org, cluster, now.Add(-time.Minute), now.Add(time.Hour), map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if read()["live"] != "present" {
		t.Fatal("old snapshot replaced current")
	}
	if err := StoreWorkloads(ctx, pool, other, cluster, now, now.Add(time.Hour), states); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cluster_workload_presence WHERE org_id=$1`, other).Scan(&n); err != nil || n != 0 {
		t.Fatal("cross-tenant snapshot accepted", err)
	}
	exec(`UPDATE cluster_workload_presence SET observed_at=NOW()-INTERVAL '2 hours',expires_at=NOW()-INTERVAL '1 hour' WHERE org_id=$1`, org)
	for _, state := range read() {
		if state != "unverified" {
			t.Fatal("stale snapshot claimed absence")
		}
	}
}
