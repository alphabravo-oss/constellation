//go:build integration

package inventorypresence

import (
	"context"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/google/uuid"
)

func TestPresenceScopeFreshnessAndHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool := pgtest.Pool(t)
	org, other, cluster := uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'presence'),($2::uuid,$2::text,'other')`, org, other)
	exec(`INSERT INTO clusters(id,org_id,name,distro) VALUES($1,$2,'presence','k3s')`, cluster, org)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM findings WHERE org_id IN($1,$2)`, org, other)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, other)
	})
	add := func(kind, name, digest, cve string) {
		t.Helper()
		asset := uuid.New()
		exec(`INSERT INTO assets(id,org_id,cluster_id,kind,name,digest) VALUES($1,$2,$3,$4,$5,NULLIF($6,''))`, asset, org, cluster, kind, name, digest)
		exec(`INSERT INTO findings(org_id,cluster_id,asset_id,kind,title,severity,external_id) VALUES($1,$2,$3,'vulnerability','fixture','critical',$4)`, org, cluster, asset, cve)
	}
	add("workload", "ns/pod/live", "", "CVE-A")
	add("workload", "ns/pod/gone", "", "CVE-B")
	add("workload", "ns/pod/done", "", "CVE-C")
	add("image", "sha256:live", "sha256:live", "CVE-A")
	add("image", "sha256:unmapped", "sha256:unmapped", "CVE-D")
	read := func() Counts {
		t.Helper()
		c, e := Read(ctx, pool, org, cluster)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	if c := read(); c.InventoryStatus != "missing" || c.UnverifiedOccurrences != 5 {
		t.Fatalf("missing snapshot: %+v", c)
	}
	now := time.Now().UTC()
	snapshot := Snapshot{Pods: map[string]string{"ns/pod/live": "Running", "ns/pod/done": "Succeeded"}, ImageDigests: map[string]bool{"sha256:live": true}}
	if err := Store(ctx, pool, org, cluster, now, now.Add(time.Hour), snapshot); err != nil {
		t.Fatal(err)
	}
	c := read()
	if c.CurrentCritical != 1 || c.CurrentOccurrences != 2 || c.HistoricalOccurrences != 2 || c.UnverifiedOccurrences != 1 {
		t.Fatalf("fresh classification: %+v", c)
	}
	exec(`UPDATE findings SET last_seen_at=$2 WHERE org_id=$1 AND external_id='CVE-B'`, org, now.Add(time.Minute))
	if c := read(); c.HistoricalOccurrences != 1 || c.UnverifiedOccurrences != 2 {
		t.Fatalf("finding newer than inventory treated as retired: %+v", c)
	}
	exec(`UPDATE findings SET last_seen_at=$2 WHERE org_id=$1 AND external_id='CVE-B'`, org, now.Add(-time.Minute))
	// A late older snapshot must not resurrect historical exposure or replace current inventory.
	if err := Store(ctx, pool, org, cluster, now.Add(-time.Minute), now.Add(time.Hour), Snapshot{Pods: map[string]string{}, ImageDigests: map[string]bool{}}); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.CurrentCritical != 1 {
		t.Fatalf("old snapshot overwrote current: %+v", got)
	}
	if err := Store(ctx, pool, other, cluster, now, now.Add(time.Hour), snapshot); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cluster_inventory_presence WHERE org_id=$1`, other).Scan(&n); err != nil || n != 0 {
		t.Fatalf("cross-tenant snapshot persisted: %d %v", n, err)
	}
	exec(`UPDATE cluster_inventory_presence SET observed_at=NOW()-INTERVAL '2 hours',expires_at=NOW()-INTERVAL '1 hour' WHERE org_id=$1`, org)
	if c := read(); c.InventoryStatus != "stale" || c.UnverifiedOccurrences != 5 || c.HistoricalOccurrences != 0 {
		t.Fatalf("stale snapshot hid findings: %+v", c)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE org_id=$1 AND lifecycle='open'`, org).Scan(&n); err != nil || n != 5 {
		t.Fatalf("history was mutated: %d %v", n, err)
	}
}
