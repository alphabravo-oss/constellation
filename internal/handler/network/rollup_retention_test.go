//go:build integration

package network

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/flowrollup"
	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
)

func TestFlowRetentionPartitionIdentityAndBatch(t *testing.T) {
	t.Parallel()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := pgfixture.Schema(t, database.Pool())
	pgfixture.PartitionCollision(t, pool, "network_flows")
	if _, err := pool.Exec(context.Background(), `CREATE TABLE network_flow_rollup_state (id boolean PRIMARY KEY, watermark timestamptz, raw_pruned_before timestamptz);
 INSERT INTO network_flow_rollup_state VALUES (true, now(), '1970-01-01');`); err != nil {
		t.Fatal(err)
	}

	rr := NewRollupRefresher(db.NewFromPool(pool))
	rr.pruneBatch = 1
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		n, err := rr.prune(ctx, 24*time.Hour)
		if err != nil || n != 1 {
			t.Fatalf("bounded prune %d: n=%d err=%v", i, n, err)
		}
	}
	var ids []int64
	if err := pool.QueryRow(ctx, "SELECT array_agg(id ORDER BY id) FROM network_flows").Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != 3 {
		t.Fatalf("current ctid twin lost: %v", ids)
	}
	for _, horizon := range []time.Duration{0, -time.Hour} {
		if n, err := rr.prune(ctx, horizon); err != nil || n != 0 {
			t.Fatalf("disabled prune: n=%d err=%v", n, err)
		}
	}
}

func rollupFixture(t *testing.T) *RollupRefresher {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := pgfixture.Schema(t, database.Pool())
	_, err := pool.Exec(context.Background(), `
CREATE TABLE network_flows (LIKE public.network_flows INCLUDING ALL);
CREATE TABLE network_flow_rollups (LIKE public.network_flow_rollups INCLUDING ALL);
CREATE TABLE network_flow_rollup_state (id boolean PRIMARY KEY, watermark timestamptz, raw_pruned_before timestamptz);
INSERT INTO network_flow_rollup_state VALUES (true, '1970-01-01', '1970-01-01');`)
	if err != nil {
		t.Fatal(err)
	}
	return &RollupRefresher{db: db.NewFromPool(pool), pruneBatch: 100, lag: 0}
}

func insertRollupFlow(t *testing.T, rr *RollupRefresher, at time.Time, late bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	tx, err := rr.db.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	watermark, _, err := flowrollup.Lock(ctx, tx, false)
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO network_flows (org_id,cluster_id,src_workload,dst_workload,protocol,at,bytes)
 VALUES ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','app/a','app/b','tcp',$1,10) RETURNING id`, at).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	if late {
		if err := flowrollup.FoldLate(ctx, tx, []uuid.UUID{id}, watermark); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

func assertRollupTotals(t *testing.T, rr *RollupRefresher, want int64) {
	t.Helper()
	var count, bytes int64
	err := rr.db.Pool().QueryRow(context.Background(), `SELECT COALESCE(sum(flow_count),0),COALESCE(sum(sum_bytes),0) FROM network_flow_rollups`).Scan(&count, &bytes)
	if err != nil || count != want || bytes != 10*want {
		t.Fatalf("totals: count=%d bytes=%d want=%d err=%v", count, bytes, want, err)
	}
}

func TestRollupLateArrivalPruneAndRefoldPreserveHistory(t *testing.T) {
	t.Parallel()
	rr := rollupFixture(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Hour)
	insertRollupFlow(t, rr, old.Add(10*time.Minute), false)
	insertRollupFlow(t, rr, old.Add(50*time.Minute), false)
	if err := rr.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// A request ending in the middle of an hour must retain its later flows.
	if err := rr.RefoldWindow(ctx, old, old.Add(20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertRollupTotals(t, rr, 2)
	insertRollupFlow(t, rr, old.Add(30*time.Minute), true)
	if err := rr.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	assertRollupTotals(t, rr, 3)
	rr.pruneBatch = 1 // even a partially pruned hour is no longer refoldable
	if n, err := rr.prune(ctx, 24*time.Hour); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if err := rr.RefoldWindow(ctx, old, old.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertRollupTotals(t, rr, 3)
	insertRollupFlow(t, rr, old.Add(40*time.Minute), true)
	if err := rr.RefoldWindow(ctx, old, old.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertRollupTotals(t, rr, 4)
}

func TestRollupFailureAndLagBlockRetention(t *testing.T) {
	t.Parallel()
	rr := rollupFixture(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-72 * time.Hour)
	insertRollupFlow(t, rr, old, false)
	if n, err := rr.prune(ctx, 24*time.Hour); err != nil || n != 0 {
		t.Fatalf("unfolded prune: %d %v", n, err)
	}
	// Force aggregation failure after advancing the test watermark, so a mere
	// age/watermark condition would allow deletion if runOnce still continued.
	if _, err := rr.db.Pool().Exec(ctx, `UPDATE network_flow_rollup_state SET watermark=now(); DROP TABLE network_flow_rollups`); err != nil {
		t.Fatal(err)
	}
	rr.retention = 24 * time.Hour
	rr.runOnce(ctx)
	var count int
	if err := rr.db.Pool().QueryRow(ctx, `SELECT count(*) FROM network_flows`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed refresh lost raw flow: count=%d err=%v", count, err)
	}
}

func TestRollupExplicitZeroRetentionOverridesEnvironment(t *testing.T) {
	t.Parallel()
	rr := rollupFixture(t)
	ctx := context.Background()
	insertRollupFlow(t, rr, time.Now().UTC().Add(-72*time.Hour), false)
	rr.retention = 24 * time.Hour
	rr.SetRetentionResolver(func(context.Context) time.Duration { return 0 })
	rr.runOnce(ctx)
	var count int
	if err := rr.db.Pool().QueryRow(ctx, `SELECT count(*) FROM network_flows`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("disabled retention lost raw flow: count=%d err=%v", count, err)
	}
}
