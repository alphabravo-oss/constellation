//go:build integration

package flowrollup

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }
func retentionExec(t *testing.T, pool *pgxpool.Pool, q string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), q, args...); err != nil {
		t.Fatal(err)
	}
}
func TestRollupExpiryHoldsBoundaryBatchAndLateIngest(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	ctx := t.Context()
	retentionExec(t, pool, `INSERT INTO system_config(org_id,config) SELECT id,'{"network_rollup_retention_days":2}'::jsonb FROM orgs ON CONFLICT(org_id) DO UPDATE SET config=EXCLUDED.config`)
	var org, cluster uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT org_id,id FROM clusters LIMIT 1`).Scan(&org, &cluster); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Hour)
	boundary := now.Add(-48 * time.Hour)
	retentionExec(t, pool, `UPDATE network_flow_rollup_state SET watermark=$1,raw_pruned_before=$2`, now, now.Add(-24*time.Hour))
	retentionExec(t, pool, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,bucket,max_at,flow_count,sum_bytes)
 VALUES($1,$2,'expiry/a','expiry/b','tcp',$3,$3,7,70),($1,$2,'expiry/c','expiry/d','tcp',$4,$4,11,110),($1,$2,'expiry/e','expiry/f','tcp',$5,$5,13,130)`, org, cluster, boundary.Add(-time.Hour), boundary.Add(-time.Hour), boundary)
	// Any tenant's zero holds the whole shared family.
	retentionExec(t, pool, `UPDATE system_config SET config='{"network_rollup_retention_days":0}'`)
	if n, err := Prune(ctx, pool, 1); err != nil || n != 0 {
		t.Fatalf("hold: %d %v", n, err)
	}
	retentionExec(t, pool, `UPDATE system_config SET config='{"network_rollup_retention_days":2}'`)
	for i := 0; i < 2; i++ {
		if n, err := Prune(ctx, pool, 1); err != nil || n != 1 {
			t.Fatalf("batch: %d %v", n, err)
		}
	}
	got, err := AvailableFrom(ctx, pool)
	if err != nil || !got.Equal(boundary) {
		t.Fatalf("boundary %v %v", got, err)
	}
	var count, bytes int64
	if err := pool.QueryRow(ctx, `SELECT flow_count,sum_bytes FROM network_flow_rollups WHERE org_id=$1 AND src_workload='expiry/e'`, org).Scan(&count, &bytes); err != nil || count != 13 || bytes != 130 {
		t.Fatalf("retained count changed %d %d %v", count, bytes, err)
	}
	// A late raw event cannot recreate an expired aggregate.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	watermark, _, err := Lock(ctx, tx, false)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO network_flows(id,org_id,cluster_id,src_workload,dst_workload,protocol,at,bytes) VALUES($1,$2,$3,'expiry/late','expiry/b','tcp',$4,100)`, id, org, cluster, boundary.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := FoldLate(ctx, tx, []uuid.UUID{id}, watermark); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var expired int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM network_flow_rollups WHERE bucket<$1`, boundary).Scan(&expired); err != nil || expired != 0 {
		t.Fatalf("expired bucket recreated %d %v", expired, err)
	}
	// Increasing retention never claims already-expired history is recoverable.
	retentionExec(t, pool, `UPDATE system_config SET config='{"network_rollup_retention_days":90}'`)
	if _, err := Prune(ctx, pool, 1); err != nil {
		t.Fatal(err)
	}
	got, err = AvailableFrom(ctx, pool)
	if err != nil || !got.Equal(boundary) {
		t.Fatal("boundary regressed")
	}
}
func TestRollupExpiryWaitsForRawBoundary(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	retentionExec(t, pool, `INSERT INTO system_config(org_id,config) SELECT id,'{"network_rollup_retention_days":1}'::jsonb FROM orgs ON CONFLICT(org_id) DO UPDATE SET config=EXCLUDED.config`)
	raw := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Hour)
	retentionExec(t, pool, `UPDATE network_flow_rollup_state SET raw_pruned_before=$1`, raw)
	if _, err := Prune(t.Context(), pool, 1); err != nil {
		t.Fatal(err)
	}
	got, err := AvailableFrom(t.Context(), pool)
	if err != nil || !got.Equal(raw) {
		t.Fatalf("passed raw boundary %v %v", got, err)
	}
	retentionExec(t, pool, `UPDATE system_config SET config='{"network_rollup_retention_days":-1}'`)
	if _, err := Prune(t.Context(), pool, 1); err == nil {
		t.Fatal("invalid policy accepted")
	}
}

func TestNeverPrunedHistoryDoesNotInventEpochCutoff(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	retentionExec(t, pool, `UPDATE network_flow_rollup_state SET raw_pruned_before='1970-01-01'`)
	var org, cluster uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT org_id,id FROM clusters LIMIT 1`).Scan(&org, &cluster); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	watermark, _, err := Lock(t.Context(), tx, false)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := tx.Exec(t.Context(), `INSERT INTO network_flows(id,org_id,cluster_id,src_workload,dst_workload,protocol,at,bytes) VALUES($1,$2,$3,'pre-epoch/a','pre-epoch/b','tcp','1969-12-31T23:00:00Z',42)`, id, org, cluster); err != nil {
		t.Fatal(err)
	}
	if err := FoldLate(t.Context(), tx, []uuid.UUID{id}, watermark); err != nil {
		t.Fatal(err)
	}
	var bytes int64
	if err := tx.QueryRow(t.Context(), `SELECT sum_bytes FROM network_flow_rollups WHERE org_id=$1 AND src_workload='pre-epoch/a'`, org).Scan(&bytes); err != nil || bytes != 42 {
		t.Fatalf("unexpired observation lost: %d %v", bytes, err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	retentionExec(t, pool, `INSERT INTO system_config(org_id,config) SELECT id,'{"network_rollup_retention_days":1}'::jsonb FROM orgs ON CONFLICT(org_id) DO UPDATE SET config=EXCLUDED.config`)
	if n, err := Prune(t.Context(), pool, 1); err != nil || n != 0 {
		t.Fatalf("unproven raw expiry: %d %v", n, err)
	}
	boundary, err := AvailableFrom(t.Context(), pool)
	if err != nil || !boundary.IsZero() {
		t.Fatalf("invented raw expiry boundary: %v %v", boundary, err)
	}
}
