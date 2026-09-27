package handler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPartitionDay(t *testing.T) {
	cases := []struct {
		name    string
		wantOK  bool
		wantDay string // YYYY-MM-DD
	}{
		{"events_20260820", true, "2026-08-20"},
		{"network_flows_20260101", true, "2026-01-01"},
		{"events_p_default", false, ""},        // default partition — never a drop candidate
		{"network_flows_p_default", false, ""}, // default partition
		{"events", false, ""},                  // parent
		{"events_2026082", false, ""},          // 7 digits, not a valid day tag
	}
	for _, c := range cases {
		day, ok := partitionDay(c.name)
		if ok != c.wantOK {
			t.Fatalf("%s: ok=%v want %v", c.name, ok, c.wantOK)
		}
		if ok && day.Format("2006-01-02") != c.wantDay {
			t.Fatalf("%s: day=%s want %s", c.name, day.Format("2006-01-02"), c.wantDay)
		}
	}
}

// The drop rule must only fire when a partition's WHOLE [day, day+1) range is at or
// before the cutoff — a partition covering the cutoff day or any future day must survive.
func TestPartitionExpiryBoundary(t *testing.T) {
	// retention 14 days, "today" = 2026-08-20 → cutoff = 2026-08-06.
	cutoff := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -14)
	expired := func(dayStr string) bool {
		day, _ := time.Parse("2006-01-02", dayStr)
		return !day.AddDate(0, 0, 1).After(cutoff) // same predicate as dropExpiredPartitions
	}
	// day+1 <= cutoff → expired
	if !expired("2026-08-05") { // covers ..08-06 00:00 == cutoff → expired
		t.Fatal("2026-08-05 partition should be expired (upper bound == cutoff)")
	}
	if expired("2026-08-06") { // covers up to 08-07, past cutoff → keep
		t.Fatal("2026-08-06 partition (the cutoff day) must be kept")
	}
	if expired("2026-08-20") {
		t.Fatal("today's partition must never be dropped")
	}
}

func defaultPartitionFixture(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	parent := "pm_reclaim_" + uuid.NewString()[:8]
	child := parent + "_p_default"
	ctx := context.Background()
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s (id uuid NOT NULL DEFAULT gen_random_uuid(), at timestamptz NOT NULL, payload text NOT NULL, PRIMARY KEY (id, at)) PARTITION BY RANGE (at)`, parent)); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s CASCADE`, parent))
	})
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s PARTITION OF %s DEFAULT`, child, parent)); err != nil {
		t.Fatalf("create default: %v", err)
	}
	return pool, parent, child
}

func fillAndDeleteDefaultPartition(t *testing.T, pool *pgxpool.Pool, parent string) int64 {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (at, payload) SELECT now(), repeat(md5(random()::text), 32) FROM generate_series(1, 512)`, parent)); err != nil {
		t.Fatalf("fill default: %v", err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`DELETE FROM %s`, parent)); err != nil {
		t.Fatalf("delete default rows: %v", err)
	}
	var size int64
	if err := pool.QueryRow(ctx, `SELECT pg_total_relation_size($1::regclass)`, parent+"_p_default").Scan(&size); err != nil {
		t.Fatalf("default size: %v", err)
	}
	return size
}

func TestReclaimEmptyDefaultPartition(t *testing.T) {
	pool, parent, child := defaultPartitionFixture(t)
	size := fillAndDeleteDefaultPartition(t, pool, parent)
	ctx := context.Background()
	reclaimed, err := reclaimEmptyDefaultPartition(ctx, pool, parent, size+1)
	if err != nil || reclaimed {
		t.Fatalf("below threshold: reclaimed=%v err=%v", reclaimed, err)
	}
	reclaimed, err = reclaimEmptyDefaultPartition(ctx, pool, parent, size)
	if err != nil || !reclaimed {
		t.Fatalf("empty default: reclaimed=%v err=%v", reclaimed, err)
	}
	var after int64
	if err := pool.QueryRow(ctx, `SELECT pg_total_relation_size($1::regclass)`, child).Scan(&after); err != nil {
		t.Fatalf("size after reclaim: %v", err)
	}
	if after >= size {
		t.Fatalf("TRUNCATE did not reclaim storage: before=%d after=%d", size, after)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (at, payload) VALUES (now(), 'new')`, parent)); err != nil {
		t.Fatalf("insert after reclaim: %v", err)
	}
	reclaimed, err = reclaimEmptyDefaultPartition(ctx, pool, parent, 0)
	if err != nil || reclaimed {
		t.Fatalf("nonempty default must survive: reclaimed=%v err=%v", reclaimed, err)
	}
	var count int
	if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, child)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("row after reclaim: count=%d err=%v", count, err)
	}
}

func TestReclaimDefaultRequiresAttachedDefaultPartition(t *testing.T) {
	pool, parent, child := defaultPartitionFixture(t)
	size := fillAndDeleteDefaultPartition(t, pool, parent)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s DETACH PARTITION %s`, parent, child)); err != nil {
		t.Fatalf("detach default: %v", err)
	}
	reclaimed, err := reclaimEmptyDefaultPartition(ctx, pool, parent, size)
	if err != nil || reclaimed {
		t.Fatalf("detached table must survive: reclaimed=%v err=%v", reclaimed, err)
	}
	var after int64
	if err := pool.QueryRow(ctx, `SELECT pg_total_relation_size($1::regclass)`, child).Scan(&after); err != nil || after != size {
		t.Fatalf("detached table changed: before=%d after=%d err=%v", size, after, err)
	}
}

func TestReclaimDefaultSkipsConcurrentIngestWithoutWaiting(t *testing.T) {
	pool, parent, child := defaultPartitionFixture(t)
	size := fillAndDeleteDefaultPartition(t, pool, parent)
	ctx := context.Background()
	insert, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Rollback(context.Background())
	if _, err := insert.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (at, payload) VALUES (now(), 'in-flight')`, parent)); err != nil {
		t.Fatalf("start ingest: %v", err)
	}
	start := time.Now()
	reclaimed, err := reclaimEmptyDefaultPartition(ctx, pool, parent, size)
	if err != nil || reclaimed {
		t.Fatalf("concurrent ingest: reclaimed=%v err=%v", reclaimed, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("reclaim waited for ingest for %s", elapsed)
	}
	if err := insert.Commit(ctx); err != nil {
		t.Fatalf("commit ingest: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, child)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("ingested row lost: count=%d err=%v", count, err)
	}
}
