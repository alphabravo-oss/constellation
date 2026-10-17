package handler

import (
	"context"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
)

func TestEventsRetentionPartitionIdentityAndLocks(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := pgfixture.Schema(t, database.Pool())
	pgfixture.PartitionCollision(t, pool, "events")
	ctx := context.Background()
	lock, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(ctx)
	if _, err := lock.Exec(ctx, "SELECT id FROM events WHERE id=1 FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	n, err := pruneEventsOnce(ctx, pool, 24*time.Hour, 1)
	if err != nil || n != 1 {
		t.Fatalf("prune unlocked expired row: n=%d err=%v", n, err)
	}
	var ids []int64
	if err := pool.QueryRow(ctx, "SELECT array_agg(id ORDER BY id) FROM events").Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 3 {
		t.Fatalf("locked and current rows must survive: %v", ids)
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	n, err = pruneEventsOnce(ctx, pool, 24*time.Hour, 1)
	if err != nil || n != 1 {
		t.Fatalf("prune expired ctid twin: n=%d err=%v", n, err)
	}
	if err := pool.QueryRow(ctx, "SELECT array_agg(id ORDER BY id) FROM events").Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != 3 {
		t.Fatalf("current row lost: %v", ids)
	}
	for _, horizon := range []time.Duration{0, -time.Hour} {
		if n, err := pruneEventsOnce(ctx, pool, horizon, 1); err != nil || n != 0 {
			t.Fatalf("disabled prune: n=%d err=%v", n, err)
		}
	}
}
