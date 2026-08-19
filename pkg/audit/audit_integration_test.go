//go:build integration

package audit

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAuditChainIntegration appends a batch of events to a real Postgres and verifies the
// resulting chain. Run with:
//
//	DATABASE_URL=postgres://... go test -tags=integration ./pkg/audit/...
//
// Requires the migrations to be applied.
func TestAuditChainIntegration(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	// Clean previous test rows by truncating with a CASCADE — but the table has triggers
	// forbidding DELETE/UPDATE, not TRUNCATE. We use TRUNCATE which bypasses row triggers.
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events RESTART IDENTITY"); err != nil {
		t.Fatalf("truncate (pre): %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE audit_events RESTART IDENTITY")
	}()

	l := New(pool)
	org := uuid.New()
	actor := uuid.New()

	for i := 0; i < 50; i++ {
		if _, _, err := l.Log(ctx, Event{
			OrgID:   &org,
			ActorID: &actor,
			Action:  "test.event",
			After:   map[string]int{"i": i},
		}); err != nil {
			t.Fatalf("log %d: %v", i, err)
		}
	}

	cb, err := VerifyChain(ctx, pool)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cb != nil {
		t.Fatalf("chain broken: %s", cb.Error())
	}

	// Tamper test: a row update is blocked at the trigger layer.
	_, err = pool.Exec(ctx, `UPDATE audit_events SET action = 'tampered' WHERE id = 1`)
	if err == nil {
		t.Fatalf("expected UPDATE to be blocked by trigger")
	}
}

// TestAuditChainConcurrentWritersIntact is the H9 regression: many writers append concurrently
// and the chain must remain intact. Before the advisory-lock fix, two writers that raced on
// `SELECT ... ORDER BY id DESC LIMIT 1 FOR UPDATE` could both read the same head (EvalPlanQual
// re-checks only the locked tuple, not the ORDER BY/LIMIT) and insert divergent prev_hash values,
// producing a false `prev_hash mismatch` in VerifyChain. With the fixed-key pg_advisory_xact_lock
// taken before the head read, every writer queues and reads the genuine committed head.
func TestAuditChainConcurrentWritersIntact(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, "TRUNCATE audit_events RESTART IDENTITY"); err != nil {
		t.Fatalf("truncate (pre): %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE audit_events RESTART IDENTITY")
	}()

	l := New(pool)
	org := uuid.New()
	actor := uuid.New()

	const (
		writers      = 16
		perWriter    = 25
		wantTotalMin = writers * perWriter
	)
	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if _, _, err := l.Log(ctx, Event{
					OrgID:   &org,
					ActorID: &actor,
					Action:  "test.concurrent",
					After:   map[string]int{"w": w, "i": i},
				}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent log: %v", err)
	}

	cb, err := VerifyChain(ctx, pool)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cb != nil {
		t.Fatalf("chain broken under concurrency: %s", cb.Error())
	}

	var n int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != wantTotalMin {
		t.Fatalf("row count = %d, want %d (no lost or duplicated writes)", n, wantTotalMin)
	}
}
