//go:build integration

package audit

import (
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func TestAuditLogInTxSharesCallerTransaction(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	pool := pgtest.Pool(t)
	logger := New(pool)
	orgID := uuid.New()
	for _, commit := range []bool{false, true} {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			t.Fatal(err)
		}
		id, _, err := logger.LogInTx(ctx, tx, Event{OrgID: &orgID, Action: "test.transactional_audit"})
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if commit {
			err = tx.Commit(ctx)
		} else {
			err = tx.Rollback(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_events WHERE id=$1)`, id).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != commit {
			t.Fatalf("audit row exists=%t after commit=%t", exists, commit)
		}
	}
	breakAt, err := VerifyChain(ctx, pool)
	if err != nil || breakAt != nil {
		t.Fatalf("chain broken after caller commit/rollback: break=%v err=%v", breakAt, err)
	}
}

// TestAuditChainIntegration appends a batch of events to a real Postgres and verifies the
// resulting chain in its own fully migrated disposable database.
func TestAuditChainIntegration(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	pool := pgtest.Pool(t)

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
	t.Parallel()
	ctx := t.Context()
	pool := pgtest.Pool(t)

	orgs := []uuid.UUID{uuid.New(), uuid.New()}
	actor := uuid.New()

	const (
		writers      = 16
		perWriter    = 25
		wantTotalMin = writers * perWriter
	)
	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter)
	start := make(chan struct{})
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			logger := New(pool)
			<-start
			for i := 0; i < perWriter; i++ {
				event := Event{OrgID: &orgs[w%len(orgs)], ActorID: &actor,
					Action: "test.concurrent", After: map[string]int{"w": w, "i": i}}
				var err error
				if w%2 == 0 {
					_, _, err = logger.Log(ctx, event)
				} else {
					var tx pgx.Tx
					tx, err = pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
					if err == nil {
						_, _, err = logger.LogInTx(ctx, tx, event)
						if err == nil {
							err = tx.Commit(ctx)
						}
						_ = tx.Rollback(ctx)
					}
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	close(start)
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
