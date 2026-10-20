package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Hold a session lock during fetch and write so multiple API replicas cannot
// commit an older snapshot after a newer one. No transaction is open during
// network I/O. Use this same connection for writes, including with MaxConns=1.
// A database restart releases the lock; transactional checkpoints make retry safe.
func withCVEImportConnection(ctx context.Context, pool *pgxpool.Pool, run func(*pgxpool.Conn) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(1735292486, 1)`).Scan(&acquired); err != nil {
		return err
	}
	if !acquired {
		return nil // Another replica owns this cycle; next scheduled sync retries.
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		var unlocked bool
		if err := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock(1735292486, 1)`).Scan(&unlocked); err != nil || !unlocked {
			// Never put a still-locked session back in the shared pool.
			_ = conn.Conn().Close(cleanup)
		}
	}()
	return run(conn)
}

func rollbackCVEImport(parent context.Context, tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// Length framing separates URLs/payloads unambiguously. Store hashes rather than
// URLs, which may contain offline-mirror credentials.
func cveFeedHash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = fmt.Fprintf(h, "%d:", len(part))
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}
