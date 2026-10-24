// Package supportretention expires temporary support payloads after their audit
// receipt is durable. Job metadata and permanent receipts are retained.
package supportretention

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ExpirePayloads holds jobs with pending/missing audit receipts, skips row locks,
// and expires at most 100 terminal payloads within a five-second database budget.
func ExpirePayloads(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tag, err := pool.Exec(ctx, `WITH candidate AS (
 SELECT id FROM support_bundle_jobs WHERE status IN ('ready','failed') AND expires_at<=now()
 AND audit_pending IS NULL AND audit_event_id IS NOT NULL
 ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT 100
 ) UPDATE support_bundle_jobs job SET status='expired',payload=NULL,error=NULL,lease_expires_at=NULL
 FROM candidate WHERE job.id=candidate.id`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
