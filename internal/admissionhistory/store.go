// Package admissionhistory owns bounded maintenance of explicit dry-run history.
package admissionhistory

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

// ClearBatchLimit bounds a single operator request, including its row locks.
const ClearBatchLimit = 1000

type ClearRequest struct {
	OrgID     uuid.UUID
	ClusterID *uuid.UUID
	ActorID   uuid.UUID
	ActorIP   net.IP
	RequestID string
}

// Clear removes at most one batch of explicitly requested operator history.
// It is not automatic age-based retention. The audit receipt commits with the
// deletion; an unavailable audit writer leaves the history intact.
func Clear(ctx context.Context, pool *pgxpool.Pool, req ClearRequest) (int64, error) {
	if req.OrgID == uuid.Nil || req.ActorID == uuid.Nil || req.ClusterID != nil && *req.ClusterID == uuid.Nil {
		return 0, errors.New("organization, actor and optional nonzero cluster required")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	tag, err := tx.Exec(ctx, `WITH candidates AS (
 SELECT id FROM admission_dry_run_history WHERE org_id=$1 AND ($2::uuid IS NULL OR cluster_id=$2)
 ORDER BY assessed_at DESC,id DESC LIMIT $3 FOR UPDATE SKIP LOCKED
 ) DELETE FROM admission_dry_run_history h USING candidates c WHERE h.id=c.id`, req.OrgID, req.ClusterID, ClearBatchLimit)
	if err != nil {
		return 0, err
	}
	deleted := tag.RowsAffected()
	cluster, target := "", "all"
	if req.ClusterID != nil {
		cluster = req.ClusterID.String()
		target = cluster
	}
	_, _, err = audit.New(pool).LogInTx(ctx, tx, audit.Event{OrgID: &req.OrgID, ActorID: &req.ActorID, ActorIP: req.ActorIP, RequestID: req.RequestID,
		Action: "admission.dry-run.clear", TargetKind: "admission-dry-run-history", TargetID: target,
		After: map[string]any{"cluster_id": cluster, "deleted": deleted, "batch_limit": ClearBatchLimit},
	})
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return deleted, nil
}
