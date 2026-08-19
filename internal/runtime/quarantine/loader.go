// Package quarantine wires the pkg/quarantine.Loader interface to the
// Postgres-backed quarantine_entries table. Lives under internal/runtime
// because it depends on the project's db wrapper; tests in the pure
// pkg/quarantine package use a fake loader.
package quarantine

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	pkgquar "github.com/alphabravocompany/constellation/pkg/quarantine"
)

// PgLoader satisfies pkg/quarantine.Loader against a Postgres pool.
type PgLoader struct {
	Pool *pgxpool.Pool
}

// Load returns every active (un-lifted, un-expired) quarantine entry for
// the given cluster. The query is sargable on the idx_quarantine_active
// partial index from migration 047.
func (l *PgLoader) Load(ctx context.Context, clusterID uuid.UUID) ([]pkgquar.Entry, error) {
	if l.Pool == nil {
		return nil, fmt.Errorf("quarantine: pool is nil")
	}
	rows, err := l.Pool.Query(ctx, `
SELECT id, org_id, cluster_id, scope, match_key, reason, origin,
       COALESCE(source_kind, ''), source_id, created_at, expires_at
  FROM quarantine_entries
 WHERE cluster_id = $1
   AND lifted_at IS NULL
   AND (expires_at IS NULL OR expires_at > NOW())`, clusterID)
	if err != nil {
		return nil, fmt.Errorf("quarantine: query: %w", err)
	}
	defer rows.Close()
	out := make([]pkgquar.Entry, 0, 32)
	for rows.Next() {
		var e pkgquar.Entry
		var scope, origin, sourceKind string
		if err := rows.Scan(&e.ID, &e.OrgID, &e.ClusterID, &scope, &e.MatchKey,
			&e.Reason, &origin, &sourceKind, &e.SourceID, &e.CreatedAt, &e.ExpiresAt); err != nil {
			return nil, fmt.Errorf("quarantine: scan: %w", err)
		}
		e.Scope = pkgquar.Scope(scope)
		e.Origin = origin
		e.SourceKind = sourceKind
		out = append(out, e)
	}
	return out, rows.Err()
}
