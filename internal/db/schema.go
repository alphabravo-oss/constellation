package db

import (
	"context"
	"fmt"
	"time"
)

// RequiredSchemaVersion is the minimum migration required by this API build.
// The migration inventory test requires updating it with each new migration.
const RequiredSchemaVersion int64 = 195

// RequireSchema fails before server initialization can write to an older schema.
// Goose records both up and down transitions; the latest entry per version wins.
// A newer schema remains compatible with this lower-bound check for rollback of
// additive releases. Destructive schema changes need a separate rollout contract.
func (d *DB) RequireSchema(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var current int64
	err := d.pool.QueryRow(bounded, `SELECT COALESCE(max(version_id),0) FROM (
 SELECT DISTINCT ON (version_id) version_id, is_applied
 FROM goose_db_version ORDER BY version_id, id DESC
) latest WHERE is_applied`).Scan(&current)
	if err != nil {
		return fmt.Errorf("read database schema version (run migrations before starting API): %w", err)
	}
	if current < RequiredSchemaVersion {
		return fmt.Errorf("database schema %d is older than required %d; run migrations before starting API", current, RequiredSchemaVersion)
	}
	return nil
}
