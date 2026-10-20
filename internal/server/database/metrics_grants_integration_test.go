//go:build integration

package database_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

// The app role may lack CREATEROLE (CNPG): migrations must not create roles,
// and the grants land once CNPG has created the metrics role.
func TestMetricsGrantsApplyOnlyWhenRoleExists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.FreshURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := database.MigratePool(ctx, pool, nil); err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer func() { _ = sqlDB.Close() }()
	// Shared server: the role may exist from a parallel test; drop-and-recreate is racy,
	// so create it only if missing and assert the grant afterwards.
	_, _ = pool.Exec(ctx, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'constellation_metrics') THEN CREATE ROLE constellation_metrics NOLOGIN; END IF; END $$`)
	if err := database.EnsureMetricsGrants(ctx, sqlDB); err != nil {
		t.Fatal(err)
	}
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('constellation_metrics', 'component_heartbeats', 'SELECT')
		AND has_table_privilege('constellation_metrics', 'cve_feed_checkpoints', 'SELECT')
		AND NOT has_table_privilege('constellation_metrics', 'users', 'SELECT')`).Scan(&ok); err != nil || !ok {
		t.Fatalf("metrics role grants: ok=%v err=%v", ok, err)
	}
}
