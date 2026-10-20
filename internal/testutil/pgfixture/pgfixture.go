// Package pgfixture provides isolated schemas for PostgreSQL regression tests.
package pgfixture

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema creates a schema and pool whose search path contains only that schema.
// Callers supply their test database pool; no production database is discovered.
func Schema(t *testing.T, testPool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	name := "fixture_" + uuid.NewString()[:8]
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := testPool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	cfg := testPool.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// PartitionCollision creates two children with the same physical tuple address,
// plus a second expired row to exercise batch limits and concurrent row locks.
func PartitionCollision(t *testing.T, pool *pgxpool.Pool, parent string) {
	t.Helper()
	ctx := context.Background()
	name := pgx.Identifier{parent}.Sanitize()
	old := pgx.Identifier{parent + "_old"}.Sanitize()
	current := pgx.Identifier{parent + "_current"}.Sanitize()
	_, err := pool.Exec(ctx, "CREATE TABLE "+name+` (id bigint, at timestamptz, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
CREATE TABLE `+old+` PARTITION OF `+name+` FOR VALUES FROM (MINVALUE) TO ('2020-01-01');
CREATE TABLE `+current+` PARTITION OF `+name+` DEFAULT;
INSERT INTO `+name+` VALUES (1, '2000-01-01'), (2, '2000-01-02'), (3, now());`)
	if err != nil {
		t.Fatal(err)
	}
	var collide bool
	if err := pool.QueryRow(ctx, "SELECT a.ctid = b.ctid FROM "+name+" a, "+name+" b WHERE a.id=1 AND b.id=3").Scan(&collide); err != nil || !collide {
		t.Fatalf("fixture must reproduce cross-partition ctid collision: collide=%v err=%v", collide, err)
	}
}
