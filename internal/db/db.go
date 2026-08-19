package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgxpool.Pool. Mirrors astronomer's pattern for consistency.
type DB struct {
	pool *pgxpool.Pool
}

// Connect opens a configured connection pool and pings the database.
func Connect(ctx context.Context, databaseURL string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing database URL: %w", err)
	}

	cfg.MaxConns = 25
	cfg.MinConns = 5
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return &DB{pool: pool}, nil
}

// NewFromPool wraps an already-constructed pool. Useful for tests and for callers
// that build a lazily-connected pool (e.g. the OpenAPI router-introspection gate,
// which only needs the router shape and never executes a query).
func NewFromPool(pool *pgxpool.Pool) *DB { return &DB{pool: pool} }

// Close closes the underlying connection pool.
func (d *DB) Close() { d.pool.Close() }

// Pool returns the underlying pgxpool.Pool.
func (d *DB) Pool() *pgxpool.Pool { return d.pool }

// Health pings the database and returns an error if unreachable.
func (d *DB) Health(ctx context.Context) error { return d.pool.Ping(ctx) }
