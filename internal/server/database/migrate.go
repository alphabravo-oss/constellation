// Package database owns the embedded goose migration set and the in-process
// runner every binary that needs the schema calls before it serves traffic.
//
// Technology Selection Guide ch.02: migrations are embedded with //go:embed,
// the runner holds a PostgreSQL session-level advisory lock for the duration
// of the run (two API replicas booting at once never race), and a failed
// migration fails the process. The same runner is the migrator the
// integration-test fixture (internal/testutil/pgtest) feeds to pgtestdb, so
// tests exercise exactly the production schema path.
package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// LockID is the pg_advisory_lock key held while migrations run. It is stable
// so every replica of every binary contends on the same lock.
const LockID int64 = 0x636f6e7374656c6c // "constell"

// FS returns the embedded migration set rooted at the migrations directory.
func FS() fs.FS {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err) // embed layout is fixed at build time
	}
	return sub
}

// Result summarises one runner invocation.
type Result struct {
	// Applied lists the versions this process applied, in order. Empty when
	// another replica had already migrated the database.
	Applied []int64
	// Version is the schema version after the run.
	Version int64
	// Duration is wall time including the wait for the advisory lock.
	Duration time.Duration
}

// Count returns the number of migrations in the embedded set (version numbers
// are not contiguous, so this differs from LatestVersion).
func Count() int { return len(names()) }

// LatestVersion returns the highest migration version in the embedded set.
func LatestVersion() int64 {
	var latest int64
	for _, name := range names() {
		if v := versionOf(name); v > latest {
			latest = v
		}
	}
	return latest
}

// Hash returns a digest of every migration file name and body. pgtestdb uses it
// to key its template database; it changes whenever a migration is added or
// edited.
func Hash() (string, error) {
	h := sha256.New()
	for _, name := range names() {
		body, err := fs.ReadFile(FS(), name)
		if err != nil {
			return "", fmt.Errorf("read embedded migration %s: %w", name, err)
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(body)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Migrate applies every pending migration under a session-level advisory
// lock. It is safe to call from several processes at once: all but one block
// on the lock and then find nothing pending.
func Migrate(ctx context.Context, db *sql.DB, logger *slog.Logger) (Result, error) {
	if logger == nil {
		logger = slog.Default()
	}
	start := time.Now()
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(LockID))
	if err != nil {
		return Result{}, fmt.Errorf("migration locker: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, FS(),
		goose.WithSessionLocker(locker),
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return Result{}, fmt.Errorf("migration provider: %w", err)
	}
	results, err := provider.Up(ctx)
	res := Result{Duration: time.Since(start)}
	for _, r := range results {
		if r.Error == nil {
			res.Applied = append(res.Applied, r.Source.Version)
		}
	}
	if err != nil {
		return res, fmt.Errorf("apply migrations (after %d applied): %w", len(res.Applied), err)
	}
	res.Version, err = provider.GetDBVersion(ctx)
	if err != nil {
		return res, fmt.Errorf("read schema version: %w", err)
	}
	res.Duration = time.Since(start)
	logger.Info("database migrated",
		slog.Int("applied", len(res.Applied)),
		slog.Int64("version", res.Version),
		slog.Int64("latest", LatestVersion()),
		slog.Duration("duration", res.Duration))
	return res, nil
}

// MigratePool runs Migrate over an existing pgx pool. Goose speaks
// database/sql, so the pool is adapted through pgx's stdlib bridge; closing the
// adapter does not close the pool.
func MigratePool(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) (Result, error) {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer func() { _ = sqlDB.Close() }()
	return Migrate(ctx, sqlDB, logger)
}

func names() []string {
	entries, err := fs.ReadDir(FS(), ".")
	if err != nil {
		panic(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func versionOf(name string) int64 {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		return 0
	}
	v, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
