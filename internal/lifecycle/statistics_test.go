//go:build integration

package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
)

func TestPartitionStatisticsRefreshesOnlyOneParentPerPass(t *testing.T) {
	t.Parallel()
	pool := statisticsPool(t)
	pgfixture.PartitionCollision(t, pool, "events")
	pgfixture.PartitionCollision(t, pool, "findings")
	result, err := RefreshPartitionStatistics(t.Context(), pool)
	if err != nil || result.Analyzed != "events" {
		t.Fatalf("oldest parent selection: result=%+v err=%v", result, err)
	}
	var analyzed int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_class
 WHERE relnamespace=current_schema()::regnamespace AND relkind='p' AND reltuples >= 0`).Scan(&analyzed); err != nil || analyzed != 1 {
		t.Fatalf("one pass must analyze only one parent: count=%d err=%v", analyzed, err)
	}
}

func TestPartitionStatisticsRefusesNonOwnerWithoutFalseSuccess(t *testing.T) {
	t.Parallel()
	pool := statisticsPool(t)
	role := "stats_reader_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	roleSQL := pgx.Identifier{role}.Sanitize()
	var schema string
	if err := pool.QueryRow(t.Context(), "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	schemaSQL := pgx.Identifier{schema}.Sanitize()
	execSessionSQL(t, pool, "CREATE ROLE "+roleSQL)
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(), "REVOKE ALL ON SCHEMA "+schemaSQL+" FROM "+roleSQL+"; DROP ROLE "+roleSQL)
		if err != nil {
			t.Error(err)
		}
	})
	execSessionSQL(t, pool, "GRANT USAGE ON SCHEMA "+schemaSQL+" TO "+roleSQL)
	cfg := pool.Config()
	cfg.ConnConfig.RuntimeParams["role"] = role
	reader, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	result, err := RefreshPartitionStatistics(t.Context(), reader)
	if err == nil || !strings.Contains(err.Error(), "ownership") || result.Analyzed != "" {
		t.Fatalf("non-owner refresh must fail: result=%+v err=%v", result, err)
	}
}

func statisticsPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	base := pgtest.Pool(t)
	pool := pgfixture.Schema(t, base)
	pgfixture.PartitionCollision(t, pool, "network_flows")
	return pool
}

func TestPartitionStatisticsRefreshPreservesRowsAndCollectsParentStats(t *testing.T) {
	t.Parallel()
	pool := statisticsPool(t)
	execSessionSQL(t, pool, `CREATE TABLE events (id integer);
 CREATE TABLE unrelated (id integer) PARTITION BY RANGE(id);
 CREATE TABLE unrelated_default PARTITION OF unrelated DEFAULT;
 INSERT INTO unrelated VALUES (1);`)
	result, err := RefreshPartitionStatistics(t.Context(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if result.Analyzed != "network_flows" || result.LastAnalyze["network_flows"].IsZero() {
		t.Fatalf("refresh result: %+v", result)
	}
	var count int
	var estimate float64
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM network_flows`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("data changed: count=%d err=%v", count, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT reltuples FROM pg_class WHERE oid='network_flows'::regclass`).Scan(&estimate); err != nil || estimate != 3 {
		t.Fatalf("parent statistics not populated: estimate=%v err=%v", estimate, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT reltuples FROM pg_class WHERE oid='unrelated'::regclass`).Scan(&estimate); err != nil || estimate != -1 {
		t.Fatalf("unrelated parent was analyzed: estimate=%v err=%v", estimate, err)
	}
}

func TestPartitionStatisticsSkipsFreshParents(t *testing.T) {
	t.Parallel()
	pool := statisticsPool(t)
	execSessionSQL(t, pool, "ANALYZE network_flows; SELECT pg_stat_force_next_flush()")
	result, err := RefreshPartitionStatistics(t.Context(), pool)
	if err != nil || result.Analyzed != "" || result.LastAnalyze["network_flows"].IsZero() {
		t.Fatalf("fresh parent was not skipped: result=%+v err=%v", result, err)
	}
}

func TestPartitionStatisticsSkipsConcurrentMaintainer(t *testing.T) {
	t.Parallel()
	pool := statisticsPool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT pg_advisory_xact_lock($1)", partitionStatisticsLock); err != nil {
		t.Fatal(err)
	}
	result, err := RefreshPartitionStatistics(t.Context(), pool)
	if err != nil || result.Analyzed != "" {
		t.Fatalf("concurrent refresh: result=%+v err=%v", result, err)
	}
}

func TestPartitionStatisticsLockedParentIsNotReportedFresh(t *testing.T) {
	t.Parallel()
	pool := statisticsPool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "LOCK TABLE ONLY network_flows IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result, err := RefreshPartitionStatistics(ctx, pool)
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "55P03" || result.Analyzed != "" || !result.LastAnalyze["network_flows"].IsZero() {
		t.Fatalf("locked parent must fail promptly without success: result=%+v err=%v", result, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err = RefreshPartitionStatistics(t.Context(), pool)
	if err != nil || result.Analyzed != "network_flows" {
		t.Fatalf("retry after unlock: result=%+v err=%v", result, err)
	}
}

func TestPartitionStatisticsRespectsCancellation(t *testing.T) {
	t.Parallel()
	pool := statisticsPool(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := RefreshPartitionStatistics(ctx, pool)
	if !errors.Is(err, context.Canceled) || result.Analyzed != "" {
		t.Fatalf("canceled refresh: result=%+v err=%v", result, err)
	}
}
