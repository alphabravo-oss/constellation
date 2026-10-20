package telemetry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSQLOperationBoundsCardinality(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"SELECT 1":                             "select",
		"  insert into x values (1)":           "insert",
		"-- comment\nUPDATE x SET a=1":         "update",
		"/* c */ DELETE FROM x":                "delete",
		"WITH q AS (SELECT 1) SELECT * FROM q": "with",
		"EXPLAIN SELECT 1":                     "other",
		"":                                     "other",
	}
	for sql, want := range cases {
		t.Run(want+"/"+sql, func(t *testing.T) {
			t.Parallel()
			if got := sqlOperation(sql); got != want {
				t.Fatalf("sqlOperation(%q) = %q, want %q", sql, got, want)
			}
		})
	}
}

func TestDBQueryTracerRecordsDurationAndCount(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	tr := NewDBQueryTracer(reg)
	ctx := tr.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "SELECT 1"})
	tr.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})
	ctx = tr.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "DELETE FROM x"})
	tr.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: context.Canceled})
	if n := testutil.CollectAndCount(tr.total, "db_queries_total"); n != 2 {
		t.Fatalf("db_queries_total series = %d, want 2", n)
	}
	if v := testutil.ToFloat64(tr.total.WithLabelValues("delete", "error")); v != 1 {
		t.Fatalf("delete/error = %v", v)
	}
	if n := testutil.CollectAndCount(tr.duration, "db_query_duration_seconds"); n != 2 {
		t.Fatalf("db_query_duration_seconds series = %d, want 2", n)
	}
}

func TestCompositeTracerChainsContexts(t *testing.T) {
	t.Parallel()
	type k1 struct{}
	type k2 struct{}
	a := ctxTracer{key: k1{}}
	b := ctxTracer{key: k2{}}
	c := NewCompositeTracer(a, b)
	ctx := c.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{})
	if ctx.Value(k1{}) == nil || ctx.Value(k2{}) == nil {
		t.Fatal("composite tracer must thread every tracer's context")
	}
}

type ctxTracer struct{ key any }

func (c ctxTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, c.key, true)
}
func (c ctxTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
