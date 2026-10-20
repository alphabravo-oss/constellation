package telemetry

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// PgxTracer returns the composite ConnConfig.Tracer the guide prescribes
// (ch.02/05): otelpgx emits a span per query under the request span; the
// DBQueryTracer records the RED metrics for the database dependency. Wire it
// before the pool is constructed:
//
//	db.Connect(ctx, url, db.WithTracer(tel.PgxTracer()))
func (t *Telemetry) PgxTracer() pgx.QueryTracer {
	t.dbTracerOnce.Do(func() { t.dbTracer = NewDBQueryTracer(t.Registry) })
	return NewCompositeTracer(
		otelpgx.NewTracer(otelpgx.WithDisableConnectionDetailsInAttributes()),
		t.dbTracer,
	)
}

// ObservePool registers a collector that samples pgxpool.Stat on every scrape
// (USE saturation signals for the dependency): db_pool_{total,idle,acquired,
// constructing,max}_conns and the acquire counters.
func (t *Telemetry) ObservePool(pool *pgxpool.Pool) {
	t.Registry.MustRegister(NewPoolStatsCollector(pool))
}

// NewCompositeTracer fans every pgx trace hook out to each tracer in order.
func NewCompositeTracer(tracers ...pgx.QueryTracer) pgx.QueryTracer {
	return &compositeTracer{tracers: tracers}
}

type compositeTracer struct{ tracers []pgx.QueryTracer }

func (c *compositeTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	for _, t := range c.tracers {
		ctx = t.TraceQueryStart(ctx, conn, data)
	}
	return ctx
}

func (c *compositeTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	for i := len(c.tracers) - 1; i >= 0; i-- {
		c.tracers[i].TraceQueryEnd(ctx, conn, data)
	}
}

// DBQueryTracer records db_query_duration_seconds and db_queries_total,
// labelled by the SQL verb (bounded cardinality) and outcome.
type DBQueryTracer struct {
	duration *prometheus.HistogramVec
	total    *prometheus.CounterVec
}

// NewDBQueryTracer registers the two metric families on reg (nil = none).
func NewDBQueryTracer(reg prometheus.Registerer) *DBQueryTracer {
	d := &DBQueryTracer{
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Postgres query duration in seconds by SQL operation.",
			Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"operation"}),
		total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "db_queries_total",
			Help: "Postgres queries by SQL operation and outcome (ok|error).",
		}, []string{"operation", "status"}),
	}
	if reg != nil {
		reg.MustRegister(d.duration, d.total)
	}
	return d
}

type dbQueryKey struct{}

type dbQueryStart struct {
	at time.Time
	op string
}

func (d *DBQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, dbQueryKey{}, dbQueryStart{at: time.Now(), op: sqlOperation(data.SQL)})
}

func (d *DBQueryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	start, ok := ctx.Value(dbQueryKey{}).(dbQueryStart)
	if !ok {
		return
	}
	status := "ok"
	if data.Err != nil {
		status = "error"
	}
	d.duration.WithLabelValues(start.op).Observe(time.Since(start.at).Seconds())
	d.total.WithLabelValues(start.op, status).Inc()
}

// sqlOperation maps the leading SQL keyword to a bounded label set.
func sqlOperation(sql string) string {
	sql = strings.TrimSpace(sql)
	for strings.HasPrefix(sql, "--") || strings.HasPrefix(sql, "/*") {
		if strings.HasPrefix(sql, "--") {
			_, rest, ok := strings.Cut(sql, "\n")
			if !ok {
				return "other"
			}
			sql = strings.TrimSpace(rest)
			continue
		}
		_, rest, ok := strings.Cut(sql, "*/")
		if !ok {
			return "other"
		}
		sql = strings.TrimSpace(rest)
	}
	word := sql
	if i := strings.IndexAny(sql, " \t\r\n("); i > 0 {
		word = sql[:i]
	}
	switch strings.ToLower(word) {
	case "select", "insert", "update", "delete", "with", "begin", "commit", "rollback", "copy", "create", "alter", "drop", "truncate", "listen", "notify":
		return strings.ToLower(word)
	default:
		return "other"
	}
}

// PoolStatsCollector exposes pgxpool.Stat as Prometheus metrics.
type PoolStatsCollector struct {
	pool  *pgxpool.Pool
	descs map[string]*prometheus.Desc
	mu    sync.Mutex
}

// NewPoolStatsCollector builds a collector for one pool.
func NewPoolStatsCollector(pool *pgxpool.Pool) *PoolStatsCollector {
	mk := func(name, help string) *prometheus.Desc { return prometheus.NewDesc(name, help, nil, nil) }
	return &PoolStatsCollector{pool: pool, descs: map[string]*prometheus.Desc{
		"total":        mk("db_pool_total_conns", "Total connections in the pool (idle + acquired + constructing)."),
		"idle":         mk("db_pool_idle_conns", "Idle connections in the pool."),
		"acquired":     mk("db_pool_acquired_conns", "Connections currently acquired by callers."),
		"constructing": mk("db_pool_constructing_conns", "Connections being established."),
		"max":          mk("db_pool_max_conns", "Configured maximum pool size."),
		"acquires":     mk("db_pool_acquire_total", "Successful acquires since the pool was created."),
		"empty":        mk("db_pool_empty_acquire_total", "Acquires that had to wait for a connection."),
		"canceled":     mk("db_pool_canceled_acquire_total", "Acquires canceled by context."),
		"acquire_dur":  mk("db_pool_acquire_duration_seconds_total", "Cumulative time spent waiting in Acquire."),
		"max_lifetime": mk("db_pool_max_lifetime_destroy_total", "Connections closed for exceeding MaxConnLifetime."),
		"max_idle":     mk("db_pool_max_idle_destroy_total", "Connections closed for exceeding MaxConnIdleTime."),
	}}
}

func (c *PoolStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs {
		ch <- d
	}
}

func (c *PoolStatsCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.pool.Stat()
	g := func(k string, v float64) { ch <- prometheus.MustNewConstMetric(c.descs[k], prometheus.GaugeValue, v) }
	cnt := func(k string, v float64) { ch <- prometheus.MustNewConstMetric(c.descs[k], prometheus.CounterValue, v) }
	g("total", float64(s.TotalConns()))
	g("idle", float64(s.IdleConns()))
	g("acquired", float64(s.AcquiredConns()))
	g("constructing", float64(s.ConstructingConns()))
	g("max", float64(s.MaxConns()))
	cnt("acquires", float64(s.AcquireCount()))
	cnt("empty", float64(s.EmptyAcquireCount()))
	cnt("canceled", float64(s.CanceledAcquireCount()))
	cnt("acquire_dur", s.AcquireDuration().Seconds())
	cnt("max_lifetime", float64(s.MaxLifetimeDestroyCount()))
	cnt("max_idle", float64(s.MaxIdleDestroyCount()))
}
