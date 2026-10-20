package telemetry

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// DBHealthCollector publishes the operational signals the runtime stream had
// to reach through a postgres-exporter + read-only role, as first-class API
// metrics: component heartbeat age, scanner engine-DB age/readiness (trivy,
// trivy-java-db, grype) and CVE-feed checkpoint age. The queries run on
// scrape, cached for TTL, so the API port answers from memory under load.
type DBHealthCollector struct {
	pool   *pgxpool.Pool
	ttl    time.Duration
	logger *slog.Logger

	heartbeatAge *prometheus.Desc
	heartbeatRow *prometheus.Desc
	engineAge    *prometheus.Desc
	engineReady  *prometheus.Desc
	feedAge      *prometheus.Desc
	feedRows     *prometheus.Desc
	scrapeErrors prometheus.Counter

	mu       sync.Mutex
	cachedAt time.Time
	cached   []prometheus.Metric
}

// NewDBHealthCollector builds the collector; ttl <= 0 means 15s.
func NewDBHealthCollector(pool *pgxpool.Pool, ttl time.Duration, logger *slog.Logger) *DBHealthCollector {
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DBHealthCollector{
		pool: pool, ttl: ttl, logger: logger,
		heartbeatAge: prometheus.NewDesc("constellation_component_heartbeat_age_seconds", "Seconds since the newest heartbeat row for this component.", []string{"component"}, nil),
		heartbeatRow: prometheus.NewDesc("constellation_component_heartbeat_rows", "Heartbeat rows (one per hostname) for this component.", []string{"component"}, nil),
		engineAge:    prometheus.NewDesc("constellation_scanner_engine_db_age_seconds", "Age of the scanner engine's applied vulnerability DB revision (from the newest scanner heartbeat).", []string{"engine"}, nil),
		engineReady:  prometheus.NewDesc("constellation_scanner_engine_db_ready", "1 when the scanner reports the engine DB as ready.", []string{"engine"}, nil),
		feedAge:      prometheus.NewDesc("constellation_cve_feed_age_seconds", "Seconds since the CVE enrichment feed checkpoint was updated.", []string{"feed"}, nil),
		feedRows:     prometheus.NewDesc("constellation_cve_feed_rows", "Rows imported at the feed's last checkpoint.", []string{"feed"}, nil),
		scrapeErrors: prometheus.NewCounter(prometheus.CounterOpts{Name: "constellation_db_health_scrape_errors_total", Help: "DB health collector query failures."}),
	}
}

// ObserveDBHealth registers the collector on the telemetry registry.
func (t *Telemetry) ObserveDBHealth(pool *pgxpool.Pool, ttl time.Duration) *DBHealthCollector {
	c := NewDBHealthCollector(pool, ttl, t.Logger)
	t.Registry.MustRegister(c)
	return c
}

func (c *DBHealthCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.heartbeatAge
	ch <- c.heartbeatRow
	ch <- c.engineAge
	ch <- c.engineReady
	ch <- c.feedAge
	ch <- c.feedRows
	ch <- c.scrapeErrors.Desc()
}

func (c *DBHealthCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.cachedAt) >= c.ttl {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		metrics, err := c.query(ctx)
		cancel()
		if err != nil {
			c.scrapeErrors.Inc()
			c.logger.Warn("db health metrics", slog.String("err", err.Error()))
		} else {
			c.cached, c.cachedAt = metrics, time.Now()
		}
	}
	for _, m := range c.cached {
		ch <- m
	}
	ch <- c.scrapeErrors
}

const (
	heartbeatSQL = `SELECT component, extract(epoch from now() - max(last_seen_at))::float8, count(*)::float8
FROM component_heartbeats GROUP BY component`
	// engine_db is the scanner heartbeat's per-engine map: {trivy: {applied_revision, status}, "trivy-java-db": {...}, grype: {...}}
	engineSQL = `SELECT e.key,
       extract(epoch from now() - (e.value->>'applied_revision')::timestamptz)::float8,
       (CASE WHEN e.value->>'status' = 'ready' THEN 1 ELSE 0 END)::float8
FROM (SELECT metadata FROM component_heartbeats WHERE component = 'scanner' ORDER BY last_seen_at DESC LIMIT 1) s,
     jsonb_each(s.metadata->'engine_db') e
WHERE e.value->>'applied_revision' IS NOT NULL`
	feedSQL = `SELECT feed, extract(epoch from now() - updated_at)::float8, row_count::float8 FROM cve_feed_checkpoints`
)

func (c *DBHealthCollector) query(ctx context.Context) ([]prometheus.Metric, error) {
	var out []prometheus.Metric
	rows, err := c.pool.Query(ctx, heartbeatSQL)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var component string
		var age, n float64
		if err := rows.Scan(&component, &age, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out,
			prometheus.MustNewConstMetric(c.heartbeatAge, prometheus.GaugeValue, age, component),
			prometheus.MustNewConstMetric(c.heartbeatRow, prometheus.GaugeValue, n, component))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = c.pool.Query(ctx, engineSQL)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var engine string
		var age, ready float64
		if err := rows.Scan(&engine, &age, &ready); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out,
			prometheus.MustNewConstMetric(c.engineAge, prometheus.GaugeValue, age, engine),
			prometheus.MustNewConstMetric(c.engineReady, prometheus.GaugeValue, ready, engine))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = c.pool.Query(ctx, feedSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var feed string
		var age, n float64
		if err := rows.Scan(&feed, &age, &n); err != nil {
			return nil, err
		}
		out = append(out,
			prometheus.MustNewConstMetric(c.feedAge, prometheus.GaugeValue, age, feed),
			prometheus.MustNewConstMetric(c.feedRows, prometheus.GaugeValue, n, feed))
	}
	return out, rows.Err()
}
