//go:build integration

package telemetry_test

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/alphabravocompany/constellation/internal/telemetry"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func TestDBHealthCollectorPublishesHeartbeatEngineAndFeedAges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool := pgtest.Pool(t)
	var org string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM orgs WHERE name='demo'`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(ctx, `INSERT INTO component_heartbeats (org_id, component, hostname, version, last_seen_at, metadata)
VALUES ($1, 'scanner', 'h1', 'test', now() - interval '90 seconds',
 '{"engine_db": {"trivy": {"applied_revision": "2026-10-18T00:00:00Z", "status": "ready"},
                 "trivy-java-db": {"applied_revision": "2026-08-20T00:00:00Z", "status": "ready"},
                 "grype": {"applied_revision": "2026-10-19T00:00:00Z", "status": "stale"}}}'::jsonb)`, org)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cve_feed_checkpoints (feed, source_hash, row_count, updated_at)
VALUES ('nvd', repeat('a', 64), 42, now() - interval '1 hour')
ON CONFLICT (feed) DO UPDATE SET updated_at = EXCLUDED.updated_at, row_count = EXCLUDED.row_count`); err != nil {
		t.Fatal(err)
	}
	c := telemetry.NewDBHealthCollector(pool, time.Second, nil)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]float64{}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			label := ""
			if len(m.GetLabel()) > 0 {
				label = m.GetLabel()[0].GetValue()
			}
			if got[f.GetName()] == nil {
				got[f.GetName()] = map[string]float64{}
			}
			got[f.GetName()][label] = m.GetGauge().GetValue()
		}
	}
	if v := got["constellation_component_heartbeat_age_seconds"]["scanner"]; v < 85 || v > 200 {
		t.Fatalf("heartbeat age %v", v)
	}
	if v := got["constellation_scanner_engine_db_age_seconds"]["trivy-java-db"]; v < 30*24*3600 {
		t.Fatalf("java-db age must be surfaced as its own engine: %v", v)
	}
	if got["constellation_scanner_engine_db_ready"]["grype"] != 0 || got["constellation_scanner_engine_db_ready"]["trivy"] != 1 {
		t.Fatalf("engine readiness: %v", got["constellation_scanner_engine_db_ready"])
	}
	if v := got["constellation_cve_feed_age_seconds"]["nvd"]; v < 3500 || v > 3700 {
		t.Fatalf("feed age %v", v)
	}
	if n := testutil.CollectAndCount(c); n < 9 {
		t.Fatalf("metrics count %d", n)
	}
	// Cached within TTL: a scrape right after must not re-query (count stays stable).
	if _, err := reg.Gather(); err != nil {
		t.Fatal(err)
	}
}
