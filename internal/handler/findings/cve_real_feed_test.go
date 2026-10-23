//go:build integration

package findings

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Opt-in qualification downloads each public feed once, then replays the exact
// bytes from a local server. No application database or network policy changes.
func TestCVERealFeedReplay(t *testing.T) {
	if os.Getenv("CONSTELLATION_TEST_REAL_CVE_FEEDS") != "1" {
		t.Skip("set CONSTELLATION_TEST_REAL_CVE_FEEDS=1 for public-feed qualification")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	pool := checkpointPool(t)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultKEVURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		_ = resp.Body.Close()
		t.Fatalf("KEV HTTP %d", resp.StatusCode)
	}
	kev, err := readCVEFeed(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	epss, err := fetchEPSSBytes(ctx, CVEIntelConfig{EPSSURL: defaultEPSSURL, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kev" {
			_, _ = w.Write(kev)
			return
		}
		_, _ = w.Write(epss)
	}))
	defer mirror.Close()
	cfg := CVEIntelConfig{KEVURL: mirror.URL + "/kev", EPSSURL: mirror.URL + "/epss", Client: mirror.Client()}
	started := time.Now()
	n, marker, err := ImportCVEIntel(ctx, pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n < 100000 {
		t.Fatalf("unexpectedly small real snapshot: %d", n)
	}
	t.Logf("real snapshot imported: %d rows, %s", n, time.Since(started))
	first := checkpointVersion(t, pool, "kev-epss")
	var digest, before string
	// Every tuple version participates, so a rewrite outside a sampled CVE fails.
	const fingerprint = `SELECT md5(string_agg(cve_id||':'||xmin::text,',' ORDER BY cve_id)) FROM cve_records`
	if err := pool.QueryRow(ctx, fingerprint).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_current_wal_insert_lsn()::text`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	restarted, err := pgxpool.NewWithConfig(ctx, pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	for i := 0; i < 3; i++ {
		n, got, err := ImportCVEIntel(ctx, restarted, cfg)
		if err != nil || n != 0 || got != marker {
			t.Fatalf("replay: %d %v", n, err)
		}
	}
	var after string
	var wal int64
	if err := pool.QueryRow(ctx, fingerprint).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if digest != after || checkpointVersion(t, pool, "kev-epss") != first {
		t.Fatal("identical real snapshot rewrote rows/checkpoint")
	}
	if err := pool.QueryRow(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$1::pg_lsn)::bigint`, before).Scan(&wal); err != nil {
		t.Fatal(err)
	}
	t.Logf("three real-feed restart replays: no tuple/checkpoint rewrites; cluster-wide WAL delta %d bytes", wal)
}
