//go:build integration

package findings

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func checkpointPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	d := openTestDB(t)
	schema := "feed_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := d.Pool().Exec(t.Context(), `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.cve_records (LIKE public.cve_records INCLUDING ALL); CREATE TABLE `+schema+`.cve_feed_checkpoints (LIKE public.cve_feed_checkpoints INCLUDING ALL)`); err != nil {
		d.Close()
		t.Fatal(err)
	}
	cfg := d.Pool().Config().Copy()
	cfg.MaxConns = 1 // Import must never acquire a second pool connection.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, err := d.Pool().Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		d.Close()
		if err != nil {
			t.Error(err)
		}
	})
	return pool
}

func checkpointVersion(t *testing.T, pool *pgxpool.Pool, feed string) string {
	t.Helper()
	var version string
	if err := pool.QueryRow(t.Context(), `SELECT xmin::text FROM cve_feed_checkpoints WHERE feed=$1`, feed).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func TestCVEFeedCheckpointRestartCorrectionAndRollback(t *testing.T) {
	t.Parallel()
	pool := checkpointPool(t)
	var probability atomic.Value
	probability.Store("0.10")
	var invalid atomic.Bool
	server := httptest.NewServer(cveSnapshotFixture(&probability, &invalid))
	defer server.Close()
	cfg := CVEIntelConfig{KEVURL: server.URL + "/kev", EPSSURL: server.URL + "/epss", Client: server.Client()}
	n, marker, err := ImportCVEIntel(t.Context(), pool, cfg)
	if err != nil || n != 1200 {
		t.Fatalf("initial import: %d %v", n, err)
	}
	first := checkpointVersion(t, pool, "kev-epss")
	measureUnconditionalCVEReplay(t, pool)
	assertUnchangedCVEReplay(t, pool, cfg, marker, first)
	// Upstreams sometimes correct content without changing version/date labels.
	probability.Store("0.25")
	if n, _, err := ImportCVEIntel(t.Context(), pool, cfg); err != nil || n != 1200 {
		t.Fatalf("same-marker correction: %d %v", n, err)
	}
	corrected := checkpointVersion(t, pool, "kev-epss")
	if corrected == first {
		t.Fatal("corrected content not checkpointed")
	}
	invalid.Store(true)
	if _, _, err := ImportCVEIntel(t.Context(), pool, cfg); err == nil {
		t.Fatal("invalid feed accepted")
	}
	if checkpointVersion(t, pool, "kev-epss") != corrected {
		t.Fatal("failed feed advanced checkpoint")
	}
	invalid.Store(false)
	// Force failure after all CVE batches, proving data + marker commit together.
	_, err = pool.Exec(t.Context(), `CREATE FUNCTION fail_feed_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test checkpoint failure'; END $$; CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON cve_feed_checkpoints FOR EACH ROW EXECUTE FUNCTION fail_feed_checkpoint()`)
	if err != nil {
		t.Fatal(err)
	}
	probability.Store("0.75")
	if _, _, err := ImportCVEIntel(t.Context(), pool, cfg); err == nil {
		t.Fatal("checkpoint failure not propagated")
	}
	var score float64
	if err := pool.QueryRow(t.Context(), `SELECT epss_probability FROM cve_records WHERE cve_id='CVE-2026-10001'`).Scan(&score); err != nil {
		t.Fatal(err)
	}
	if score != 0.25 || checkpointVersion(t, pool, "kev-epss") != corrected {
		t.Fatal("partial feed escaped failed transaction")
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER fail_checkpoint ON cve_feed_checkpoints`); err != nil {
		t.Fatal(err)
	}
	if n, _, err := ImportCVEIntel(t.Context(), pool, cfg); err != nil || n != 1200 {
		t.Fatalf("retry after failure: %d %v", n, err)
	}
	// Source changes must not reuse a different mirror's checkpoint.
	cfg.EPSSURL += "?mirror=2"
	if n, _, err := ImportCVEIntel(t.Context(), pool, cfg); err != nil || n != 1200 {
		t.Fatalf("source change: %d %v", n, err)
	}
}

func TestCVEFeedReplicaLockAndCancellation(t *testing.T) {
	t.Parallel()
	pool := checkpointPool(t)
	other, err := pgxpool.NewWithConfig(t.Context(), pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var fetched atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fetched.Add(1); http.Error(w, "unexpected", 500) }))
	defer server.Close()
	err = withCVEImportConnection(t.Context(), other, func(*pgxpool.Conn) error {
		n, _, err := ImportCVEIntel(t.Context(), pool, CVEIntelConfig{KEVURL: server.URL, EPSSURL: server.URL})
		if err != nil || n != 0 || fetched.Load() != 0 {
			t.Fatalf("competing replica fetched feed: %d %v", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	err = withCVEImportConnection(ctx, pool, func(*pgxpool.Conn) error { cancel(); return ctx.Err() })
	if err == nil {
		t.Fatal("cancellation lost")
	}
	// Canceled imports must release session locks before returning to pool.
	ran := false
	err = withCVEImportConnection(t.Context(), other, func(*pgxpool.Conn) error { ran = true; return nil })
	if err != nil || !ran {
		t.Fatalf("lock leaked after cancellation: %v", err)
	}
}

func TestNVDCheckpointResumeAndIncompleteWindow(t *testing.T) {
	t.Parallel()
	pool := checkpointPool(t)
	var failSecond atomic.Bool
	failSecond.Store(true)
	var observedStart atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedStart.Store(r.URL.Query().Get("lastModStartDate"))
		if r.URL.Query().Get("startIndex") == "0" {
			_, _ = fmt.Fprint(w, `{"resultsPerPage":1,"startIndex":0,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2026-20001","published":"2026-01-01T12:00:00.000","lastModified":"2026-10-11T12:00:00.000","descriptions":[{"lang":"en","value":"first"}]}}]}`)
			return
		}
		if failSecond.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprint(w, `{"resultsPerPage":1,"startIndex":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2026-20002","descriptions":[{"lang":"en","value":"second"}]}}]}`)
	}))
	defer server.Close()
	cfg := nvdConfig{BaseURL: server.URL, Client: server.Client(), APIKey: "fixture"}
	through := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Millisecond)
	if _, err := pool.Exec(t.Context(), `INSERT INTO cve_feed_checkpoints(feed,source_hash,completed_through,row_count) VALUES('nvd',$1,$2,0)`, cveFeedHash(cfg.base()), through); err != nil {
		t.Fatal(err)
	}
	prior := checkpointVersion(t, pool, "nvd")
	if n, err := ImportNVD(t.Context(), pool, cfg, nil); err == nil || n != 1 {
		t.Fatalf("partial page: %d %v", n, err)
	}
	if checkpointVersion(t, pool, "nvd") != prior {
		t.Fatal("incomplete window advanced cursor")
	}
	if observedStart.Load().(string) != through.Add(-2*time.Hour).Format("2006-01-02T15:04:05.000Z") {
		t.Fatal("did not resume overlapping persisted window")
	}
	failSecond.Store(false)
	if n, err := ImportNVD(t.Context(), pool, cfg, nil); err != nil || n != 2 {
		t.Fatalf("retry window: %d %v", n, err)
	}
	if checkpointVersion(t, pool, "nvd") == prior {
		t.Fatal("completed window did not advance")
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM cve_records`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("replay duplicated rows: %d %v", count, err)
	}
	var published time.Time
	if err := pool.QueryRow(t.Context(), `SELECT published_at FROM cve_records WHERE cve_id='CVE-2026-20001'`).Scan(&published); err != nil {
		t.Fatal(err)
	}
	if published.Year() != 2026 {
		t.Fatal("NVD zone-less UTC timestamp lost")
	}
	// Page caps must return failure, never a successful incomplete checkpoint.
	conn, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	pages := nvdMaxPages
	_, err = importNVDWindow(t.Context(), conn, cfg, cveFeedHash(cfg.base()), through, time.Now(), &pages)
	conn.Release()
	if err == nil {
		t.Fatal("exhausted page budget accepted")
	}
}

func TestCVEFeedRejectsInvalidSnapshots(t *testing.T) {
	t.Parallel()
	for _, feed := range []string{"", "{}", `{"catalogVersion":"v","count":2,"vulnerabilities":[]}`} {
		if _, err := parseKEV([]byte(feed)); err == nil {
			t.Fatalf("invalid KEV accepted: %q", feed)
		}
	}
	for _, row := range []string{"CVE-2026-1,NaN,0.1", "CVE-2026-1,1.2,0.1", "CVE-2026-1,0.2,bad", "broken"} {
		if _, _, err := parseEPSS(strings.NewReader("#score_date:2026-10-12\ncve,epss,percentile\n" + row)); err == nil {
			t.Fatalf("invalid EPSS accepted: %q", row)
		}
	}
	for _, feed := range []string{`{}`, `{"vulnerabilities":[]}`, `{"resultsPerPage":null,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`, `{"resultsPerPage":1,"startIndex":0,"totalResults":0,"vulnerabilities":[{"cve":{"id":"CVE-2026-1"}}]}`} {
		if _, _, err := parseNVDPage([]byte(feed)); err == nil {
			t.Fatalf("invalid NVD accepted: %q", feed)
		}
	}
}

func TestNVDCheckpointCatchesUpOldWindowsAndResetsForMirror(t *testing.T) {
	t.Parallel()
	pool := checkpointPool(t)
	var ranges [][2]time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, e1 := time.Parse(time.RFC3339Nano, r.URL.Query().Get("lastModStartDate"))
		end, e2 := time.Parse(time.RFC3339Nano, r.URL.Query().Get("lastModEndDate"))
		if e1 != nil || e2 != nil {
			http.Error(w, "dates", 400)
			return
		}
		ranges = append(ranges, [2]time.Time{start, end})
		_, _ = fmt.Fprint(w, `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer server.Close()
	cfg := nvdConfig{BaseURL: server.URL, Client: server.Client(), APIKey: "fixture"}
	old := time.Now().UTC().Add(-150 * 24 * time.Hour).Truncate(time.Millisecond)
	if _, err := pool.Exec(t.Context(), `INSERT INTO cve_feed_checkpoints(feed,source_hash,completed_through,row_count) VALUES('nvd',$1,$2,0)`, cveFeedHash(cfg.base()), old); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportNVD(t.Context(), pool, cfg, nil); err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 || !ranges[0][0].Equal(old.Add(-2*time.Hour)) || !ranges[1][0].Equal(ranges[0][1].Add(-2*time.Hour)) {
		t.Fatalf("catch-up skipped a window: %v", ranges)
	}
	for _, window := range ranges {
		if window[1].Sub(window[0]) > 120*24*time.Hour {
			t.Fatal("window exceeds upstream bound")
		}
	}
	cfg.BaseURL += "/different-mirror"
	if _, err := ImportNVD(t.Context(), pool, cfg, nil); err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 3 || ranges[2][1].Sub(ranges[2][0]) != 120*24*time.Hour {
		t.Fatal("new mirror did not start with initial window")
	}
}

func TestNVDFetchRejectsInconsistentPaginationAndRedirects(t *testing.T) {
	for _, body := range []string{
		`{"resultsPerPage":0,"startIndex":5,"totalResults":5,"vulnerabilities":[]}`,
		`{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":""}}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, body) }))
			defer server.Close()
			if _, _, err := fetchNVDPage(t.Context(), nvdConfig{BaseURL: server.URL, Client: server.Client()}, 0, time.Now().Add(-time.Hour), time.Now()); err == nil {
				t.Fatal("malformed page accepted")
			}
		})
	}
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	if _, _, err := fetchNVDPage(t.Context(), nvdConfig{BaseURL: source.URL, Client: source.Client(), APIKey: "fixture"}, 0, time.Now().Add(-time.Hour), time.Now()); err == nil {
		t.Fatal("redirect accepted")
	}
	if leaked.Load() {
		t.Fatal("NVD API key request followed redirect")
	}
}

func measureUnconditionalCVEReplay(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var baselineStart string
	if err := pool.QueryRow(t.Context(), `SELECT pg_current_wal_insert_lsn()::text`).Scan(&baselineStart); err != nil {
		t.Fatal(err)
	}
	// Reproduce the previous unconditional conflict-update cost for comparison.
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE cve_records SET epss_probability=epss_probability`); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	var rewritten int64
	if err := tx.QueryRow(t.Context(), `SELECT pg_stat_get_xact_tuples_updated('cve_records'::regclass)`).Scan(&rewritten); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	var baselineWAL int64
	if err := pool.QueryRow(t.Context(), `SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$1::pg_lsn)::bigint`, baselineStart).Scan(&baselineWAL); err != nil {
		t.Fatal(err)
	}
	if rewritten != 1200 {
		t.Fatalf("unconditional baseline rewrites=%d", rewritten)
	}
	t.Logf("one unconditional 1200-row replay: WAL delta=%d bytes, rewritten tuples=%d", baselineWAL, rewritten)

}
func assertUnchangedCVEReplay(t *testing.T, pool *pgxpool.Pool, cfg CVEIntelConfig, marker, first string) {
	t.Helper()
	var rowVersion, before string
	if err := pool.QueryRow(t.Context(), `SELECT xmin::text FROM cve_records WHERE cve_id='CVE-2026-10001'`).Scan(&rowVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT pg_current_wal_insert_lsn()::text`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// A new pool has no process-local checkpoint state.
	restarted, err := pgxpool.NewWithConfig(t.Context(), pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	for i := 0; i < 3; i++ {
		n, got, err := ImportCVEIntel(t.Context(), restarted, cfg)
		if err != nil || n != 0 || got != marker {
			t.Fatalf("restart replay: %d %q %v", n, got, err)
		}
	}
	var wal int64
	if err := pool.QueryRow(t.Context(), `SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$1::pg_lsn)::bigint`, before).Scan(&wal); err != nil {
		t.Fatal(err)
	}
	t.Logf("three identical 1200-row feed replays: WAL delta=%d bytes (cluster-wide, includes background activity)", wal)
	if checkpointVersion(t, pool, "kev-epss") != first {
		t.Fatal("identical feed rewrote checkpoint")
	}
	var replayVersion string
	if err := pool.QueryRow(t.Context(), `SELECT xmin::text FROM cve_records WHERE cve_id='CVE-2026-10001'`).Scan(&replayVersion); err != nil {
		t.Fatal(err)
	}
	if replayVersion != rowVersion {
		t.Fatal("identical feed rewrote CVE row")
	}

}

func cveSnapshotFixture(probability *atomic.Value, invalid *atomic.Bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kev" {
			_, _ = fmt.Fprint(w, `{"catalogVersion":"fixed-version","count":1,"vulnerabilities":[{"cveID":"CVE-2026-10001","vulnerabilityName":"test"}]}`)
			return
		}
		if invalid.Load() {
			_, _ = fmt.Fprint(w, "not a feed")
			return
		}
		_, _ = fmt.Fprintln(w, "#score_date:2026-10-12T00:00:00+0000\ncve,epss,percentile")
		for i := 0; i < 1200; i++ {
			_, _ = fmt.Fprintf(w, "CVE-2026-%d,%s,0.8\n", 10001+i, probability.Load().(string))
		}
	}
}
