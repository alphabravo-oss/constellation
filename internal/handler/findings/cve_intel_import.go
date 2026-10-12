package findings

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Live CVE-intelligence importer: CISA KEV (known-exploited) + FIRST EPSS
// (exploit-probability) straight from their public single-file feeds. This is the
// live replacement for the dropped vulndb bundle as the source of cve_records
// exploitation intel — no bbolt, no bundle upload. NVD base-catalog import (CVE
// descriptions + CVSS) is a syscfg-gated follow-up; until then KEV rows carry the
// vuln name/short description and EPSS rows carry the probability, and the upsert's
// COALESCE lets a later NVD import fill descriptions without clobbering this.
//
// Both feeds are small and cache-friendly. URLs are overridable (offline mirror)
// via CONSTELLATION_KEV_URL / CONSTELLATION_EPSS_URL.

const (
	defaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	defaultEPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
)

// CVEIntelConfig configures the live importer. Zero values fall back to the public
// feeds and a 6h interval.
type CVEIntelConfig struct {
	KEVURL   string
	EPSSURL  string
	Interval time.Duration
	Client   *http.Client
}

func (c CVEIntelConfig) kevURL() string {
	if c.KEVURL != "" {
		return c.KEVURL
	}
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_KEV_URL")); v != "" {
		return v
	}
	return defaultKEVURL
}

func (c CVEIntelConfig) epssURL() string {
	if c.EPSSURL != "" {
		return c.EPSSURL
	}
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_EPSS_URL")); v != "" {
		return v
	}
	return defaultEPSSURL
}

func (c CVEIntelConfig) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

// ---- KEV ----

type kevFeed struct {
	CatalogVersion  string `json:"catalogVersion"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CveID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		ShortDescription  string `json:"shortDescription"`
	} `json:"vulnerabilities"`
}

// parseKEV parses the CISA KEV catalog JSON. Pure so it's unit-testable.
func parseKEV(b []byte) (*kevFeed, error) {
	var f kevFeed
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("kev decode: %w", err)
	}
	if f.CatalogVersion == "" || f.Count != len(f.Vulnerabilities) {
		return nil, fmt.Errorf("kev incomplete catalog")
	}
	seen := make(map[string]bool, len(f.Vulnerabilities))
	for _, v := range f.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CveID))
		if !strings.HasPrefix(id, "CVE-") || seen[id] {
			return nil, fmt.Errorf("kev invalid or duplicate CVE")
		}
		seen[id] = true
	}
	return &f, nil
}

// ---- EPSS ----

type epssScore struct {
	prob       float64
	percentile float64
}

// parseEPSS reads the EPSS scores CSV (optionally gzip-compressed) and returns a
// cve->score map plus the feed's score_date. The file is a `#`-comment header
// (carrying score_date), a `cve,epss,percentile` column header, then rows. Pure so
// it's unit-testable; caller decides gzip vs plain by wrapping the reader.
func parseEPSS(r io.Reader) (map[string]epssScore, string, error) {
	out := make(map[string]epssScore, 300_000)
	scoreDate := ""
	br := bufio.NewReaderSize(r, 1<<16)
	sawHeader := false
	for {
		line, err := br.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			if strings.HasPrefix(trimmed, "#") {
				// e.g. "#model_version:v2025.03.14,score_date:2026-08-19T00:00:00+0000"
				if i := strings.Index(trimmed, "score_date:"); i >= 0 {
					sd := trimmed[i+len("score_date:"):]
					sd = strings.SplitN(sd, ",", 2)[0]
					if len(sd) >= 10 {
						scoreDate = sd[:10]
					}
				}
			} else if !sawHeader && strings.HasPrefix(trimmed, "cve,") {
				sawHeader = true
			} else {
				parts := strings.Split(trimmed, ",")
				if !sawHeader || len(parts) != 3 {
					return nil, "", fmt.Errorf("epss invalid row")
				}
				cve := strings.ToUpper(strings.TrimSpace(parts[0]))
				prob, e1 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
				pct, e2 := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
				if !strings.HasPrefix(cve, "CVE-") || e1 != nil || e2 != nil || math.IsNaN(prob) || math.IsNaN(pct) || prob < 0 || prob > 1 || pct < 0 || pct > 1 {
					return nil, "", fmt.Errorf("epss invalid score")
				}
				if _, exists := out[cve]; exists {
					return nil, "", fmt.Errorf("epss duplicate CVE")
				}
				out[cve] = epssScore{prob: prob, percentile: pct}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, "", fmt.Errorf("epss read: %w", err)
		}
	}
	if _, err := time.Parse("2006-01-02", scoreDate); err != nil || !sawHeader {
		return nil, "", fmt.Errorf("epss missing header or valid score date")
	}
	return out, scoreDate, nil
}

// ImportCVEIntel commits a complete KEV+EPSS snapshot and its persistent content
// checkpoint atomically. Identical snapshots skip CVE writes across restarts.
func ImportCVEIntel(ctx context.Context, pool *pgxpool.Pool, cfg CVEIntelConfig) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	total, marker := 0, ""
	err := withCVEImportConnection(ctx, pool, func(conn *pgxpool.Conn) error {
		var err error
		total, marker, err = importCVEIntel(ctx, conn, cfg)
		return err
	})
	return total, marker, err
}

func importCVEIntel(ctx context.Context, conn *pgxpool.Conn, cfg CVEIntelConfig) (int, string, error) {
	kevBytes, err := httpGet(ctx, cfg.client(), cfg.kevURL())
	if err != nil {
		return 0, "", fmt.Errorf("fetch kev: %w", err)
	}
	kev, err := parseKEV(kevBytes)
	if err != nil {
		return 0, "", err
	}
	epssBytes, err := fetchEPSSBytes(ctx, cfg)
	if err != nil {
		return 0, "", err
	}
	sourceHash := cveFeedHash(cfg.kevURL(), cfg.epssURL())
	contentHash := cveFeedHash(string(kevBytes), string(epssBytes))
	var previous string
	err = conn.QueryRow(ctx, `SELECT content_hash FROM cve_feed_checkpoints WHERE feed='kev-epss' AND source_hash=$1`, sourceHash).Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, "", err
	}
	if previous == contentHash {
		return 0, contentHash, nil
	}
	epss, scoreDate, err := parseEPSS(bytes.NewReader(epssBytes))
	if err != nil {
		return 0, "", err
	}
	rows := mergeCVEIntelRows(kev, epss, scoreDate)
	total, err := writeCVEIntelSnapshot(ctx, conn, sourceHash, contentHash, rows)
	return total, contentHash, err
}

func mergeCVEIntelRows(kev *kevFeed, epss map[string]epssScore, scoreDate string) map[string]*cveImportRow {
	// Merge into one row per CVE: KEV entries carry name/description/kev flag; every
	// EPSS score is applied (creating a bare row for EPSS-only CVEs).
	byID := make(map[string]*cveImportRow, len(epss)+len(kev.Vulnerabilities))
	for _, v := range kev.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CveID))
		if id == "" {
			continue
		}
		row := &cveImportRow{
			id:          id,
			title:       strings.TrimSpace(v.VulnerabilityName),
			description: strings.TrimSpace(v.ShortDescription),
			kevListed:   true,
			sources:     []string{"cisa-kev"},
		}
		if t, e := time.Parse("2006-01-02", strings.TrimSpace(v.DateAdded)); e == nil {
			row.kevAdded = &t
		}
		byID[id] = row
	}
	epssAt := time.Now().UTC()
	if scoreDate != "" {
		if t, e := time.Parse("2006-01-02", scoreDate); e == nil {
			epssAt = t
		}
	}
	for id, sc := range epss {
		row := byID[id]
		if row == nil {
			row = &cveImportRow{id: id, sources: []string{"epss"}}
			byID[id] = row
		}
		p := sc.prob
		row.epss = &p
		row.epssAt = &epssAt
	}

	return byID
}

func writeCVEIntelSnapshot(ctx context.Context, conn *pgxpool.Conn, sourceHash, contentHash string, byID map[string]*cveImportRow) (int, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollbackCVEImport(ctx, tx)
	if _, err := tx.Exec(ctx, `SET LOCAL synchronous_commit=on`); err != nil {
		return 0, err
	}

	// Batched upserts (reuses the bundle importer's COALESCE-merge writer).
	const batch = 1000
	rows := make([]cveImportRow, 0, batch)
	total := 0
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		if err := upsertCVERows(ctx, tx, rows); err != nil {
			return err
		}
		total += len(rows)
		rows = rows[:0]
		return nil
	}
	for _, r := range byID {
		rows = append(rows, *r)
		if len(rows) >= batch {
			if err := flush(); err != nil {
				return 0, err
			}
		}
	}
	if err := flush(); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO cve_feed_checkpoints(feed,source_hash,content_hash,row_count)
        VALUES ('kev-epss',$1,$2,$3) ON CONFLICT(feed) DO UPDATE SET source_hash=EXCLUDED.source_hash,
        content_hash=EXCLUDED.content_hash,row_count=EXCLUDED.row_count,updated_at=now()`, sourceHash, contentHash, total); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return total, nil
}

func fetchEPSSBytes(ctx context.Context, cfg CVEIntelConfig) ([]byte, error) {
	url := cfg.epssURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cfg.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch epss: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch epss: status %d", resp.StatusCode)
	}
	var r io.Reader = resp.Body
	if strings.HasSuffix(url, ".gz") || resp.Header.Get("Content-Type") == "application/gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("epss gunzip: %w", err)
		}
		defer gz.Close()
		r = gz
	}
	return readCVEFeed(r)
}

// Limit decompressed bytes too; a truncated or oversized feed must never advance
// the checkpoint even when its prefix happens to be syntactically valid.
func readCVEFeed(r io.Reader) ([]byte, error) {
	const limit = 64 << 20
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("CVE feed exceeds %d bytes", limit)
	}
	return b, nil
}

func httpGet(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return readCVEFeed(resp.Body)
}

// ReconcileCVEIntelLoop keeps cve_records fed with live KEV + EPSS intel. Skips a
// re-import using a durable content hash, including after a pod restart. Catalog
// labels alone are not trusted: same-version corrections are imported too.
func ReconcileCVEIntelLoop(ctx context.Context, pool *pgxpool.Pool, cfg CVEIntelConfig, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	run := func() {
		total, marker, err := ImportCVEIntel(ctx, pool, cfg)
		if err != nil {
			logger.Warn("cve-intel import failed", slog.String("err", err.Error()))
			return
		}
		if total == 0 {
			return
		}
		logger.Info("cve-intel imported", slog.Int("records", total), slog.String("marker", marker))
	}
	run()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
