package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/syscfg"
)

// NVD recent-change CVE importer (descriptions + CVSS). Complements the always-on
// KEV+EPSS exploitation-intel importer: KEV/EPSS say "is this exploited / how
// likely", NVD adds the human description + CVSS base score/vector. Enabled +
// keyed via system_config (UI-settable): nvd_enabled, nvd_api_key, nvd_mirror_url.
//
// Uses the NVD 2.0 REST API (services.nvd.nist.gov/rest/json/cves/2.0), paginated
// 2000/page, rate-limited (5 req/30s without a key, 50 with). We sync a rolling
// lastModified window on first use, then a persistent overlapping watermark; the upsert's COALESCE merges onto the KEV/EPSS rows without clobber.

const (
	defaultNVDBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdPageSize    = 2000
	nvdWindowDays  = 120 // NVD caps lastMod ranges at 120 days
	nvdMaxPages    = 200 // safety bound
)

type nvdConfig struct {
	Enabled    bool
	APIKey     string
	BaseURL    string
	Interval   time.Duration
	Client     *http.Client
	WindowDays int
}

func (c nvdConfig) base() string {
	if b := strings.TrimSpace(c.BaseURL); b != "" {
		return b
	}
	return defaultNVDBase
}

func (c nvdConfig) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c nvdConfig) rateDelay() time.Duration {
	// Respect NVD's rate limits with margin: 50 req/30s keyed, 5 unkeyed.
	if strings.TrimSpace(c.APIKey) != "" {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

// ---- parse ----

type nvdResponse struct {
	ResultsPerPage  *int `json:"resultsPerPage"`
	StartIndex      *int `json:"startIndex"`
	TotalResults    *int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
				CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVSSMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// parseNVDPage decodes one NVD 2.0 page into cve_records rows + the total count.
// Pure so it's unit-testable without hitting the API.
func parseNVDPage(b []byte) ([]cveImportRow, int, error) {
	var resp nvdResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, 0, fmt.Errorf("nvd decode: %w", err)
	}
	if resp.ResultsPerPage == nil || resp.StartIndex == nil || resp.TotalResults == nil {
		return nil, 0, fmt.Errorf("nvd missing pagination metadata")
	}
	if resp.Vulnerabilities == nil || *resp.StartIndex < 0 || *resp.TotalResults < 0 || *resp.ResultsPerPage < len(resp.Vulnerabilities) || *resp.ResultsPerPage > nvdPageSize || *resp.StartIndex+len(resp.Vulnerabilities) > *resp.TotalResults {
		return nil, 0, fmt.Errorf("nvd invalid pagination metadata")
	}
	rows := make([]cveImportRow, 0, len(resp.Vulnerabilities))
	seen := make(map[string]bool, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		c := v.CVE
		id := strings.ToUpper(strings.TrimSpace(c.ID))
		if !strings.HasPrefix(id, "CVE-") || seen[id] {
			return nil, 0, fmt.Errorf("nvd invalid or duplicate CVE")
		}
		seen[id] = true
		row := cveImportRow{id: id, sources: []string{"nvd"}}
		for _, d := range c.Descriptions {
			if strings.EqualFold(d.Lang, "en") {
				row.description = strings.TrimSpace(d.Value)
				break
			}
		}
		if m := firstCVSS(c.Metrics.CVSSMetricV31, c.Metrics.CVSSMetricV30); m != nil {
			s := m.CVSSData.BaseScore
			row.cvssBase = &s
			row.cvssVector = m.CVSSData.VectorString
		}
		if t, err := parseNVDTime(c.Published); err == nil {
			row.published = &t
		}
		if t, err := parseNVDTime(c.LastModified); err == nil {
			row.modified = &t
		}
		rows = append(rows, row)
	}
	return rows, *resp.TotalResults, nil
}

func firstCVSS(v31, v30 []nvdCVSSMetric) *nvdCVSSMetric {
	if len(v31) > 0 {
		return &v31[0]
	}
	if len(v30) > 0 {
		return &v30[0]
	}
	return nil
}

// ImportNVD persists completed windows, overlapping by two hours for boundary
// updates. A failed page never advances the watermark; previous pages can safely
// replay through the conditional writer. Initial sync still covers recent CVEs,
// not a historical full-catalog bootstrap.
func ImportNVD(ctx context.Context, pool *pgxpool.Pool, cfg nvdConfig, logger *slog.Logger) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	total := 0
	err := withCVEImportConnection(ctx, pool, func(conn *pgxpool.Conn) error {
		var err error
		total, err = importNVD(ctx, conn, cfg)
		return err
	})
	return total, err
}

func importNVD(ctx context.Context, conn *pgxpool.Conn, cfg nvdConfig) (int, error) {
	days := cfg.WindowDays
	if days <= 0 || days > nvdWindowDays {
		days = nvdWindowDays
	}
	sourceHash := cveFeedHash(cfg.base())
	now := time.Now().UTC().Truncate(time.Millisecond)
	start := now.Add(-time.Duration(days) * 24 * time.Hour)
	var through time.Time
	err := conn.QueryRow(ctx, `SELECT completed_through FROM cve_feed_checkpoints WHERE feed='nvd' AND source_hash=$1`, sourceHash).Scan(&through)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	if err == nil {
		if through.After(now) {
			return 0, fmt.Errorf("nvd checkpoint is ahead of local clock")
		}
		start = through.Add(-2 * time.Hour)
	}
	total, pages := 0, 0
	for start.Before(now) {
		end := start.Add(time.Duration(days) * 24 * time.Hour)
		if end.After(now) {
			end = now
		}
		count, err := importNVDWindow(ctx, conn, cfg, sourceHash, start, end, &pages)
		total += count
		if err != nil {
			return total, err
		}
		if end.Equal(now) {
			return total, nil
		}
		start = end.Add(-2 * time.Hour)
	}
	return total, nil
}

func importNVDWindow(ctx context.Context, conn *pgxpool.Conn, cfg nvdConfig, sourceHash string, start, end time.Time, pages *int) (int, error) {
	total, index, expected := 0, 0, -1
	seen := make(map[string]bool)
	for *pages < nvdMaxPages {
		if *pages > 0 {
			select {
			case <-ctx.Done():
				return total, ctx.Err()
			case <-time.After(cfg.rateDelay()):
			}
		}
		(*pages)++
		rows, count, err := fetchNVDPage(ctx, cfg, index, start, end)
		if err != nil {
			return total, err
		}
		if err := validateNVDPageProgress(expected, index, count, rows, seen); err != nil {
			return total, err
		}
		expected = count
		index += len(rows)
		if err := commitNVDPage(ctx, conn, sourceHash, end, index, count, rows); err != nil {
			return total, err
		}
		total += len(rows)
		if index == count {
			return total, nil
		}
	}
	return total, fmt.Errorf("nvd page budget exhausted before completing window")
}

func validateNVDPageProgress(expected, index, count int, rows []cveImportRow, seen map[string]bool) error {
	if expected >= 0 && expected != count {
		return fmt.Errorf("nvd result count changed during pagination; retry window")
	}
	if len(rows) == 0 && index < count {
		return fmt.Errorf("nvd empty page before end of results")
	}
	for _, row := range rows {
		if seen[row.id] {
			return fmt.Errorf("nvd duplicate CVE across pages; retry window")
		}
		seen[row.id] = true
	}
	return nil
}

func commitNVDPage(ctx context.Context, conn *pgxpool.Conn, sourceHash string, end time.Time, index, count int, rows []cveImportRow) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackCVEImport(ctx, tx)
	if err := upsertCVERows(ctx, tx, rows); err != nil {
		return err
	}
	if index == count {
		if _, err := tx.Exec(ctx, `SET LOCAL synchronous_commit=on`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cve_feed_checkpoints(feed,source_hash,completed_through,row_count)
            VALUES ('nvd',$1,$2,$3) ON CONFLICT(feed) DO UPDATE SET source_hash=EXCLUDED.source_hash,
            completed_through=EXCLUDED.completed_through,row_count=EXCLUDED.row_count,updated_at=now()`, sourceHash, end, index); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func parseNVDTime(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	// NVD also emits UTC timestamps without a zone suffix.
	return time.Parse("2006-01-02T15:04:05.999999999", value)
}

func fetchNVDPage(ctx context.Context, cfg nvdConfig, startIndex int, start, end time.Time) ([]cveImportRow, int, error) {
	base, err := url.Parse(cfg.base())
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, 0, fmt.Errorf("nvd base URL must be HTTP(S), without query or fragment")
	}
	query := base.Query()
	query.Set("resultsPerPage", fmt.Sprint(nvdPageSize))
	query.Set("startIndex", fmt.Sprint(startIndex))
	query.Set("lastModStartDate", start.Format("2006-01-02T15:04:05.000Z"))
	query.Set("lastModEndDate", end.Format("2006-01-02T15:04:05.000Z"))
	base.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	if k := strings.TrimSpace(cfg.APIKey); k != "" {
		req.Header.Set("apiKey", k)
	}
	client := *cfg.client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("nvd fetch: status %d", resp.StatusCode)
	}
	b, err := readCVEFeed(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	var metadata nvdResponse
	if err := json.Unmarshal(b, &metadata); err != nil {
		return nil, 0, fmt.Errorf("nvd decode: %w", err)
	}
	if metadata.StartIndex == nil || *metadata.StartIndex != startIndex {
		return nil, 0, fmt.Errorf("nvd unexpected startIndex")
	}
	return parseNVDPage(b)
}

// ReconcileNVDLoop reads the NVD config from system_config (the bootstrap org) each
// tick and, when enabled, syncs the trailing window. Default OFF — the KEV+EPSS
// importer is the always-on live source; NVD is opt-in for full descriptions+CVSS.
func ReconcileNVDLoop(ctx context.Context, pool *pgxpool.Pool, interval time.Duration, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	run := func() {
		cfg, ok := loadNVDConfig(ctx, pool)
		if !ok || !cfg.Enabled {
			return
		}
		n, err := ImportNVD(ctx, pool, cfg, logger)
		if err != nil {
			logger.Warn("nvd import failed", slog.String("err", err.Error()))
			return
		}
		logger.Info("nvd imported", slog.Int("records", n))
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

// loadNVDConfig reads NVD settings from the first organization's system_config.
func loadNVDConfig(ctx context.Context, pool *pgxpool.Pool) (nvdConfig, bool) {
	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		return nvdConfig{}, false
	}
	cfg, _, err := syscfg.Load(ctx, pool, orgID)
	if err != nil {
		return nvdConfig{}, false
	}
	return nvdConfig{
		Enabled: cfg.NVDEnabled,
		APIKey:  cfg.NVDAPIKey,
		BaseURL: cfg.NVDMirrorURL,
	}, true
}
