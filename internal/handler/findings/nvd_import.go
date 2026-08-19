package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/syscfg"
)

// NVD full-catalog CVE importer (descriptions + CVSS). Complements the always-on
// KEV+EPSS exploitation-intel importer: KEV/EPSS say "is this exploited / how
// likely", NVD adds the human description + CVSS base score/vector. Enabled +
// keyed via system_config (UI-settable): nvd_enabled, nvd_api_key, nvd_mirror_url.
//
// Uses the NVD 2.0 REST API (services.nvd.nist.gov/rest/json/cves/2.0), paginated
// 2000/page, rate-limited (5 req/30s without a key, 50 with). We sync a rolling
// lastModified window each run so restarts stay cheap and recently-changed CVEs
// keep fresh; the upsert's COALESCE merges onto the KEV/EPSS rows without clobber.

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
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
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
	rows := make([]cveImportRow, 0, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		c := v.CVE
		id := strings.ToUpper(strings.TrimSpace(c.ID))
		if id == "" {
			continue
		}
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
		if t, err := time.Parse(time.RFC3339, c.Published); err == nil {
			row.published = &t
		}
		if t, err := time.Parse(time.RFC3339, c.LastModified); err == nil {
			row.modified = &t
		}
		rows = append(rows, row)
	}
	return rows, resp.TotalResults, nil
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

// ImportNVD syncs CVEs modified in the trailing window into cve_records. Returns
// the number of rows upserted.
func ImportNVD(ctx context.Context, pool *pgxpool.Pool, cfg nvdConfig, logger *slog.Logger) (int, error) {
	cveImportMu.Lock()
	defer cveImportMu.Unlock()

	windowDays := cfg.WindowDays
	if windowDays <= 0 || windowDays > nvdWindowDays {
		windowDays = nvdWindowDays
	}
	end := time.Now().UTC()
	start := end.Add(-time.Duration(windowDays) * 24 * time.Hour)

	total := 0
	startIndex := 0
	for page := 0; page < nvdMaxPages; page++ {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		rows, totalResults, err := fetchNVDPage(ctx, cfg, startIndex, start, end)
		if err != nil {
			return total, err
		}
		if len(rows) > 0 {
			if err := upsertCVERows(ctx, pool, rows); err != nil {
				return total, err
			}
			total += len(rows)
		}
		startIndex += nvdPageSize
		if startIndex >= totalResults || len(rows) == 0 {
			break
		}
		// Respect the rate limit between pages.
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(cfg.rateDelay()):
		}
	}
	return total, nil
}

func fetchNVDPage(ctx context.Context, cfg nvdConfig, startIndex int, start, end time.Time) ([]cveImportRow, int, error) {
	url := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d&lastModStartDate=%s&lastModEndDate=%s",
		cfg.base(), nvdPageSize, startIndex,
		start.Format("2006-01-02T15:04:05.000Z"), end.Format("2006-01-02T15:04:05.000Z"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	if k := strings.TrimSpace(cfg.APIKey); k != "" {
		req.Header.Set("apiKey", k)
	}
	resp, err := cfg.client().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("nvd fetch: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, 0, err
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
