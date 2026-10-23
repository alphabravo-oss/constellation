package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type engineDBStatus struct {
	DownloadRevision string `json:"download_revision,omitempty"`
	AppliedRevision  string `json:"applied_revision,omitempty"`
	Status           string `json:"status"`
}

const maxEngineDBMetadataBytes = 64 * 1024

type limitedDBStatusOutput struct {
	data     []byte
	overflow bool
}

func (output *limitedDBStatusOutput) Write(chunk []byte) (int, error) {
	written := len(chunk)
	remaining := maxEngineDBMetadataBytes - len(output.data)
	if len(chunk) > remaining {
		output.overflow = true
		chunk = chunk[:remaining]
	}
	output.data = append(output.data, chunk...)
	return written, nil
}

func (w *worker) engineDBSnapshot(ctx context.Context) map[string]engineDBStatus {
	w.engineDBMu.Lock()
	downloads := make(map[string]string, len(w.engineDBDownloads))
	for engine, revision := range w.engineDBDownloads {
		downloads[engine] = revision
	}
	w.engineDBMu.Unlock()

	out := make(map[string]engineDBStatus, 2)
	for _, engine := range []string{"trivy", "grype"} {
		status := engineDBStatus{DownloadRevision: downloads[engine]}
		if w.engines != nil && !w.engines[engine] {
			status.Status = "disabled"
		} else {
			status.AppliedRevision, status.Status = w.installedDBRevision(ctx, engine)
		}
		out[engine] = status
	}
	return out
}

func (w *worker) installedDBRevision(ctx context.Context, engine string) (string, string) {
	switch engine {
	case "trivy":
		cacheDir := w.cacheDirs["trivy"]
		if cacheDir == "" {
			cacheDir = os.Getenv("TRIVY_CACHE_DIR")
		}
		if cacheDir == "" {
			userCacheDir, err := os.UserCacheDir()
			if err != nil {
				return "", "unavailable"
			}
			cacheDir = filepath.Join(userCacheDir, "trivy")
		}
		metadataPath := filepath.Join(cacheDir, "db", "metadata.json")
		info, err := os.Lstat(metadataPath)
		if os.IsNotExist(err) {
			return "", "missing"
		}
		if err != nil {
			return "", "unavailable"
		}
		if !info.Mode().IsRegular() || info.Size() > maxEngineDBMetadataBytes {
			return "", "invalid"
		}
		file, err := os.Open(metadataPath)
		if err != nil {
			return "", "unavailable"
		}
		defer file.Close()
		var metadata struct {
			UpdatedAt string `json:"UpdatedAt"`
		}
		body, err := io.ReadAll(io.LimitReader(file, maxEngineDBMetadataBytes+1))
		if err != nil || len(body) > maxEngineDBMetadataBytes || json.Unmarshal(body, &metadata) != nil {
			return "", "invalid"
		}
		return normalizedDBRevision(metadata.UpdatedAt)
	case "grype":
		status, err := readGrypeDBStatus(ctx)
		if err != nil {
			return "", "unavailable"
		}
		if !status.Valid {
			return "", "invalid"
		}
		return normalizedDBRevision(status.Built)
	}
	return "", "unavailable"
}

// Validating a multi-GB database can exceed five seconds even with a warm cache.
// Keep a bounded deadline, but allow checksum validation to finish on worker CPUs.
const grypeDBStatusTimeout = time.Minute

type grypeDBStatus struct {
	Built string `json:"built"`
	Valid bool   `json:"valid"`
	From  string `json:"from"`
}

func readGrypeDBStatus(ctx context.Context) (grypeDBStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, grypeDBStatusTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "grype", "db", "status", "-o", "json", "-q")
	command.Env = append(os.Environ(), "GRYPE_DB_AUTO_UPDATE=false")
	var output limitedDBStatusOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	err := command.Run()
	var status grypeDBStatus
	if ctx.Err() != nil {
		return status, ctx.Err()
	}
	if err != nil && len(output.data) == 0 {
		return status, err
	}
	if output.overflow || json.Unmarshal(output.data, &status) != nil {
		return grypeDBStatus{}, nil
	}
	// Grype returns a nonzero exit for an invalid DB, but its structured output
	// still carries the recorded archive needed for non-destructive recovery.
	if err != nil {
		status.Valid = false
	}
	return status, nil
}

func grypeRecoveryArchive(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("recovery requires an HTTPS archive URL")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", fmt.Errorf("invalid archive query")
	}
	checksums := query["checksum"]
	if len(checksums) != 1 || !strings.HasPrefix(checksums[0], "sha256:") {
		return "", fmt.Errorf("recovery requires one SHA256 archive checksum")
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(checksums[0], "sha256:"))
	if err != nil || len(digest) != 32 {
		return "", fmt.Errorf("invalid archive checksum")
	}
	return u.String(), nil
}

func (w *worker) recoverGrypeDB(ctx context.Context) error {
	status, err := readGrypeDBStatus(ctx)
	if err != nil {
		return err
	}
	if status.Valid {
		return fmt.Errorf("database does not need corruption recovery")
	}
	archive, err := grypeRecoveryArchive(status.From)
	if err != nil {
		return err
	}
	// Import stages and validates the replacement. Never delete the active DB:
	// download failure must leave its evidence available for diagnosis/retry.
	command := exec.CommandContext(ctx, "grype", "db", "import", archive, "-q")
	command.Env = os.Environ()
	if err := command.Run(); err != nil {
		return fmt.Errorf("Grype database recovery import failed")
	}
	return nil
}

func normalizedDBRevision(value string) (string, string) {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil || parsed.IsZero() {
		return "", "invalid"
	}
	return parsed.UTC().Format(time.RFC3339Nano), "ready"
}

// scannerRuntimeConfig mirrors GET /api/v1/scanner/config — UI-settable knobs
// (system_config) the scanner polls so admins can change them without a redeploy.
type scannerRuntimeConfig struct {
	DBRefreshMinutes int   `json:"db_refresh_minutes"`
	OfflineDB        bool  `json:"offline_db"`
	RefreshNow       int64 `json:"refresh_now"` // unix-seconds "force refresh" signal
}

const maxScannerConfigBytes = 64 * 1024

var scannerConfigClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func (w *worker) fetchScannerConfig(ctx context.Context) (scannerRuntimeConfig, bool) {
	var out scannerRuntimeConfig
	if w.controlPlane == "" {
		return out, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.controlPlane+"/api/v1/scanner/config", nil)
	if err != nil {
		return out, false
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	w.setScannerHeaders(req)
	resp, err := scannerConfigClient.Do(req)
	if err != nil {
		return out, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxScannerConfigBytes+1))
	if err != nil || len(body) > maxScannerConfigBytes {
		return out, false
	}
	// Pointers distinguish explicit zero/false from missing or null policy fields.
	var wire struct {
		DBRefreshMinutes *int   `json:"db_refresh_minutes"`
		OfflineDB        *bool  `json:"offline_db"`
		RefreshNow       *int64 `json:"refresh_now"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || wire.DBRefreshMinutes == nil || wire.OfflineDB == nil || wire.RefreshNow == nil {
		return out, false
	}
	minutes := *wire.DBRefreshMinutes
	if (minutes != 0 && (minutes < 15 || minutes > 43200)) || *wire.RefreshNow < 0 {
		return out, false
	}
	return scannerRuntimeConfig{DBRefreshMinutes: minutes, OfflineDB: *wire.OfflineDB, RefreshNow: *wire.RefreshNow}, true
}

// refreshVulnDBs pulls the latest Trivy + Grype DBs from their upstream feeds.
// No-op when air-gapped — operators pre-load the DBs (see docs/offline-scanning.md).
func (w *worker) refreshVulnDBs(ctx context.Context, offline bool) {
	if offline {
		return
	}
	w.dbRefreshMu.Lock()
	defer w.dbRefreshMu.Unlock()
	run := func(name string, args ...string) {
		if w.engines != nil && !w.engines[name] {
			return
		}
		if _, err := exec.LookPath(name); err != nil {
			w.logger.Warn("vuln DB refresh failed", "engine", name, "reason", "executable unavailable")
			return
		}
		refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
		c := exec.CommandContext(refreshCtx, name, args...)
		c.Env = os.Environ()
		updateErr := c.Run()
		revision, status := w.installedDBRevision(refreshCtx, name)
		recovered := false
		if name == "grype" && status == "invalid" && refreshCtx.Err() == nil {
			w.logger.Warn("invalid Grype database; attempting verified archive recovery")
			if err := w.recoverGrypeDB(refreshCtx); err != nil {
				w.logger.Warn("vuln DB recovery failed", "engine", name, "err", err.Error())
				return
			}
			revision, status = w.installedDBRevision(refreshCtx, name)
			recovered = true
		}
		if status != "ready" || (updateErr != nil && !recovered) {
			w.logger.Warn("vuln DB refresh failed", "engine", name, "status", status, "update_failed", updateErr != nil)
			return
		}
		w.engineDBMu.Lock()
		if w.engineDBDownloads == nil {
			w.engineDBDownloads = make(map[string]string, 2)
		}
		w.engineDBDownloads[name] = revision
		w.engineDBMu.Unlock()
		w.logger.Info("vuln DB refreshed", "engine", name, "revision", revision, "recovered", recovered)
	}
	run("trivy", "image", "--download-db-only", "--quiet")
	// Scans run with --skip-java-db-update, so the Java (Maven index) DB only ever moves
	// when this loop refreshes it explicitly. Trivy keeps it separate from the main DB.
	w.refreshTrivyJavaDB(ctx)
	run("grype", "db", "update", "-q")
	if w.engines == nil || w.engines["grype"] {
		w.pruneGrypeStaging(ctx)
	}
}

// dbRefreshPolicy retains the last valid remote policy through outages. A worker
// with a control plane waits for its first valid policy before downloading.
type dbRefreshPolicy struct {
	envInterval    time.Duration
	envOffline     bool
	remoteRequired bool
	known          bool
	config         scannerRuntimeConfig
	lastSignal     int64
	last           time.Time
}

func (p *dbRefreshPolicy) due(now time.Time, cfg scannerRuntimeConfig, valid bool) bool {
	force := false
	if valid {
		// Seed the signal on the first successful fetch, including after an outage.
		// A historical click must not cause a second boot refresh.
		force = p.known && cfg.RefreshNow > p.lastSignal
		if !p.known || cfg.RefreshNow > p.lastSignal {
			p.lastSignal = cfg.RefreshNow
		}
		p.config, p.known = cfg, true
	}
	if p.envOffline || (p.remoteRequired && !p.known) || p.config.OfflineDB {
		return false
	}
	interval := p.envInterval
	if p.config.DBRefreshMinutes > 0 {
		interval = time.Duration(p.config.DBRefreshMinutes) * time.Minute
	}
	return p.last.IsZero() || force || (interval > 0 && now.Sub(p.last) >= interval)
}

// dbRefreshLoop polls policy once on boot and every five minutes thereafter.
// Offline policy suppresses both scheduled and forced refreshes. Force signals
// observed while offline are consumed, not queued for later execution.
func (w *worker) dbRefreshLoop(ctx context.Context, envInterval time.Duration, envOffline bool) {
	policy := dbRefreshPolicy{envInterval: envInterval, envOffline: envOffline, remoteRequired: w.controlPlane != ""}
	poll := func() {
		cfg, valid := w.fetchScannerConfig(ctx)
		if ctx.Err() != nil {
			return
		}
		if policy.due(time.Now(), cfg, valid) {
			w.refreshVulnDBs(ctx, false)
			policy.last = time.Now()
		}
	}
	poll()
	check := time.NewTicker(5 * time.Minute)
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			poll()
		}
	}
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// refreshTrivyJavaDB downloads the Trivy Java DB (trivy-java-db) next to the main DB.
// Best-effort: a failure is logged and the previous Java DB stays in use; the main DB
// refresh result is reported separately so a Java-DB outage never masks it.
func (w *worker) refreshTrivyJavaDB(ctx context.Context) {
	if w.engines != nil && !w.engines["trivy"] {
		return
	}
	if _, err := exec.LookPath("trivy"); err != nil {
		return
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	c := exec.CommandContext(refreshCtx, "trivy", "image", "--download-java-db-only", "--quiet")
	c.Env = os.Environ()
	if err := c.Run(); err != nil {
		w.logger.Warn("trivy java DB refresh failed", "err", err.Error())
		return
	}
	w.logger.Info("trivy java DB refreshed")
}
