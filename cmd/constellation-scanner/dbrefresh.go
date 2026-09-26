package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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
		if err := json.NewDecoder(io.LimitReader(file, maxEngineDBMetadataBytes)).Decode(&metadata); err != nil {
			return "", "invalid"
		}
		return normalizedDBRevision(metadata.UpdatedAt)
	case "grype":
		commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		command := exec.CommandContext(commandCtx, "grype", "db", "status", "-o", "json", "-q")
		command.Env = append(os.Environ(), "GRYPE_DB_AUTO_UPDATE=false")
		var output limitedDBStatusOutput
		command.Stdout = &output
		command.Stderr = io.Discard
		err := command.Run()
		if err != nil && len(output.data) == 0 {
			return "", "unavailable"
		}
		var status struct {
			Built string `json:"built"`
			Valid bool   `json:"valid"`
		}
		if output.overflow || json.Unmarshal(output.data, &status) != nil {
			return "", "invalid"
		}
		if !status.Valid || err != nil {
			return "", "invalid"
		}
		return normalizedDBRevision(status.Built)
	}
	return "", "unavailable"
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return out, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, false
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, true
}

// refreshVulnDBs pulls the latest Trivy + Grype DBs from their upstream feeds.
// No-op when air-gapped — operators pre-load the DBs (see docs/offline-scanning.md).
func (w *worker) refreshVulnDBs(ctx context.Context, offline bool) {
	if offline {
		return
	}
	run := func(name string, args ...string) {
		if _, err := exec.LookPath(name); err != nil {
			return
		}
		c := exec.CommandContext(ctx, name, args...)
		c.Env = os.Environ()
		if err := c.Run(); err != nil {
			w.logger.Warn("vuln DB refresh failed", "engine", name, "err", err.Error())
			return
		}
		revision, status := w.installedDBRevision(ctx, name)
		if status == "ready" {
			w.engineDBMu.Lock()
			if w.engineDBDownloads == nil {
				w.engineDBDownloads = make(map[string]string, 2)
			}
			w.engineDBDownloads[name] = revision
			w.engineDBMu.Unlock()
		}
		w.logger.Info("vuln DB refreshed", "engine", name)
	}
	run("trivy", "image", "--download-db-only", "--quiet")
	run("grype", "db", "update", "-q")
	// Grype's updater downloads each DB into a `grype-db-download<rand>` staging dir
	// under the cache and, on some paths, leaves it behind after importing into the
	// versioned dir (`6/`). Across many refreshes these pile up — ~50 dirs / 10GB was
	// observed. Sweep them after every update; the active versioned DB is untouched.
	w.pruneGrypeStaging()
}

// pruneGrypeStaging removes grype's abandoned download-staging dirs from the grype
// cache, keeping the active versioned DB (e.g. `6/`). Best-effort + quiet.
func (w *worker) pruneGrypeStaging() {
	dir := os.Getenv("GRYPE_DB_CACHE_DIR")
	if dir == "" {
		dir = "/tmp/grype/db"
	}
	matches, err := filepath.Glob(filepath.Join(dir, "grype-db-download*"))
	if err != nil {
		return
	}
	removed := 0
	for _, m := range matches {
		if err := os.RemoveAll(m); err == nil {
			removed++
		}
	}
	if removed > 0 {
		w.logger.Info("grype cache: pruned stale download-staging dirs", "count", removed, "dir", dir)
	}
}

// dbRefreshLoop keeps the Trivy/Grype DBs fresh on the effective interval. The
// UI-settable system_config value (polled via /api/v1/scanner/config) overrides
// the env/flag default when set; offline mode from either source suppresses pulls.
func (w *worker) dbRefreshLoop(ctx context.Context, envInterval time.Duration, envOffline bool) {
	effective := func() (time.Duration, bool) {
		iv, off := envInterval, envOffline
		if cfg, ok := w.fetchScannerConfig(ctx); ok {
			if cfg.DBRefreshMinutes > 0 {
				iv = time.Duration(cfg.DBRefreshMinutes) * time.Minute
			}
			off = off || cfg.OfflineDB
		}
		return iv, off
	}

	iv, off := effective()
	w.refreshVulnDBs(ctx, off) // initial refresh on boot
	last := time.Now()
	// Seed the last-applied force-refresh signal from the current config so a boot
	// doesn't re-trigger an old "refresh now" click.
	var lastRefreshNow int64
	if cfg, ok := w.fetchScannerConfig(ctx); ok {
		lastRefreshNow = cfg.RefreshNow
	}

	// Re-check config every 5 min so a UI change to the interval — or a "Refresh
	// now" click — takes effect within minutes.
	check := time.NewTicker(5 * time.Minute)
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			iv, off = envInterval, envOffline
			forceNow := false
			if cfg, ok := w.fetchScannerConfig(ctx); ok {
				if cfg.DBRefreshMinutes > 0 {
					iv = time.Duration(cfg.DBRefreshMinutes) * time.Minute
				}
				off = off || cfg.OfflineDB
				if cfg.RefreshNow > lastRefreshNow {
					forceNow = true
					lastRefreshNow = cfg.RefreshNow
				}
			}
			if forceNow || (iv > 0 && time.Since(last) >= iv) {
				w.refreshVulnDBs(ctx, off)
				last = time.Now()
			}
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
