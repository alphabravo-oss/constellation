package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"time"
)

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
		w.logger.Info("vuln DB refreshed", "engine", name)
	}
	run("trivy", "image", "--download-db-only", "--quiet")
	run("grype", "db", "update", "-q")
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
