// Periodic host-facts reporter. Runs as one goroutine started from main.
//
// Behavior:
//   - on launch, collect immediately and POST (so the UI sees a row right
//     away rather than waiting up to a full interval)
//   - then every CONSTELLATION_HOSTSCAN_INTERVAL (default 5m), repeat
//   - POST failures are logged and counted but never crash the agent —
//     the host-facts surface is observability, not correctness
//
// Mirrors the structure of the other ingest loops (events, flows,
// threats) so the heartbeat / metrics shape is familiar.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
	"github.com/alphabravocompany/constellation/pkg/version"
)

// hostScanConfig is the per-goroutine config; populated from env in main.
type hostScanConfig struct {
	APIBaseURL string
	Token      string
	NodeName   string
	CNIDir     string
	Interval   time.Duration
	HostRoot   string
	Logger     *slog.Logger
}

func hostScanLoop(ctx context.Context, cfg hostScanConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.APIBaseURL == "" || cfg.Token == "" {
		cfg.Logger.Info("hostscan: disabled (no api url or token)")
		return
	}
	url := cfg.APIBaseURL + "/api/v1/host-facts:report"
	cli := &http.Client{Timeout: 20 * time.Second}

	tick := time.NewTimer(0) // fire immediately on launch
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			facts := hostscan.Collect(ctx, hostscan.Options{
				HostRoot:     cfg.HostRoot,
				NodeName:     cfg.NodeName,
				CNIDir:       cfg.CNIDir,
				AgentVersion: version.Version,
			})
			if err := postFacts(ctx, cli, url, cfg.Token, facts); err != nil {
				cfg.Logger.Error("hostscan: report failed", slog.String("err", err.Error()))
			} else {
				cfg.Logger.Info("hostscan: reported",
					slog.String("node", facts.Node),
					slog.String("kernel", facts.Kernel.Release),
					slog.String("os", facts.OS.PrettyName),
					slog.String("cni", facts.CNI.Name),
					slog.Bool("btf", facts.BPF.BTFPresent),
					slog.Bool("nfqueue", facts.Net.IPTablesNFQueue),
				)
			}
			tick.Reset(cfg.Interval)
		}
	}
}

func postFacts(ctx context.Context, cli *http.Client, url, token string, facts hostscan.Facts) error {
	body, err := json.Marshal(facts)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// hostScanIntervalFromEnv parses CONSTELLATION_HOSTSCAN_INTERVAL ("5m",
// "30s", etc.) and falls back to a default. Exposed for testing.
func hostScanIntervalFromEnv(envVal string, fallback time.Duration) time.Duration {
	if envVal == "" {
		return fallback
	}
	d, err := time.ParseDuration(envVal)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// hostScanHostRootFromEnv defaults to "" (use absolute paths). Set
// CONSTELLATION_HOSTSCAN_ROOT=/host if the chart mounts host filesystems
// under a /host prefix instead of at /proc, /sys, /etc directly.
func hostScanHostRootFromEnv() string {
	return os.Getenv("CONSTELLATION_HOSTSCAN_ROOT")
}
