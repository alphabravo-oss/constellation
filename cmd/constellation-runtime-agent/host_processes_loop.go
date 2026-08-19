// Periodic process-snapshot reporter (Slice B). Mirrors hostScanLoop
// for layout: launch fires once on startup, then every
// CONSTELLATION_HOSTSCAN_PROC_INTERVAL (default 1m). Failures are
// logged and counted but never crash the agent.
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
	"strconv"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
)

type hostProcessesConfig struct {
	APIBaseURL string
	Token      string
	NodeName   string
	Interval   time.Duration
	HostRoot   string
	MaxItems   int
	Logger     *slog.Logger
}

func hostProcessesLoop(ctx context.Context, cfg hostProcessesConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.APIBaseURL == "" || cfg.Token == "" {
		cfg.Logger.Info("host-processes: disabled (no api url or token)")
		return
	}
	url := cfg.APIBaseURL + "/api/v1/host-processes:report"
	cli := &http.Client{Timeout: 30 * time.Second}

	tick := time.NewTimer(0)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			procs := hostscan.CollectProcesses(hostscan.ProcessOptions{
				HostRoot: cfg.HostRoot,
				NodeName: cfg.NodeName,
				MaxItems: cfg.MaxItems,
			})
			if err := postProcesses(ctx, cli, url, cfg.Token, procs); err != nil {
				cfg.Logger.Error("host-processes: report failed", slog.String("err", err.Error()))
			} else {
				cfg.Logger.Info("host-processes: reported",
					slog.String("node", procs.Node),
					slog.Int("count", procs.Count),
					slog.Int("items", len(procs.Items)),
				)
			}
			tick.Reset(cfg.Interval)
		}
	}
}

func postProcesses(ctx context.Context, cli *http.Client, url, token string, p hostscan.Processes) error {
	body, err := json.Marshal(p)
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

// hostProcMaxItemsFromEnv parses CONSTELLATION_HOSTSCAN_PROC_MAX with
// a default of 1000.
func hostProcMaxItemsFromEnv() int {
	v := os.Getenv("CONSTELLATION_HOSTSCAN_PROC_MAX")
	if v == "" {
		return 1000
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 1000
	}
	return n
}
