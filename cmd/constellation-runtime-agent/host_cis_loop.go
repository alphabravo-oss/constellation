// Periodic CIS benchmark runner (Slice E). Runs the in-tree CIS
// checks (no shell-out, no nvbench shell templates) and POSTs to
// /api/v1/host-cis:report. Cadence default: every 6 hours — host
// hardening drifts slowly.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
)

type hostCISConfig struct {
	APIBaseURL string
	Token      string
	NodeName   string
	Interval   time.Duration
	HostRoot   string
	Logger     *slog.Logger
}

func hostCISLoop(ctx context.Context, cfg hostCISConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 6 * time.Hour
	}
	if cfg.APIBaseURL == "" || cfg.Token == "" {
		cfg.Logger.Info("host-cis: disabled (no api url or token)")
		return
	}
	url := cfg.APIBaseURL + "/api/v1/host-cis:report"
	cli := &http.Client{Timeout: 30 * time.Second}

	tick := time.NewTimer(0)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			report := hostscan.RunCIS(hostscan.CISOptions{
				HostRoot: cfg.HostRoot,
				NodeName: cfg.NodeName,
			})
			if err := postCIS(ctx, cli, url, cfg.Token, report); err != nil {
				cfg.Logger.Error("host-cis: report failed", slog.String("err", err.Error()))
			} else {
				cfg.Logger.Info("host-cis: reported",
					slog.String("node", report.Node),
					slog.String("profile", report.Profile),
					slog.Int("pass", report.Passed),
					slog.Int("fail", report.Failed),
					slog.Int("warn", report.Warned),
					slog.Int("skip", report.Skipped),
				)
			}
			tick.Reset(cfg.Interval)
		}
	}
}

func postCIS(ctx context.Context, cli *http.Client, url, token string, r hostscan.CISReport) error {
	body, err := json.Marshal(r)
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
