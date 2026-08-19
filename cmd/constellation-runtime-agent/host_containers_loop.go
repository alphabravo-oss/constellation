// Periodic container-inventory reporter (Slice C). Shells out to
// crictl against the host's CRI socket and POSTs to
// /api/v1/host-containers:report.
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

type hostContainersConfig struct {
	APIBaseURL string
	Token      string
	NodeName   string
	Interval   time.Duration
	HostRoot   string
	Logger     *slog.Logger
	OnSnapshot func(hostscan.Containers)
}

func hostContainersLoop(ctx context.Context, cfg hostContainersConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.APIBaseURL == "" || cfg.Token == "" {
		cfg.Logger.Info("host-containers: disabled (no api url or token)")
		return
	}
	url := cfg.APIBaseURL + "/api/v1/host-containers:report"
	cli := &http.Client{Timeout: 30 * time.Second}

	tick := time.NewTimer(0)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			snap, err := hostscan.CollectContainers(ctx, hostscan.ContainersOptions{
				HostRoot: cfg.HostRoot,
				NodeName: cfg.NodeName,
			})
			if err != nil {
				// Collection failed (no CRI socket, crictl missing,
				// etc.). Log and skip the upload — leaving the
				// previous snapshot (if any) in the DB.
				cfg.Logger.Warn("host-containers: collect failed",
					slog.String("err", err.Error()))
				tick.Reset(cfg.Interval)
				continue
			}
			if cfg.OnSnapshot != nil {
				cfg.OnSnapshot(snap)
			}
			if err := postContainers(ctx, cli, url, cfg.Token, snap); err != nil {
				cfg.Logger.Error("host-containers: report failed", slog.String("err", err.Error()))
			} else {
				cfg.Logger.Info("host-containers: reported",
					slog.String("node", snap.Node),
					slog.String("runtime", snap.Runtime),
					slog.Int("count", snap.Count),
				)
			}
			tick.Reset(cfg.Interval)
		}
	}
}

func postContainers(ctx context.Context, cli *http.Client, url, token string, c hostscan.Containers) error {
	body, err := json.Marshal(c)
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
