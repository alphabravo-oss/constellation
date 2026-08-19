// Periodic host package reporter (Slice D.1). Reads the native package
// DB on the host (dpkg / rpm / apk) and POSTs to /api/v1/host-packages:report.
//
// Package lists change rarely (only when an admin installs/upgrades),
// so the cadence is much slower than facts/processes/containers:
// default once per hour.
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

type hostPackagesConfig struct {
	APIBaseURL    string
	Token         string
	NodeName      string
	Interval      time.Duration
	HostRoot      string
	Distro        string // os-release ID
	DistroVersion string // os-release VERSION_ID
	Logger        *slog.Logger
}

func hostPackagesLoop(ctx context.Context, cfg hostPackagesConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}
	if cfg.APIBaseURL == "" || cfg.Token == "" {
		cfg.Logger.Info("host-packages: disabled (no api url or token)")
		return
	}
	url := cfg.APIBaseURL + "/api/v1/host-packages:report"
	cli := &http.Client{Timeout: 60 * time.Second}

	tick := time.NewTimer(0)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Re-detect distro each tick — cheap and lets the loop
			// recover if hostScanLoop hadn't run yet on the first call.
			distro := cfg.Distro
			distroVersion := cfg.DistroVersion
			if distro == "" || distroVersion == "" {
				detectedDistro, detectedVersion := detectOSForPackages(cfg.HostRoot)
				if distro == "" {
					distro = detectedDistro
				}
				if distroVersion == "" {
					distroVersion = detectedVersion
				}
			}
			snap, err := hostscan.CollectPackages(hostscan.PackagesOptions{
				HostRoot:      cfg.HostRoot,
				NodeName:      cfg.NodeName,
				Distro:        distro,
				DistroVersion: distroVersion,
			})
			if err != nil && snap.Count == 0 {
				cfg.Logger.Warn("host-packages: collect failed",
					slog.String("err", err.Error()))
				tick.Reset(cfg.Interval)
				continue
			}
			if err := postPackages(ctx, cli, url, cfg.Token, snap); err != nil {
				cfg.Logger.Error("host-packages: report failed", slog.String("err", err.Error()))
			} else {
				cfg.Logger.Info("host-packages: reported",
					slog.String("node", snap.Node),
					slog.String("source", snap.Source),
					slog.String("distro", snap.Distro),
					slog.String("distro_version", snap.DistroVersion),
					slog.Int("count", snap.Count),
				)
			}
			tick.Reset(cfg.Interval)
		}
	}
}

func postPackages(ctx context.Context, cli *http.Client, url, token string, p hostscan.Packages) error {
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

// detectOSForPackages reads the host's os-release. Light wrapper
// over hostscan.collectOS so we don't pull in the rest of the facts.
func detectOSForPackages(hostRoot string) (string, string) {
	f := hostscan.Collect(context.Background(), hostscan.Options{HostRoot: hostRoot})
	return f.OS.ID, f.OS.VersionID
}
