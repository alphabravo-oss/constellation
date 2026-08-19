package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
)

type workloadPackagesConfig struct {
	APIBaseURL string
	Token      string
	NodeName   string
	ClusterID  string
	Interval   time.Duration
	HostRoot   string
	CrictlBin  string
	Logger     *slog.Logger
}

type workloadPackagesReport struct {
	ClusterID  string                      `json:"cluster_id,omitempty"`
	Node       string                      `json:"node"`
	ObservedAt time.Time                   `json:"observed_at"`
	Runtime    string                      `json:"runtime,omitempty"`
	WorkloadID string                      `json:"workload_id"`
	Namespace  string                      `json:"namespace,omitempty"`
	PodName    string                      `json:"pod_name,omitempty"`
	PodUID     string                      `json:"pod_uid,omitempty"`
	Count      int                         `json:"count"`
	Containers []workloadPackagesContainer `json:"containers"`
}

type workloadPackagesContainer struct {
	ContainerID   string             `json:"container_id"`
	ContainerName string             `json:"container_name,omitempty"`
	ContainerPID  int                `json:"container_pid,omitempty"`
	Image         string             `json:"image,omitempty"`
	ImageRef      string             `json:"image_ref,omitempty"`
	Distro        string             `json:"distro,omitempty"`
	DistroVersion string             `json:"distro_version,omitempty"`
	Source        string             `json:"source,omitempty"`
	Count         int                `json:"count"`
	Items         []hostscan.Package `json:"items"`
}

func workloadPackagesLoop(ctx context.Context, cfg workloadPackagesConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	if cfg.APIBaseURL == "" || cfg.Token == "" {
		cfg.Logger.Info("workload-packages: disabled (no api url or token)")
		return
	}
	url := cfg.APIBaseURL + "/api/v1/workload-packages:report"
	cli := &http.Client{Timeout: 2 * time.Minute}

	tick := time.NewTimer(0)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			snap, err := hostscan.CollectContainers(ctx, hostscan.ContainersOptions{
				HostRoot:  cfg.HostRoot,
				NodeName:  cfg.NodeName,
				CrictlBin: cfg.CrictlBin,
			})
			if err != nil {
				cfg.Logger.Warn("workload-packages: container inventory failed", slog.String("err", err.Error()))
				tick.Reset(cfg.Interval)
				continue
			}

			inventories := make([]hostscan.ContainerPackages, 0, len(snap.Items))
			for _, c := range snap.Items {
				if !isRunningContainerState(c.State) {
					continue
				}
				workloadID := workloadIDForContainer(c)
				inv, err := hostscan.CollectContainerPackages(ctx, hostscan.ContainerPackagesOptions{
					HostRoot:   cfg.HostRoot,
					NodeName:   snap.Node,
					Container:  c,
					WorkloadID: workloadID,
					CrictlBin:  cfg.CrictlBin,
				})
				if err != nil {
					cfg.Logger.Debug("workload-packages: container package collection skipped",
						slog.String("container", c.ID),
						slog.String("workload", workloadID),
						slog.String("err", err.Error()))
					continue
				}
				if inv.Count == 0 {
					continue
				}
				inventories = append(inventories, inv)
			}

			reports := workloadPackageReportsFromInventories(cfg.ClusterID, inventories)
			for _, report := range reports {
				if err := postWorkloadPackages(ctx, cli, url, cfg.Token, report); err != nil {
					cfg.Logger.Error("workload-packages: report failed",
						slog.String("workload", report.WorkloadID),
						slog.String("err", err.Error()))
					continue
				}
				cfg.Logger.Info("workload-packages: reported",
					slog.String("node", report.Node),
					slog.String("workload", report.WorkloadID),
					slog.Int("containers", len(report.Containers)),
					slog.Int("packages", report.Count))
			}
			tick.Reset(cfg.Interval)
		}
	}
}

func isRunningContainerState(state string) bool {
	state = strings.ToLower(strings.TrimSpace(state))
	return state == "container_running" || state == "running"
}

func workloadIDForContainer(c hostscan.Container) string {
	if id := workloadIDFromPod(c.PodNS, c.PodName); id != "" {
		return id
	}
	return nodeLocalWorkloadID(c.ID)
}

func workloadPackageReportsFromInventories(clusterID string, inventories []hostscan.ContainerPackages) []workloadPackagesReport {
	type key struct {
		node       string
		workloadID string
	}
	byKey := map[key]*workloadPackagesReport{}
	order := []key{}
	for _, inv := range inventories {
		if inv.Count == 0 || strings.TrimSpace(inv.WorkloadID) == "" {
			continue
		}
		k := key{node: strings.TrimSpace(inv.Node), workloadID: strings.TrimSpace(inv.WorkloadID)}
		report := byKey[k]
		if report == nil {
			report = &workloadPackagesReport{
				ClusterID:  strings.TrimSpace(clusterID),
				Node:       k.node,
				ObservedAt: inv.ObservedAt,
				Runtime:    inv.Runtime,
				WorkloadID: k.workloadID,
				Namespace:  inv.Namespace,
				PodName:    inv.PodName,
				PodUID:     inv.PodUID,
			}
			byKey[k] = report
			order = append(order, k)
		}
		if inv.ObservedAt.After(report.ObservedAt) {
			report.ObservedAt = inv.ObservedAt
		}
		if report.Runtime == "" {
			report.Runtime = inv.Runtime
		}
		if report.Namespace == "" {
			report.Namespace = inv.Namespace
		}
		if report.PodName == "" {
			report.PodName = inv.PodName
		}
		if report.PodUID == "" {
			report.PodUID = inv.PodUID
		}
		report.Count += inv.Count
		report.Containers = append(report.Containers, workloadPackagesContainer{
			ContainerID:   inv.ContainerID,
			ContainerName: inv.ContainerName,
			ContainerPID:  inv.ContainerPID,
			Image:         inv.Image,
			ImageRef:      inv.ImageRef,
			Distro:        inv.Distro,
			DistroVersion: inv.DistroVersion,
			Source:        inv.Source,
			Count:         inv.Count,
			Items:         inv.Items,
		})
	}

	out := make([]workloadPackagesReport, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

func postWorkloadPackages(ctx context.Context, cli *http.Client, url, token string, report workloadPackagesReport) error {
	body, err := json.Marshal(report)
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
