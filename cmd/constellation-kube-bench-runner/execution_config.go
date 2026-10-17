package main

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func configureExecutionWorker(cfg *config) error {
	raw := strings.TrimSpace(os.Getenv("BENCH_EXECUTION_WORKER"))
	if raw == "" || raw == "false" {
		return nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil || !enabled {
		return errors.New("invalid BENCH_EXECUTION_WORKER")
	}
	if cfg.profile != "kube-bench" {
		return errors.New("durable docker-bench worker unsupported: upstream executable and configuration are not bundled")
	}
	if cfg.clusterID != "" && !validExecutionUUID(cfg.clusterID) {
		return errors.New("benchmark worker configured cluster must be a canonical nonzero UUID")
	}
	origin, err := url.Parse(cfg.apiURL)
	if err != nil || origin.Hostname() == "" || origin.User != nil || origin.Scheme != "http" && origin.Scheme != "https" || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" && origin.Path != "/" {
		return errors.New("benchmark worker requires a configured HTTP(S) control-plane origin")
	}
	cfg.spoolDir = strings.TrimSpace(os.Getenv("BENCH_STATE_DIR"))
	cfg.runnerID = strings.TrimSpace(os.Getenv("POD_UID"))
	if !filepath.IsAbs(cfg.spoolDir) || !validExecutionUUID(cfg.runnerID) || len(cfg.node) == 0 || len(cfg.node) > 253 || strings.ContainsAny(cfg.node, "\r\n\x00") {
		return errors.New("benchmark worker requires persistent BENCH_STATE_DIR, POD_UID, and NODE_NAME")
	}
	if cfg.watchInterval == 0 {
		cfg.watchInterval = 30 * time.Second
	}
	if cfg.watchInterval < time.Second || cfg.watchInterval > 5*time.Minute {
		return errors.New("benchmark worker interval must be between one second and five minutes")
	}
	cfg.durableWorker = true
	return nil
}
