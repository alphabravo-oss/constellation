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
	"strings"
	"sync"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
)

type fileProfileFilesConfig struct {
	APIBaseURL        string
	Token             string
	NodeName          string
	ClusterID         string
	Interval          time.Duration
	HostRoot          string
	CrictlBin         string
	RuleSync          *FileProfileRuleSyncWorker
	EnforcementStatus *fileProfileEnforcementStatusStore
	Logger            *slog.Logger
}

type fileProfileWatchReport struct {
	ClusterID         string                          `json:"cluster_id"`
	Node              string                          `json:"node"`
	ObservedAt        time.Time                       `json:"observed_at"`
	BundleFingerprint string                          `json:"bundle_fingerprint"`
	Rules             []hostscan.FileProfileWatchRule `json:"rules"`
}

func fileProfileFilesLoop(ctx context.Context, cfg fileProfileFilesConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.APIBaseURL == "" || cfg.Token == "" || strings.TrimSpace(cfg.ClusterID) == "" || cfg.RuleSync == nil {
		cfg.Logger.Info("file-profile-files: disabled (missing api url, token, cluster id, or rule sync)")
		return
	}
	url := strings.TrimRight(cfg.APIBaseURL, "/") + "/api/v1/runtime/file-profile-watches:report"
	cli := &http.Client{Timeout: 2 * time.Minute}

	tick := time.NewTimer(10 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			rules, fingerprint := cfg.RuleSync.RulesWithFingerprint()
			if len(rules) == 0 {
				report := fileProfileWatchReport{
					ClusterID:         cfg.ClusterID,
					Node:              cfg.NodeName,
					ObservedAt:        time.Now().UTC(),
					BundleFingerprint: fingerprint,
					Rules:             []hostscan.FileProfileWatchRule{},
				}
				if report.Node == "" {
					if host, _ := os.Hostname(); host != "" {
						report.Node = host
					}
				}
				if err := postFileProfileWatches(ctx, cli, url, cfg.Token, report); err != nil {
					cfg.Logger.Warn("file-profile-files: empty report failed", slog.String("err", err.Error()))
				}
				tick.Reset(cfg.Interval)
				continue
			}
			containers, err := hostscan.CollectContainers(ctx, hostscan.ContainersOptions{
				HostRoot:  cfg.HostRoot,
				NodeName:  cfg.NodeName,
				CrictlBin: cfg.CrictlBin,
			})
			if err != nil {
				cfg.Logger.Warn("file-profile-files: container inventory failed", slog.String("err", err.Error()))
				tick.Reset(cfg.Interval)
				continue
			}
			snapshot, err := hostscan.CollectFileProfileWatches(ctx, hostscan.FileProfileWatchOptions{
				HostRoot:        cfg.HostRoot,
				NodeName:        cfg.NodeName,
				CrictlBin:       cfg.CrictlBin,
				Containers:      containers,
				Rules:           hostscanRulesFromWire(rules),
				MaxFilesPerRule: fileProfileMaxFilesPerRule(),
				MaxWalkDepth:    fileProfileMaxWalkDepth(),
				HashMaxBytes:    fileProfileHashMaxBytes(),
			})
			if err != nil {
				cfg.Logger.Warn("file-profile-files: collection failed", slog.String("err", err.Error()))
				tick.Reset(cfg.Interval)
				continue
			}
			report := fileProfileWatchReport{
				ClusterID:         cfg.ClusterID,
				Node:              snapshot.Node,
				ObservedAt:        snapshot.ObservedAt,
				BundleFingerprint: fingerprint,
				Rules:             applyFileProfileEnforcementStatus(snapshot.Rules, cfg.EnforcementStatus),
			}
			if err := postFileProfileWatches(ctx, cli, url, cfg.Token, report); err != nil {
				cfg.Logger.Warn("file-profile-files: report failed", slog.String("err", err.Error()))
				tick.Reset(cfg.Interval)
				continue
			}
			cfg.Logger.Info("file-profile-files: reported",
				slog.String("node", report.Node),
				slog.Int("rules", len(report.Rules)),
				slog.String("fingerprint", fingerprint))
			tick.Reset(cfg.Interval)
		}
	}
}

type fileProfileEnforcementStatus struct {
	Protect bool
	State   string
}

type fileProfileEnforcementStatusStore struct {
	mu    sync.RWMutex
	rules map[string]fileProfileEnforcementStatus
}

func newFileProfileEnforcementStatusStore() *fileProfileEnforcementStatusStore {
	return &fileProfileEnforcementStatusStore{rules: map[string]fileProfileEnforcementStatus{}}
}

func (s *fileProfileEnforcementStatusStore) Replace(next map[string]fileProfileEnforcementStatus) {
	if s == nil {
		return
	}
	cp := make(map[string]fileProfileEnforcementStatus, len(next))
	for id, status := range next {
		id = strings.TrimSpace(id)
		status.State = strings.TrimSpace(status.State)
		if id == "" || status.State == "" {
			continue
		}
		cp[id] = status
	}
	s.mu.Lock()
	s.rules = cp
	s.mu.Unlock()
}

func (s *fileProfileEnforcementStatusStore) Get(ruleID string) (fileProfileEnforcementStatus, bool) {
	if s == nil {
		return fileProfileEnforcementStatus{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	status, ok := s.rules[strings.TrimSpace(ruleID)]
	return status, ok
}

func applyFileProfileEnforcementStatus(in []hostscan.FileProfileWatchRule, store *fileProfileEnforcementStatusStore) []hostscan.FileProfileWatchRule {
	out := make([]hostscan.FileProfileWatchRule, len(in))
	copy(out, in)
	for i := range out {
		status, ok := store.Get(out[i].ID)
		if !ok {
			continue
		}
		out[i].Protect = status.Protect
		out[i].Enforcement = status.State
	}
	return out
}

func postFileProfileWatches(ctx context.Context, cli *http.Client, url, token string, report fileProfileWatchReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func hostscanRulesFromWire(in []fileProfileRuleWire) []hostscan.FileProfileRule {
	out := make([]hostscan.FileProfileRule, 0, len(in))
	for _, rule := range in {
		out = append(out, hostscan.FileProfileRule{
			ID:             rule.ID,
			WorkloadID:     rule.WorkloadID,
			PodWorkloadIDs: append([]string(nil), rule.PodWorkloadIDs...),
			Mode:           rule.Mode,
			Filter:         rule.Filter,
			Path:           rule.Path,
			Regex:          rule.Regex,
			Recursive:      rule.Recursive,
			Behavior:       rule.Behavior,
		})
	}
	return out
}

func fileProfileMaxFilesPerRule() int {
	n, _ := strconv.Atoi(os.Getenv("CONSTELLATION_FILE_PROFILE_MAX_FILES_PER_RULE"))
	if n <= 0 || n > 1000 {
		return 200
	}
	return n
}

func fileProfileMaxWalkDepth() int {
	n, _ := strconv.Atoi(os.Getenv("CONSTELLATION_FILE_PROFILE_MAX_WALK_DEPTH"))
	if n <= 0 || n > 32 {
		return 8
	}
	return n
}

// fileProfileHashMaxBytes controls B3 content hashing of watched files. Content
// hashing is a pure-observation enhancement (monitor by default) so it is ON by
// default with a conservative per-file cap; set the env to 0 (or negative) to
// disable, or raise it to hash larger files. Files above the cap are skipped
// (Sha256 left empty) so a giant log file can't dominate a scan cycle.
func fileProfileHashMaxBytes() int64 {
	raw := strings.TrimSpace(os.Getenv("CONSTELLATION_FILE_PROFILE_HASH_MAX_BYTES"))
	if raw == "" {
		return 4 << 20 // 4 MiB default
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 4 << 20
	}
	return n // 0 explicitly disables hashing
}
