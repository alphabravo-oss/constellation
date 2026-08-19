package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

type FileProfileRuleSyncConfig struct {
	APIBaseURL string
	Token      string
	ClusterID  string
	Node       string
	Interval   time.Duration
	HTTPClient *http.Client
	Logger     *slog.Logger
	// DPSup is optional. This worker enforces agent-side (fanotify) and never
	// pushes to dp, so it has no readiness gate; DPSup is used only to detect a
	// dp restart (generation bump) and force a cache re-emit so downstream
	// consumers observe a fresh update. Nil ⇒ no generation tracking.
	DPSup *dp.Supervisor
}

type fileProfileRuleWire struct {
	ID             string                     `json:"id"`
	WorkloadID     string                     `json:"workload_id"`
	PodWorkloadIDs []string                   `json:"pod_workload_ids,omitempty"`
	Namespace      string                     `json:"namespace,omitempty"`
	Name           string                     `json:"name,omitempty"`
	Mode           string                     `json:"mode"`
	Filter         string                     `json:"filter"`
	Path           string                     `json:"path"`
	Regex          string                     `json:"regex"`
	Recursive      bool                       `json:"recursive"`
	Behavior       string                     `json:"behavior"`
	Applications   []string                   `json:"applications"`
	Exceptions     []fileProfileExceptionWire `json:"exceptions,omitempty"`
	Description    string                     `json:"description,omitempty"`
	UpdatedAt      string                     `json:"updated_at"`
}

type fileProfileExceptionWire struct {
	ID           string   `json:"id"`
	RuleID       string   `json:"rule_id,omitempty"`
	Filter       string   `json:"filter"`
	Path         string   `json:"path"`
	Regex        string   `json:"regex"`
	Recursive    bool     `json:"recursive"`
	Applications []string `json:"applications"`
	Description  string   `json:"description,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	UpdatedAt    string   `json:"updated_at"`
}

type fileProfileRuleBundleWire struct {
	ClusterID   string                `json:"cluster_id"`
	GeneratedAt string                `json:"generated_at"`
	Rules       []fileProfileRuleWire `json:"rules"`
}

type FileProfileRuleSyncWorker struct {
	cfg FileProfileRuleSyncConfig

	mu          sync.RWMutex
	rules       []fileProfileRuleWire
	fingerprint string
	lastGen     uint64

	syncs    atomic.Uint64
	updates  atomic.Uint64
	errors   atomic.Uint64
	lastSync atomic.Int64
}

func NewFileProfileRuleSyncWorker(cfg FileProfileRuleSyncConfig) *FileProfileRuleSyncWorker {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &FileProfileRuleSyncWorker{cfg: cfg}
}

func (w *FileProfileRuleSyncWorker) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}
	w.SyncOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.SyncOnce(ctx)
		}
	}
}

func (w *FileProfileRuleSyncWorker) SyncOnce(ctx context.Context) {
	w.syncs.Add(1)
	w.lastSync.Store(time.Now().Unix())
	if strings.TrimSpace(w.cfg.ClusterID) == "" {
		return
	}
	bundle, err := w.fetch(ctx)
	if err != nil {
		w.errors.Add(1)
		w.cfg.Logger.Warn("file profile rule sync: fetch failed", slog.String("err", err.Error()))
		return
	}
	fp := fingerprintFileProfileRules(bundle.Rules)
	var gen uint64
	if w.cfg.DPSup != nil {
		gen = w.cfg.DPSup.Generation()
	}
	w.mu.Lock()
	// A dp generation bump (restart) forces a re-emit even when the fingerprint
	// is unchanged, so this config type resyncs on restart like the dp-pushing
	// workers do.
	force := w.cfg.DPSup != nil && gen != w.lastGen
	changed := fp != w.fingerprint || force
	if changed {
		w.rules = append([]fileProfileRuleWire(nil), bundle.Rules...)
		w.fingerprint = fp
		w.lastGen = gen
	}
	w.mu.Unlock()
	if changed {
		w.updates.Add(1)
		w.cfg.Logger.Info("file profile rule sync: updated",
			slog.Int("rules", len(bundle.Rules)),
			slog.String("fingerprint", fp))
	}
}

func (w *FileProfileRuleSyncWorker) Rules() []fileProfileRuleWire {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]fileProfileRuleWire(nil), w.rules...)
}

func (w *FileProfileRuleSyncWorker) RulesWithFingerprint() ([]fileProfileRuleWire, string) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]fileProfileRuleWire(nil), w.rules...), w.fingerprint
}

func (w *FileProfileRuleSyncWorker) fetch(ctx context.Context) (fileProfileRuleBundleWire, error) {
	url := strings.TrimRight(w.cfg.APIBaseURL, "/") +
		"/api/v1/runtime/file-profile-rules:bundle?cluster_id=" + w.cfg.ClusterID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fileProfileRuleBundleWire{}, err
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return fileProfileRuleBundleWire{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fileProfileRuleBundleWire{}, fmt.Errorf("server %d", resp.StatusCode)
	}
	var out fileProfileRuleBundleWire
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fileProfileRuleBundleWire{}, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}

func fingerprintFileProfileRules(rules []fileProfileRuleWire) string {
	h := sha256.New()
	for _, rule := range rules {
		_, _ = h.Write([]byte(rule.ID))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(rule.WorkloadID))
		_, _ = h.Write([]byte{0})
		for _, podWorkloadID := range rule.PodWorkloadIDs {
			_, _ = h.Write([]byte(podWorkloadID))
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(rule.Namespace))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(rule.Name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(rule.Mode))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(rule.Filter))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(rule.Path))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(rule.Regex))
		_, _ = h.Write([]byte{0})
		if rule.Recursive {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(rule.Behavior))
		_, _ = h.Write([]byte{0})
		for _, app := range rule.Applications {
			_, _ = h.Write([]byte(app))
			_, _ = h.Write([]byte{0})
		}
		for _, exception := range rule.Exceptions {
			_, _ = h.Write([]byte(exception.ID))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(exception.RuleID))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(exception.Filter))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(exception.Path))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(exception.Regex))
			_, _ = h.Write([]byte{0})
			if exception.Recursive {
				_, _ = h.Write([]byte{1})
			} else {
				_, _ = h.Write([]byte{0})
			}
			for _, app := range exception.Applications {
				_, _ = h.Write([]byte(app))
				_, _ = h.Write([]byte{0})
			}
			_, _ = h.Write([]byte(exception.Description))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(exception.ExpiresAt))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(exception.UpdatedAt))
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(rule.Description))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(rule.UpdatedAt))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
