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

// Process baseline sync — pulls the per-workload process baselines (mode +
// allowed basenames) the agent-side enforcer kills out-of-baseline execs
// against. 1:1 with FileProfileRuleSyncWorker but for process baselines.

type ProcessBaselineSyncConfig struct {
	APIBaseURL string
	Token      string
	ClusterID  string
	Node       string
	Interval   time.Duration
	HTTPClient *http.Client
	Logger     *slog.Logger
	// DPSup is optional. This worker enforces agent-side (kill-on-exec) and
	// never pushes to dp, so it has no readiness gate; DPSup is used only to
	// detect a dp restart (generation bump) and force a cache re-emit. Nil ⇒ no
	// generation tracking.
	DPSup *dp.Supervisor
}

type processBaselineRowWire struct {
	WorkloadID     string   `json:"workload_id"`
	PodWorkloadIDs []string `json:"pod_workload_ids,omitempty"`
	Namespace      string   `json:"namespace,omitempty"`
	Name           string   `json:"name,omitempty"`
	Mode           string   `json:"mode"`
	Processes      []string `json:"processes"`
	// RT-MATCH-16: rich per-process entries (full path + sha256 + parent + action).
	// Present only from a server that emits them; empty => fall back to Processes.
	Entries   []processBaselineEntryWire `json:"entries,omitempty"`
	UpdatedAt string                     `json:"updated_at"`
}

// processBaselineEntryWire mirrors the server's processBundleEntry.
type processBaselineEntryWire struct {
	Basename   string `json:"basename,omitempty"`
	Path       string `json:"path,omitempty"`
	Sha256     string `json:"sha256,omitempty"`
	ParentName string `json:"parent_name,omitempty"`
	Action     string `json:"action"`
}

type processBaselineBundleWire struct {
	ClusterID   string                   `json:"cluster_id"`
	GeneratedAt string                   `json:"generated_at"`
	Rows        []processBaselineRowWire `json:"rows"`
}

type ProcessBaselineSyncWorker struct {
	cfg ProcessBaselineSyncConfig

	mu          sync.RWMutex
	rows        []processBaselineRowWire
	fingerprint string
	lastGen     uint64

	syncs    atomic.Uint64
	updates  atomic.Uint64
	errors   atomic.Uint64
	lastSync atomic.Int64
}

func NewProcessBaselineSyncWorker(cfg ProcessBaselineSyncConfig) *ProcessBaselineSyncWorker {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &ProcessBaselineSyncWorker{cfg: cfg}
}

func (w *ProcessBaselineSyncWorker) Run(ctx context.Context) {
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

func (w *ProcessBaselineSyncWorker) SyncOnce(ctx context.Context) {
	w.syncs.Add(1)
	w.lastSync.Store(time.Now().Unix())
	if strings.TrimSpace(w.cfg.ClusterID) == "" {
		return
	}
	bundle, err := w.fetch(ctx)
	if err != nil {
		w.errors.Add(1)
		w.cfg.Logger.Warn("process baseline sync: fetch failed", slog.String("err", err.Error()))
		return
	}
	fp := fingerprintProcessBaselines(bundle.Rows)
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
		w.rows = append([]processBaselineRowWire(nil), bundle.Rows...)
		w.fingerprint = fp
		w.lastGen = gen
	}
	w.mu.Unlock()
	if changed {
		w.updates.Add(1)
		w.cfg.Logger.Info("process baseline sync: updated",
			slog.Int("rows", len(bundle.Rows)),
			slog.String("fingerprint", fp))
	}
}

func (w *ProcessBaselineSyncWorker) Rows() []processBaselineRowWire {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]processBaselineRowWire(nil), w.rows...)
}

func (w *ProcessBaselineSyncWorker) RowsWithFingerprint() ([]processBaselineRowWire, string) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]processBaselineRowWire(nil), w.rows...), w.fingerprint
}

func (w *ProcessBaselineSyncWorker) fetch(ctx context.Context) (processBaselineBundleWire, error) {
	url := strings.TrimRight(w.cfg.APIBaseURL, "/") +
		"/api/v1/runtime/process-baselines:bundle?cluster_id=" + w.cfg.ClusterID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return processBaselineBundleWire{}, err
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return processBaselineBundleWire{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return processBaselineBundleWire{}, fmt.Errorf("server %d", resp.StatusCode)
	}
	var out processBaselineBundleWire
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return processBaselineBundleWire{}, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}

func fingerprintProcessBaselines(rows []processBaselineRowWire) string {
	h := sha256.New()
	for _, row := range rows {
		_, _ = h.Write([]byte(row.WorkloadID))
		_, _ = h.Write([]byte{0})
		for _, p := range row.PodWorkloadIDs {
			_, _ = h.Write([]byte(p))
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(row.Mode))
		_, _ = h.Write([]byte{0})
		for _, p := range row.Processes {
			_, _ = h.Write([]byte(p))
			_, _ = h.Write([]byte{0})
		}
		for _, e := range row.Entries {
			_, _ = h.Write([]byte(e.Basename + "|" + e.Path + "|" + e.Sha256 + "|" + e.ParentName + "|" + e.Action))
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(row.UpdatedAt))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ----- enforcement status store (untagged: both _linux and _other use it) ----

type processEnforcementStatus struct {
	Protect bool
	State   string // "enforced" once a kill has fired for the workload
}

type processEnforcementStatusStore struct {
	mu sync.RWMutex
	m  map[string]processEnforcementStatus
}

func newProcessEnforcementStatusStore() *processEnforcementStatusStore {
	return &processEnforcementStatusStore{m: map[string]processEnforcementStatus{}}
}

func (s *processEnforcementStatusStore) Replace(workloadID string, st processEnforcementStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[workloadID] = st
}

func (s *processEnforcementStatusStore) Get(workloadID string) (processEnforcementStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.m[workloadID]
	return st, ok
}
