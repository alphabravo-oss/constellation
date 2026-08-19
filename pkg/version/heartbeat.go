package version

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// HeartbeatPayload is the JSON body POSTed to /api/v1/heartbeats every 30s by
// each component. The server upserts on (org_id, cluster_id, component, hostname)
// and uses a decreasing uptime to infer a restart.
type HeartbeatPayload struct {
	Component     string `json:"component"`
	ClusterID     string `json:"cluster_id,omitempty"`
	ClusterName   string `json:"cluster_name,omitempty"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	BuildTime     string `json:"build_time,omitempty"`
	Hostname      string `json:"hostname"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	LastError     string `json:"last_error,omitempty"`
	RestartCount  int    `json:"restart_count,omitempty"`
	Metadata      any    `json:"metadata,omitempty"`
}

// HeartbeatConfig configures the periodic heartbeat poster.
//
// APIBaseURL must not include the /api/v1 suffix — we add it.
// Token is the scanner-token / runtime-agent-token; the server selects the
// correct middleware based on the route. Component is the logical name
// recorded in the heartbeats table ('scanner', 'runtime-agent', etc.).
type HeartbeatConfig struct {
	APIBaseURL  string
	Token       string
	TokenFn     func() string
	Component   string
	ClusterID   string
	ClusterName string
	Interval    time.Duration
	Logger      *slog.Logger
	HTTPClient  *http.Client
	// LastErrorFn lets callers expose their most recent failure (e.g. last
	// upload error) without depending on this package. Nil-safe.
	LastErrorFn func() string
	// MetadataFn lets callers expose role-specific, bounded health/capacity
	// details without changing the heartbeat endpoint for every component.
	MetadataFn func() any
}

// HeartbeatLoop posts a heartbeat to the API on Interval until ctx is canceled.
//
// The loop is intentionally tolerant: any HTTP / network error is logged at
// WARN and the loop continues. We never want a control-plane outage to crash
// a data-plane agent.
func HeartbeatLoop(ctx context.Context, cfg HeartbeatConfig) {
	if cfg.APIBaseURL == "" || (cfg.Token == "" && cfg.TokenFn == nil) {
		// No control plane configured (dev mode / stdout-only). Skip silently
		// after a single INFO so operators see the intent.
		if cfg.Logger != nil {
			cfg.Logger.Info("heartbeat.disabled", slog.String("component", cfg.Component), slog.String("reason", "missing api_url or token"))
		}
		return
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	url := strings.TrimRight(cfg.APIBaseURL, "/") + "/api/v1/heartbeats"

	// Send one immediately so the row exists before the first tick fires —
	// the UI's "stale" threshold is 5 minutes so an empty grid for 30s after
	// boot is unhelpful.
	sendOnce(ctx, client, url, cfg)

	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	var sent atomic.Uint64
	for {
		select {
		case <-ctx.Done():
			cfg.Logger.Info("heartbeat.stopped",
				slog.String("component", cfg.Component),
				slog.Uint64("sent", sent.Load()))
			return
		case <-t.C:
			if sendOnce(ctx, client, url, cfg) {
				sent.Add(1)
			}
		}
	}
}

// sendOnce performs a single POST. Returns true on 2xx.
func sendOnce(ctx context.Context, client *http.Client, url string, cfg HeartbeatConfig) bool {
	token := cfg.Token
	if token == "" && cfg.TokenFn != nil {
		token = strings.TrimSpace(cfg.TokenFn())
	}
	if token == "" {
		cfg.Logger.Debug("heartbeat.token_missing", slog.String("component", cfg.Component))
		return false
	}
	payload := HeartbeatPayload{
		Component:     cfg.Component,
		ClusterID:     cfg.ClusterID,
		ClusterName:   cfg.ClusterName,
		Version:       Version,
		Commit:        Commit,
		BuildTime:     BuildTime,
		Hostname:      InfoFor(cfg.Component).Hostname,
		UptimeSeconds: int64(Uptime().Seconds()),
	}
	if cfg.LastErrorFn != nil {
		payload.LastError = cfg.LastErrorFn()
	}
	if cfg.MetadataFn != nil {
		payload.Metadata = cfg.MetadataFn()
	}

	body, err := json.Marshal(payload)
	if err != nil {
		cfg.Logger.Warn("heartbeat.marshal", slog.String("err", err.Error()))
		return false
	}

	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		cfg.Logger.Warn("heartbeat.req", slog.String("err", err.Error()))
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// Don't spam the log on every tick when the control plane is down;
		// downgrade to DEBUG on connection-refused / dial-timeout repeats.
		if isTransient(err) {
			cfg.Logger.Debug("heartbeat.post.transient",
				slog.String("component", cfg.Component),
				slog.String("err", err.Error()))
		} else {
			cfg.Logger.Warn("heartbeat.post",
				slog.String("component", cfg.Component),
				slog.String("err", err.Error()))
		}
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		cfg.Logger.Warn("heartbeat.status",
			slog.String("component", cfg.Component),
			slog.Int("status", resp.StatusCode),
			slog.String("body", strings.TrimSpace(string(buf))))
		return false
	}
	return true
}

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, hint := range []string{"connection refused", "no such host", "i/o timeout", "context deadline exceeded"} {
		if strings.Contains(msg, hint) {
			return true
		}
	}
	return false
}

// ErrMissingClusterID is returned by helpers that require a cluster context
// to be set up before they can produce a meaningful payload.
var ErrMissingClusterID = errors.New("heartbeat: cluster_id required")

// HeartbeatConfigured reports whether a component has enough configuration to
// try a heartbeat. It resolves TokenFn so one-shot jobs can see late-projected
// Kubernetes token files without duplicating that logic.
func HeartbeatConfigured(cfg HeartbeatConfig) bool {
	if cfg.APIBaseURL == "" {
		return false
	}
	if strings.TrimSpace(cfg.Token) != "" {
		return true
	}
	return cfg.TokenFn != nil && strings.TrimSpace(cfg.TokenFn()) != ""
}

// SendOnceExternal is exported for callers (tests, one-shot CLIs) that just
// want to fire a single heartbeat without spinning up a goroutine. The
// returned error preserves the HTTP body for debugging.
func SendOnceExternal(ctx context.Context, cfg HeartbeatConfig) error {
	if cfg.APIBaseURL == "" {
		return errors.New("heartbeat: api url required")
	}
	if cfg.Token == "" && cfg.TokenFn != nil {
		cfg.Token = strings.TrimSpace(cfg.TokenFn())
	}
	if cfg.Token == "" {
		return errors.New("heartbeat: token required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	url := strings.TrimRight(cfg.APIBaseURL, "/") + "/api/v1/heartbeats"
	if ok := sendOnce(ctx, client, url, cfg); !ok {
		return fmt.Errorf("heartbeat: send failed (component=%s)", cfg.Component)
	}
	return nil
}
