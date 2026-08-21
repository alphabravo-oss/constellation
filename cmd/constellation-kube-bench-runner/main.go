// constellation-kube-bench-runner executes the upstream kube-bench (or
// docker-bench) binary, reads its --json output, and POSTs the raw report to
// the control-plane compliance ingest endpoint. It is deliberately thin: it
// shells the upstream benchmark and forwards the bytes — all parsing and
// cross-framework expansion happens server-side in compliance.Compliance.Ingest.
//
// ponytail: the kube-bench (or docker-bench) binary MUST be present in the
// image at BENCH_BINARY (default "kube-bench"). We do NOT vendor or reimplement
// the benchmark; the runner only orchestrates exec -> read -> POST.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/pkg/version"
)

const (
	defaultBinary    = "kube-bench"
	defaultProfile   = "kube-bench"
	postTimeout      = 15 * time.Second
	benchRunTimeout  = 5 * time.Minute
	maxReportBytes   = 16 << 20
	componentName    = "kube-bench-runner"
	ingestPathFormat = "/api/v1/compliance/ingest?profile=%s"
)

type config struct {
	hbCfg     version.HeartbeatConfig
	apiURL    string
	token     string
	binary    string
	args      []string
	profile   string
	benchmark string
	clusterID string
	node      string
	// watchInterval > 0 turns the runner into a resident poller for on-demand
	// run requests (CMP-RUN-31). Zero = one-shot CronJob mode.
	watchInterval time.Duration
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "constellation-kube-bench-runner")
	version.LogStartup(logger, componentName)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", "err", err.Error())
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// CMP-RUN-31: watch mode. When BENCH_WATCH_INTERVAL is set the runner stays
	// resident and polls the control plane for on-demand run requests
	// (POST /compliance/bench/claim) instead of running once and exiting. This is
	// what turns the enqueue handler into a fresh benchmark run. Default (unset) =
	// the historical one-shot CronJob behaviour.
	if cfg.watchInterval > 0 {
		watchLoop(ctx, http.DefaultClient, cfg, logger)
		return
	}

	if err := runAndIngest(ctx, http.DefaultClient, cfg, logger); err != nil {
		logger.Error("bench run", "err", err.Error())
		os.Exit(1)
	}

	// Best-effort heartbeat so the runner shows up in the components table like
	// the other one-shot jobs (compliance-collector).
	if version.HeartbeatConfigured(cfg.hbCfg) {
		if err := version.SendOnceExternal(ctx, cfg.hbCfg); err != nil {
			logger.Warn("heartbeat failed", "err", err.Error())
		}
	}
}

// runAndIngest execs the benchmark and POSTs the report to /compliance/ingest,
// attributing the results to this cluster/node. Shared by the one-shot and watch
// paths.
func runAndIngest(ctx context.Context, client *http.Client, cfg config, logger *slog.Logger) error {
	report, err := runBenchmark(ctx, cfg.binary, cfg.args)
	if err != nil {
		return fmt.Errorf("run benchmark %s: %w", cfg.binary, err)
	}

	endpoint := strings.TrimRight(cfg.apiURL, "/") + fmt.Sprintf(ingestPathFormat, cfg.profile)
	if cfg.benchmark != "" {
		endpoint += "&benchmark=" + url.QueryEscape(cfg.benchmark)
	}
	// CMP-CLOBBER-03: attribute the results to this cluster (and node, where the runner
	// runs per-node) so multi-cluster tenants no longer clobber each other's rows. Both
	// are optional query params the ingest handler reads; empty is left off.
	if cfg.clusterID != "" {
		endpoint += "&cluster_id=" + url.QueryEscape(cfg.clusterID)
	}
	if cfg.node != "" {
		endpoint += "&node=" + url.QueryEscape(cfg.node)
	}
	if err := postReport(ctx, client, endpoint, cfg.token, report); err != nil {
		return fmt.Errorf("post report %s: %w", endpoint, err)
	}
	logger.Info("ingest succeeded", "profile", cfg.profile, "benchmark", cfg.benchmark, "bytes", len(report))
	return nil
}

// watchLoop polls the control plane for pending on-demand run requests and
// services each one by running the benchmark and ingesting the report. It also
// heartbeats on every tick so the resident runner stays visible in the health
// table. The loop exits when ctx is cancelled.
func watchLoop(ctx context.Context, client *http.Client, cfg config, logger *slog.Logger) {
	logger.Info("watch mode started", "interval", cfg.watchInterval.String(), "profile", cfg.profile)
	ticker := time.NewTicker(cfg.watchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("watch mode stopping")
			return
		case <-ticker.C:
			claimed, err := claimPendingRun(ctx, client, cfg)
			if err != nil {
				logger.Warn("claim poll failed", "err", err.Error())
			} else if claimed {
				logger.Info("claimed on-demand bench run; executing")
				if err := runAndIngest(ctx, client, cfg, logger); err != nil {
					logger.Error("on-demand bench run", "err", err.Error())
				}
			}
			if version.HeartbeatConfigured(cfg.hbCfg) {
				if err := version.SendOnceExternal(ctx, cfg.hbCfg); err != nil {
					logger.Warn("heartbeat failed", "err", err.Error())
				}
			}
		}
	}
}

// claimPendingRun asks the control plane for the next pending run request for
// this cluster+profile. HTTP 200 => a request was claimed (run it); 204 => queue
// empty. The claim is atomic server-side (FOR UPDATE SKIP LOCKED).
func claimPendingRun(ctx context.Context, client *http.Client, cfg config) (bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, postTimeout)
	defer cancel()
	endpoint := strings.TrimRight(cfg.apiURL, "/") + "/api/v1/compliance/bench/claim?profile=" + url.QueryEscape(cfg.profile)
	if cfg.clusterID != "" {
		endpoint += "&cluster_id=" + url.QueryEscape(cfg.clusterID)
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxReportBytes))
	switch {
	case resp.StatusCode == http.StatusNoContent:
		return false, nil
	case resp.StatusCode == http.StatusOK:
		return true, nil
	default:
		return false, fmt.Errorf("claim returned %d", resp.StatusCode)
	}
}

func loadConfig() (config, error) {
	apiURL := firstNonEmpty(os.Getenv("CONSTELLATION_API_URL"), os.Getenv("CONSTELLATION_CONTROL_PLANE_URL"))
	if apiURL == "" {
		return config{}, errors.New("CONSTELLATION_API_URL required")
	}
	profile := strings.TrimSpace(os.Getenv("BENCH_PROFILE"))
	if profile == "" {
		profile = defaultProfile
	}
	binary := strings.TrimSpace(os.Getenv("BENCH_BINARY"))
	if binary == "" {
		binary = defaultBinary
	}
	args := splitArgs(os.Getenv("BENCH_ARGS"))
	if !hasJSONFlag(args) {
		args = append(args, "--json")
	}
	// BENCH_VERSION pins the CIS benchmark id (e.g. eks-1.4.0, gke-1.6.0,
	// cis-1.9). Empty = let kube-bench auto-detect from the running distro/k8s
	// version. When set we pass it through to kube-bench AND forward it on the
	// ingest query so the parsed rows are tagged with the right CIS profile even
	// if the JSON report omits a per-control version.
	benchmark := strings.TrimSpace(os.Getenv("BENCH_VERSION"))
	if benchmark != "" && !hasBenchmarkFlag(args) {
		args = append(args, "--benchmark", benchmark)
	}

	// BENCH_WATCH_INTERVAL (e.g. "30s") opts the runner into resident watch mode.
	var watchInterval time.Duration
	if raw := strings.TrimSpace(os.Getenv("BENCH_WATCH_INTERVAL")); raw != "" {
		d, perr := time.ParseDuration(raw)
		if perr != nil {
			return config{}, fmt.Errorf("invalid BENCH_WATCH_INTERVAL %q: %w", raw, perr)
		}
		watchInterval = d
	}

	hbCfg := version.HeartbeatConfigFromEnv(componentName, version.HeartbeatEnvOptions{
		APIBaseURL:   apiURL,
		TokenEnv:     []string{"CONSTELLATION_KUBE_BENCH_RUNNER_TOKEN", "RUNTIME_AGENT_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_KUBE_BENCH_RUNNER_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE"},
		Logger:       slog.Default(),
	})
	token := hbCfg.Token
	if token == "" && hbCfg.TokenFn != nil {
		token = strings.TrimSpace(hbCfg.TokenFn())
	}
	if token == "" {
		return config{}, errors.New("ingest token required (set CONSTELLATION_KUBE_BENCH_RUNNER_TOKEN or RUNTIME_AGENT_TOKEN[_FILE])")
	}

	return config{
		hbCfg:     hbCfg,
		apiURL:    apiURL,
		token:     token,
		binary:    binary,
		args:      args,
		profile:   profile,
		benchmark: benchmark,
		clusterID: hbCfg.ClusterID,
		// NODE_NAME is the standard downward-API field-ref env; set it on the pod spec
		// when the runner runs per-node so results dedup per (cluster, node). Empty for a
		// cluster-level run — the ingest handler then keys on the cluster alone.
		node:          strings.TrimSpace(os.Getenv("NODE_NAME")),
		watchInterval: watchInterval,
	}, nil
}

// runBenchmark execs the upstream benchmark binary and returns its stdout (the
// --json report). It does not parse the bytes.
func runBenchmark(ctx context.Context, binary string, args []string) ([]byte, error) {
	runCtx, cancel := context.WithTimeout(ctx, benchRunTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w (stderr: %s)", binary, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 {
		return nil, fmt.Errorf("%s produced no output", binary)
	}
	return out, nil
}

// postReport sends the raw benchmark JSON to the compliance ingest endpoint
// using the same bearer-token auth the collector heartbeat uses. This function
// holds the testable read-and-post payload shaping.
func postReport(ctx context.Context, client *http.Client, endpoint, token string, report []byte) error {
	reqCtx, cancel := context.WithTimeout(ctx, postTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(report))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("ingest returned %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// splitArgs splits a whitespace-delimited BENCH_ARGS string. ponytail: simple
// whitespace split — no shell quoting. kube-bench flags don't need spaces in
// values, so this ceiling is fine.
func splitArgs(raw string) []string {
	return strings.Fields(raw)
}

func hasJSONFlag(args []string) bool {
	for _, a := range args {
		if a == "--json" {
			return true
		}
	}
	return false
}

func hasBenchmarkFlag(args []string) bool {
	for _, a := range args {
		if a == "--benchmark" || strings.HasPrefix(a, "--benchmark=") {
			return true
		}
	}
	return false
}
