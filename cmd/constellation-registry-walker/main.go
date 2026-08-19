// constellation-registry-walker is the periodic registry discovery daemon.
//
// Lifecycle mirrors cmd/constellation-discoverer: long-running, systemd-friendly,
// shutdown on SIGINT/SIGTERM.
//
// On every WALKER_INTERVAL (default 60s) the daemon:
//
//  1. Queries `registries` for rows whose cadence-derived next-sync time is in
//     the past (or whose last_sync_at is NULL for non-manual cadences).
//  2. Fans out to at most WALKER_CONCURRENCY (default 4) in-flight syncs.
//  3. For each registry: grabs pg_advisory_xact_lock on hashtext('reg:'||id),
//     decrypts creds, calls the matching adapter's ListImages, diffs the
//     repo+tag set against `registry_images`, and inserts a `scan_jobs` row for
//     every new tag.
//  4. Updates last_sync_at, last_sync_status, last_sync_error, images_seen.
//  5. Emits an audit row attributing the sync to the daemon principal (no
//     actor_id, since this is a service principal not a user).
//
// Required env:
//
//	DATABASE_URL          postgres DSN
//
// Optional env:
//
//	WALKER_INTERVAL       default 60s
//	WALKER_CONCURRENCY    default 4
//	CONSTELLATION_KEK     32-byte hex KEK; bootstrapped if absent
//	ONE_SHOT              "true" runs one tick and exits (used by integration tests)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/version"
)

const (
	defaultInterval    = 60 * time.Second
	defaultConcurrency = 4
)

type config struct {
	databaseURL string
	interval    time.Duration
	concurrency int
	oneShot     bool
}

func loadConfig() (config, error) {
	c := config{interval: defaultInterval, concurrency: defaultConcurrency}
	c.databaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if c.databaseURL == "" {
		return c, errors.New("DATABASE_URL is required")
	}
	if v := strings.TrimSpace(os.Getenv("WALKER_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("WALKER_INTERVAL: %w", err)
		}
		c.interval = d
	}
	if v := strings.TrimSpace(os.Getenv("WALKER_CONCURRENCY")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c, fmt.Errorf("WALKER_CONCURRENCY: %w", err)
		}
		if n < 1 {
			n = 1
		}
		c.concurrency = n
	}
	if v := strings.TrimSpace(os.Getenv("ONE_SHOT")); v == "true" || v == "1" {
		c.oneShot = true
	}
	return c, nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()}))
	slog.SetDefault(logger)
	version.LogStartup(logger, "registry-walker")

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", slog.String("err", err.Error()))
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.databaseURL)
	if err != nil {
		logger.Error("db connect", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		logger.Error("db ping", slog.String("err", err.Error()))
		os.Exit(1)
	}

	auditor := audit.New(pool)

	logger.Info("walker starting",
		slog.Duration("interval", cfg.interval),
		slog.Int("concurrency", cfg.concurrency),
		slog.Bool("one_shot", cfg.oneShot))

	hbCfg := version.HeartbeatConfigFromEnv("registry-walker", version.HeartbeatEnvOptions{
		TokenEnv:     []string{"CONSTELLATION_REGISTRY_WALKER_TOKEN", "SCANNER_TOKEN", "RUNTIME_AGENT_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_REGISTRY_WALKER_TOKEN_FILE", "SCANNER_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE"},
		Logger:       logger,
		MetadataFn: func() any {
			return map[string]any{
				"interval_seconds": cfg.interval.Seconds(),
				"concurrency":      cfg.concurrency,
				"one_shot":         cfg.oneShot,
			}
		},
	})
	if !cfg.oneShot {
		go version.HeartbeatLoop(ctx, hbCfg)
	}

	if cfg.oneShot {
		if err := handler.RegistryWalkerTick(ctx, pool, logger, auditor, cfg.concurrency, cfg.interval); err != nil {
			logger.Warn("first tick error", slog.String("err", err.Error()))
		}
		if version.HeartbeatConfigured(hbCfg) {
			if err := version.SendOnceExternal(ctx, hbCfg); err != nil {
				logger.Warn("heartbeat failed", slog.String("err", err.Error()))
			}
		}
		return
	}

	// RunRegistryWalker runs one tick immediately, then loops until ctx is done.
	// The same loop is now also run leader-gated inside the api server
	// (internal/server/leaderelection.go), so shipped deployments get scheduled
	// rescans without deploying this standalone binary.
	handler.RunRegistryWalker(ctx, pool, logger, auditor, cfg.concurrency, cfg.interval)
}
