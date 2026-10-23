// constellation-api is the control-plane HTTP service.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/identity"
	"github.com/alphabravocompany/constellation/internal/server"
	migrations "github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/storagehealth"
	"github.com/alphabravocompany/constellation/internal/telemetry"
	"github.com/alphabravocompany/constellation/pkg/version"
)

func main() {
	listenAddr := flag.String("listen", env("LISTEN_ADDR", ":8080"), "HTTP listen address")
	checkSchemaOnly := flag.Bool("check-schema", false, "verify the required database migration, then exit without starting services")
	migrateOnly := flag.Bool("migrate-only", false, "apply pending schema migrations under the advisory lock, then exit")
	flag.Parse()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		slog.Error("DATABASE_URL required")
		os.Exit(2)
	}

	if *checkSchemaOnly {
		os.Exit(checkSchema(context.Background(), databaseURL))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	telCfg := telemetry.ConfigFromEnv("constellation-api")
	tel, err := telemetry.Init(ctx, telCfg)
	if err != nil {
		slog.Error("observability init", slog.String("err", err.Error()))
		os.Exit(1)
	}
	// Wave N6: every binary logs its build triplet once on startup so kubectl
	// logs / journalctl operators can immediately see "what is running."
	version.LogStartup(tel.Logger, "api")
	// Air-gap first (guide ch.08/09): one line naming every endpoint outside the
	// cluster this process may contact; all are opt-in through configuration.
	telemetry.NewEgress().
		Add("otlp", telCfg.Endpoint).
		Add("oidc_issuer", os.Getenv("OIDC_ISSUER_URL")).
		Add("fed_master", os.Getenv("CONSTELLATION_FED_MASTER_URL")).
		Log(tel.Logger)
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = tel.Shutdown(shutdownCtx)
	}()

	database, err := connectWithRetry(ctx, databaseURL, envDuration("DB_CONNECT_TIMEOUT", 5*time.Minute), tel.Logger, db.WithTracer(tel.PgxTracer()))
	if err != nil {
		tel.Logger.Error("db connect", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer database.Close()
	tel.ObservePool(database.Pool())
	// Component heartbeat / scanner engine-DB / CVE-feed ages as first-class metrics
	// (no postgres-exporter needed); queried on scrape, cached 15s.
	tel.ObserveDBHealth(database.Pool(), 15*time.Second)

	// Guide ch.02: the binary ships its migrations and applies them under a
	// session-level advisory lock before it accepts traffic; a failed migration
	// is a failed boot. Replicas starting together serialise on the lock.
	if _, err := migrations.MigratePool(ctx, database.Pool(), tel.Logger); err != nil {
		tel.Logger.Error("migrate", slog.String("err", err.Error()))
		os.Exit(1)
	}
	if *migrateOnly {
		return
	}

	archiveStream := (storagehealth.ArchiveDestination{
		Enabled:         os.Getenv("CONSTELLATION_STORAGE_ARCHIVE_ENABLED") == "true",
		Endpoint:        os.Getenv("CONSTELLATION_STORAGE_ARCHIVE_ENDPOINT"),
		EndpointS3:      os.Getenv("CONSTELLATION_STORAGE_ARCHIVE_ENDPOINT_S3"),
		EndpointDefault: os.Getenv("CONSTELLATION_STORAGE_ARCHIVE_ENDPOINT_DEFAULT"),
		Bucket:          os.Getenv("CONSTELLATION_STORAGE_ARCHIVE_BUCKET"),
		Prefix:          os.Getenv("CONSTELLATION_STORAGE_ARCHIVE_PREFIX"),
	}).StreamID()

	tel.Registry.MustRegister(storagehealth.New(database.Pool(), storagehealth.Config{ArchiveStream: archiveStream}, tel.Logger))

	cfg := server.Config{
		ListenAddr:           *listenAddr,
		AdminListenAddr:      env("ADMIN_LISTEN_ADDR", ":9090"),
		RequestTimeout:       envDuration("REQUEST_TIMEOUT", 60*time.Second),
		MaxBodyBytes:         int64(envInt("MAX_BODY_BYTES", 64<<20)),
		EnablePprof:          envBool("CONSTELLATION_ENABLE_PPROF", false),
		DatabaseURL:          databaseURL,
		PATMaxLifetime:       envDuration("PAT_MAX_LIFETIME", 90*24*time.Hour),
		CORSOrigins:          strings.Split(env("CORS_ORIGINS", "http://localhost:5173"), ","),
		VulnDBReadyRequired:  envBool("CONSTELLATION_VULNDB_READY_REQUIRED", false),
		VulnDBReadyMaxAge:    envDuration("CONSTELLATION_VULNDB_READY_MAX_AGE", 0),
		VulnDBRescanInterval: envDuration("CONSTELLATION_VULNDB_RESCAN_INTERVAL", 2*time.Minute),

		RepositoryScanRetentionEnabled:   envBool("CONSTELLATION_REPOSITORY_SCAN_RETENTION_ENABLED", false),
		RepositoryScanRetentionMaxAge:    envDuration("CONSTELLATION_REPOSITORY_SCAN_RETENTION_MAX_AGE", 90*24*time.Hour),
		RepositoryScanRetentionInterval:  envDuration("CONSTELLATION_REPOSITORY_SCAN_RETENTION_INTERVAL", 24*time.Hour),
		RepositoryScanRetentionBatchSize: envInt("CONSTELLATION_REPOSITORY_SCAN_RETENTION_BATCH_SIZE", 500),
		RepositoryScanRetentionDryRun:    envBool("CONSTELLATION_REPOSITORY_SCAN_RETENTION_DRY_RUN", false),
	}
	if iss := os.Getenv("OIDC_ISSUER_URL"); iss != "" {
		cfg.OIDC = &identity.OIDCConfig{
			IssuerURL:    iss,
			Bundled:      envBool("OIDC_BUNDLED", false),
			ClientID:     os.Getenv("OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),
			Audience:     os.Getenv("OIDC_AUDIENCE"), RolesClaim: env("OIDC_ROLES_CLAIM", "alphabravo_roles"), OrgName: env("OIDC_ORG", "default"), Scopes: strings.Fields(env("OIDC_SCOPES", "openid email profile")),
		}
	}
	cfg.Local = identity.LocalConfig{Enabled: envBool("LOCAL_AUTH_ENABLED", true), Display: env("LOCAL_AUTH_DISPLAY", "all"), TOTPPolicy: env("LOCAL_AUTH_TOTP_POLICY", "everyone"), PasswordMinLength: envInt("LOCAL_AUTH_PASSWORD_MIN_LENGTH", 16), SessionSeconds: envInt("LOCAL_AUTH_SESSION_SECONDS", 3600), IPRate: envInt("LOCAL_AUTH_IP_RATE", 20), AccountRate: envInt("LOCAL_AUTH_ACCOUNT_RATE", 5), OrgName: env("LOCAL_AUTH_ORG", "default"), BootstrapEmail: env("LOCAL_BOOTSTRAP_EMAIL", "admin@constellation.local"), BootstrapPassword: os.Getenv("LOCAL_BOOTSTRAP_PASSWORD"), BootstrapTOTP: os.Getenv("LOCAL_BOOTSTRAP_TOTP")}

	cfg.BreakGlass = identity.BreakGlassConfig{Enabled: envBool("BREAK_GLASS_ENABLED", false), PasswordHash: os.Getenv("BREAK_GLASS_PASSWORD_HASH"), TOTPSecret: os.Getenv("BREAK_GLASS_TOTP_SECRET"), OrgName: env("BREAK_GLASS_ORG", "default"), SessionTTL: envDuration("BREAK_GLASS_SESSION_TTL", 5*time.Minute)}

	if cfg.OIDC != nil {
		if err := json.Unmarshal([]byte(env("OIDC_ROLE_MAPPING", "{}")), &cfg.OIDC.RoleMapping); err != nil {
			tel.Logger.Error("invalid OIDC_ROLE_MAPPING")
			os.Exit(2)
		}
	}
	srv, err := server.New(ctx, cfg, tel, database)
	if err != nil {
		tel.Logger.Error("server new", slog.String("err", err.Error()))
		os.Exit(1)
	}
	go version.HeartbeatLoop(ctx, version.HeartbeatConfigFromEnv("api", version.HeartbeatEnvOptions{
		APIBaseURL:   apiHeartbeatURL(*listenAddr),
		TokenEnv:     []string{"CONSTELLATION_API_TOKEN", "RUNTIME_AGENT_TOKEN", "SCANNER_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_API_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE", "SCANNER_TOKEN_FILE"},
		Logger:       tel.Logger,
		MetadataFn: func() any {
			return map[string]any{
				"listen_addr":                       *listenAddr,
				"admin_listen_addr":                 cfg.AdminListenAddr,
				"oidc_enabled":                      cfg.OIDC != nil,
				"break_glass_enabled":               cfg.BreakGlass.Enabled,
				"vulndb_ready_required":             cfg.VulnDBReadyRequired,
				"vulndb_rescan_interval_s":          cfg.VulnDBRescanInterval.Seconds(),
				"repository_scan_retention_enabled": cfg.RepositoryScanRetentionEnabled,
			}
		},
	}))
	if err := srv.Run(ctx); err != nil {
		tel.Logger.Error("server run", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func apiHeartbeatURL(listenAddr string) string {
	if override := strings.TrimSpace(os.Getenv("CONSTELLATION_API_HEARTBEAT_URL")); override != "" {
		return strings.TrimRight(override, "/")
	}
	listenAddr = strings.TrimSpace(listenAddr)
	port := "8080"
	if strings.HasPrefix(listenAddr, ":") && len(listenAddr) > 1 {
		port = strings.TrimPrefix(listenAddr, ":")
	} else if idx := strings.LastIndex(listenAddr, ":"); idx >= 0 && idx < len(listenAddr)-1 {
		port = listenAddr[idx+1:]
	}
	return "http://127.0.0.1:" + port
}

// connectWithRetry waits for the database to accept connections (Postgres may
// still be starting on a fresh install) instead of relying on an init
// container; it gives up after timeout so a misconfigured DSN still fails fast.
func connectWithRetry(ctx context.Context, databaseURL string, timeout time.Duration, logger *slog.Logger, opts ...db.Option) (*db.DB, error) {
	deadline := time.Now().Add(timeout)
	for attempt := 1; ; attempt++ {
		database, err := db.Connect(ctx, databaseURL, opts...)
		if err == nil {
			return database, nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return nil, err
		}
		logger.Warn("database not ready; retrying", slog.Int("attempt", attempt), slog.String("err", err.Error()))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "t", "true", "y", "yes", "on", "enabled":
		return true
	case "0", "f", "false", "n", "no", "off", "disabled":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// checkSchema is also the Helm init-container gate. It uses the API image's own
// requirement, so an old table or a mismatched chart cannot admit a new binary.
func checkSchema(ctx context.Context, databaseURL string) int {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	database, err := db.Connect(bounded, databaseURL)
	if err != nil {
		slog.Error("schema check connection failed", "error", err)
		return 1
	}
	defer database.Close()
	if err := database.RequireSchema(bounded); err != nil {
		slog.Error("schema check failed", "error", err)
		return 1
	}
	slog.Info("database schema ready", "required_version", db.RequiredSchemaVersion)
	return 0
}
