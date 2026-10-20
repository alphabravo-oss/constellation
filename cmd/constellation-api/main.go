// constellation-api is the control-plane HTTP service.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/server"
	migrations "github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/telemetry"
	"github.com/alphabravocompany/constellation/pkg/version"
)

func main() {
	listenAddr := flag.String("listen", env("LISTEN_ADDR", ":8080"), "HTTP listen address")
	rotateJWT := flag.Bool("rotate-jwt-key", false,
		"A5: mint a new RS256 session-signing keypair, demote the previous to verify-only, then exit")
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

	if *rotateJWT {
		os.Exit(rotateJWTKey(ctx, databaseURL))
	}

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
		Add("astronomer_jwks", os.Getenv("ASTRONOMER_JWKS_URL")).
		Add("ldap", os.Getenv("LDAP_URL")).
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

	cfg := server.Config{
		ListenAddr:           *listenAddr,
		AdminListenAddr:      env("ADMIN_LISTEN_ADDR", ":9090"),
		RequestTimeout:       envDuration("REQUEST_TIMEOUT", 60*time.Second),
		MaxBodyBytes:         int64(envInt("MAX_BODY_BYTES", 64<<20)),
		EnablePprof:          envBool("CONSTELLATION_ENABLE_PPROF", false),
		DatabaseURL:          databaseURL,
		JWTKeys:              loadJWTKeys(envBool("CONSTELLATION_REQUIRE_JWT_KEYS", false)),
		JWTIssuer:            env("JWT_ISSUER", "constellation"),
		JWTAudience:          env("JWT_AUDIENCE", "constellation-api"),
		JWTTTL:               envDuration("JWT_TTL", 15*time.Minute),
		SessionIdleTimeout:   envDuration("SESSION_IDLE_TIMEOUT", 30*time.Minute),
		PATMaxLifetime:       envDuration("PAT_MAX_LIFETIME", 90*24*time.Hour),
		CORSOrigins:          strings.Split(env("CORS_ORIGINS", "http://localhost:5173"), ","),
		AstronomerJWKSURL:    os.Getenv("ASTRONOMER_JWKS_URL"),
		AstronomerIssuer:     os.Getenv("ASTRONOMER_JWT_ISSUER"),
		AstronomerAudience:   os.Getenv("ASTRONOMER_JWT_AUDIENCE"),
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
		cfg.OIDC = &auth.OIDCConfig{
			IssuerURL:    iss,
			ClientID:     os.Getenv("OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURL:  env("OIDC_REDIRECT_URL", "http://localhost:8080/api/v1/auth/oidc/callback"),
		}
	}
	// SAML SP config: enabled when the IdP metadata is supplied (inline XML or a file path).
	// The SP cert/key are optional (only needed for signed AuthnRequests / encrypted assertions);
	// signature validation of the IdP's assertions is driven by the IdP cert in the metadata.
	if md := envFileOrValue("SAML_IDP_METADATA"); len(md) > 0 {
		cfg.SAML = &auth.SAMLConfig{
			IdPMetadataXML: md,
			ACSURL:         env("SAML_ACS_URL", "http://localhost:8080/api/v1/auth/saml/acs"),
			SPCertPEM:      envFileOrValue("SAML_SP_CERT"),
			SPKeyPEM:       envFileOrValue("SAML_SP_KEY"),
		}
	}
	// LDAP/AD config: enabled when a directory URL is supplied. Mirrors the bind+search model.
	if url := os.Getenv("LDAP_URL"); url != "" {
		cfg.LDAP = &auth.LDAPConfig{
			URL:          url,
			BindDN:       os.Getenv("LDAP_BIND_DN"),
			BindPassword: os.Getenv("LDAP_BIND_PW"),
			BaseDN:       os.Getenv("LDAP_BASE_DN"),
			UserFilter:   env("LDAP_USER_FILTER", "(uid=%s)"),
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
				"jwt_keys_configured":               len(cfg.JWTKeys) > 0,
				"oidc_enabled":                      cfg.OIDC != nil,
				"saml_enabled":                      cfg.SAML != nil,
				"ldap_enabled":                      cfg.LDAP != nil,
				"astronomer_enabled":                strings.TrimSpace(cfg.AstronomerJWKSURL) != "",
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

// envFileOrValue resolves a PEM/XML blob from either <KEY> (inline value) or <KEY>_FILE (a path
// to read), preferring the inline value. Returns nil when neither is set. SAML metadata/cert/key
// are usually mounted as Secret files, so the _FILE form is the common production path; the inline
// form keeps local/dev config a single env var.
func envFileOrValue(key string) []byte {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return []byte(v)
	}
	if path := strings.TrimSpace(os.Getenv(key + "_FILE")); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			slog.Error("read "+key+"_FILE", slog.String("err", err.Error()))
			os.Exit(2)
		}
		return b
	}
	return nil
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

// rotateJWTKey performs the A5 session-key rotation against the DB-persisted
// session_signing_keys store and exits. Already-issued tokens keep verifying against the
// demoted previous key until they expire; new logins are signed with the fresh active key.
// Running replicas pick up the rotation within one reload interval via the in-process
// session-key reloader (server.runSessionKeyReloader) — no restart required. Returns a
// process exit code.
func rotateJWTKey(ctx context.Context, databaseURL string) int {
	database, err := db.Connect(ctx, databaseURL)
	if err != nil {
		slog.Error("rotate-jwt-key: db connect", slog.String("err", err.Error()))
		return 1
	}
	defer database.Close()
	if _, err := auth.RotateSessionKey(ctx, database.Pool()); err != nil {
		slog.Error("rotate-jwt-key", slog.String("err", err.Error()))
		return 1
	}
	slog.Info("rotate-jwt-key: new RS256 session-signing key is active; previous key kept for verification until its tokens expire")
	return 0
}

// loadJWTKeys returns the operator-supplied rotation key set, or nil. JWT_KEYS may
// contain multiple comma-separated base64 values (active key first). A5: on empty
// env we return nil so server.New falls through to the DB-backed RS256 session
// keypair (the default production path) instead of minting an ephemeral HS256 key.
func loadJWTKeys(required bool) [][]byte {
	out, err := buildJWTKeys(os.Getenv("JWT_KEYS"), required)
	if err != nil {
		slog.Error("JWT_KEYS unavailable", slog.String("err", err.Error()))
		os.Exit(2)
	}
	if len(out) == 0 {
		slog.Info("JWT_KEYS empty; signing sessions RS256 with the shared DB-backed keypair")
	}
	return out
}

func buildJWTKeys(raw string, required bool) ([][]byte, error) {
	if strings.TrimSpace(raw) == "" {
		if required {
			return nil, fmt.Errorf("JWT_KEYS required")
		}
		// Empty key set: server.New loads the persisted RS256 keypair from
		// session_signing_keys (generating it on first boot).
		return nil, nil
	}
	return parseJWTKeys(raw)
}

func parseJWTKeys(raw string) ([][]byte, error) {
	parts := strings.Split(raw, ",")
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		value := strings.TrimSpace(p)
		if value == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(b) < 32 {
			b = []byte(value)
		}
		if len(b) < 32 {
			slog.Warn("JWT_KEYS entry shorter than 32 bytes; skipping", slog.Int("len", len(b)))
			continue
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no key is at least 32 bytes")
	}
	return out, nil
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
