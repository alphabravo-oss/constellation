// constellation-bootstrap mints the initial admin org + user on a fresh
// install so an operator can log in immediately.
//
// Behaviour:
//
//   - Connects to postgres via DATABASE_URL.
//   - If ANY user already exists in the target org, exits success without
//     touching anything (idempotent — safe to re-run after the chart
//     re-applies the post-install Hook).
//   - Otherwise creates the org (default name "default", overridable via
//     env BOOTSTRAP_ORG), the user with email BOOTSTRAP_EMAIL and password
//     BOOTSTRAP_PASSWORD (Argon2id-hashed via internal/auth, same path
//     auth.Login verifies against), and a GlobalAdmin role assignment
//     scoped to the new org.
//
// The Helm chart wires a post-install + post-upgrade Job that:
//
//  1. Renders a 24-char random password into a Secret named
//     `<release>-bootstrap` (Helm `randAlphaNum 24` at template time).
//  2. Runs this binary with that password mounted via env-from-secret.
//
// Operators retrieve the credential with:
//
//	kubectl -n constellation-system get secret constellation-bootstrap \
//	  -o jsonpath='{.data.password}' | base64 -d
//
// The Secret is `helm.sh/hook-delete-policy: before-hook-creation` so
// re-running `helm upgrade` regenerates a fresh password — but the
// idempotency check above means the seeded user keeps the password from
// the FIRST install (subsequent regenerated passwords go unused). To
// rotate, an operator runs `kubectl delete user...` first.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"sigs.k8s.io/yaml"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/obslog"
	regsecrets "github.com/alphabravocompany/constellation/pkg/registry/secrets"
)

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "bootstrap")

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		logger.Error("DATABASE_URL is required")
		os.Exit(2)
	}
	orgName := env("BOOTSTRAP_ORG", "default")
	orgDisplay := env("BOOTSTRAP_ORG_DISPLAY", "Default Org")
	email := env("BOOTSTRAP_EMAIL", "admin@constellation.local")
	display := env("BOOTSTRAP_DISPLAY", "Constellation Admin")
	password := os.Getenv("BOOTSTRAP_PASSWORD")
	if password == "" {
		logger.Error("BOOTSTRAP_PASSWORD is required (passed via Secret env)")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		logger.Error("db connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Step 1 — find or create the org. ON CONFLICT lets us safely
	// re-enter on subsequent helm upgrades.
	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO orgs (name, display_name, region, ai_enabled)
VALUES ($1, $2, 'us-east-1', FALSE)
ON CONFLICT (name) DO UPDATE SET display_name = orgs.display_name
RETURNING id`, orgName, orgDisplay).Scan(&orgID); err != nil {
		logger.Error("upsert org", "err", err, "name", orgName)
		os.Exit(1)
	}
	logger.Info("org ready", "name", orgName, "id", orgID)

	// Step 1b — seed declarative identity providers (B4: Constellation's equivalent of
	// NeuVector's LoadInitCfg / *initcfg.yaml ConfigMaps). Runs independently of the admin-user
	// idempotency below — providers seed on every install/upgrade, but auth.SeedAuthServer only
	// inserts when no provider of that type exists yet, so it never clobbers one an operator
	// later edited through the API. Best-effort: a bad providers file is logged but must not
	// block the admin bootstrap (mirrors NeuVector's InitCfgMapError-and-continue behaviour).
	if err := seedAuthProviders(ctx, pool, orgID, os.Getenv("BOOTSTRAP_AUTH_PROVIDERS_FILE"), logger); err != nil {
		logger.Error("seed auth providers (continuing)", "err", err)
	}

	// Step 2 — idempotency. If the org already has any local-login user,
	// don't touch anything. The first password wins. To rotate, the
	// operator must delete the row first.
	var existing int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE org_id = $1 AND password_hash IS NOT NULL`,
		orgID).Scan(&existing); err != nil {
		logger.Error("count users", "err", err)
		os.Exit(1)
	}
	if existing > 0 {
		logger.Info("bootstrap skipped — org already has local-login users",
			"org", orgName, "existing_count", existing)
		return
	}

	// Step 3 — hash the password via the project's auth package so we
	// produce exactly the encoded format auth.VerifyPassword expects.
	hash, err := auth.HashPassword(password)
	if err != nil {
		logger.Error("hash password", "err", err)
		os.Exit(1)
	}

	// Step 4 — insert the user. ON CONFLICT (org_id, email) is defensive:
	// the existing-count check above should prevent ever hitting it, but
	// belt-and-suspenders against a parallel run.
	//
	// must_change_password = TRUE (A4): the bootstrap password is generated into a
	// Kubernetes Secret and is therefore known to anyone who can read the Secret, so the
	// first interactive login is forced through a password change before the admin can do
	// anything else (the auth middleware blocks all other routes until it clears).
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO users (org_id, email, display_name, password_hash, must_change_password)
VALUES ($1, $2, $3, $4, TRUE)
ON CONFLICT (org_id, email) DO UPDATE SET password_hash = EXCLUDED.password_hash
RETURNING id`, orgID, email, display, hash).Scan(&userID); err != nil {
		logger.Error("upsert user", "err", err)
		os.Exit(1)
	}
	logger.Info("user created", "email", email, "id", userID)

	// Step 5 — grant GlobalAdmin scoped to the org.
	if _, err := pool.Exec(ctx, `
INSERT INTO role_assignments (user_id, role, scope_org_id)
VALUES ($1, 'GlobalAdmin', $2)
ON CONFLICT DO NOTHING`, userID, orgID); err != nil {
		logger.Error("role assignment", "err", err)
		os.Exit(1)
	}
	logger.Info("role assigned", "role", "GlobalAdmin", "user", userID)

	// Final check — verify the password actually verifies against what we
	// stored. Catches an Argon2 parameter mismatch between the seed and
	// the API process.
	if err := assertVerifies(ctx, pool, orgID, email, password); err != nil {
		logger.Error("post-bootstrap verify failed", "err", err)
		os.Exit(1)
	}
	fmt.Println("bootstrap complete:")
	fmt.Printf("  org:      %s (%s)\n", orgName, orgID)
	fmt.Printf("  email:    %s\n", email)
	fmt.Printf("  password: <see Secret>\n")
}

// authProviderSpec is the YAML/JSON wire shape for one declarative identity provider. It mirrors
// the /api/v1/auth-servers REST body so a config exported from the API round-trips back in.
// auth.ServerConfig already carries json tags; RoleMapping needs a local DTO because
// auth.RoleMapping deliberately has none.
type authProviderSpec struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	AuthOrder   int               `json:"auth_order"`
	Config      auth.ServerConfig `json:"config"`
	RoleMapping struct {
		Rules   map[string]string `json:"rules"`
		Default string            `json:"default"`
	} `json:"role_mapping"`
}

func (s authProviderSpec) toAuthServer(orgID uuid.UUID) auth.AuthServer {
	return auth.AuthServer{
		OrgID:       orgID,
		Type:        strings.TrimSpace(s.Type),
		Name:        strings.TrimSpace(s.Name),
		Enabled:     s.Enabled,
		AuthOrder:   s.AuthOrder,
		Config:      s.Config,
		RoleMapping: auth.RoleMapping{Rules: s.RoleMapping.Rules, Default: s.RoleMapping.Default},
	}
}

// parseAuthProviders accepts a YAML list of providers (or a single provider document) and
// converts via sigs.k8s.io/yaml so the json tags on auth.ServerConfig are honoured.
func parseAuthProviders(raw []byte) ([]authProviderSpec, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var list []authProviderSpec
	if err := yaml.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var one authProviderSpec
	if err := yaml.Unmarshal(raw, &one); err != nil {
		return nil, fmt.Errorf("parse auth providers: %w", err)
	}
	if strings.TrimSpace(one.Type) == "" {
		return nil, nil
	}
	return []authProviderSpec{one}, nil
}

// seedAuthProviders reads a mounted YAML file of identity providers and idempotently seeds each
// into auth_servers. Empty path => no-op (the common case, no SSO configured). Per-provider
// failures (invalid config, duplicate name) are logged and skipped so one bad entry never
// blocks the others; only a file read/parse error is returned.
func seedAuthProviders(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, path string, logger *slog.Logger) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read auth providers file %q: %w", path, err)
	}
	specs, err := parseAuthProviders(raw)
	if err != nil {
		return err
	}
	// H2: seal the IdP secret fields at rest under the same install-KEK cipher the server uses, so
	// declaratively-seeded providers never land cleartext in auth_servers.config. A cipher failure
	// is logged and we fall back to a nil sealer (plaintext) rather than blocking the bootstrap.
	var sealer auth.Sealer
	if cipher, cerr := regsecrets.Default(ctx, pool, logger); cerr != nil {
		logger.Error("auth provider secret cipher unavailable — seeding without at-rest sealing", "err", cerr)
	} else {
		sealer = cipher
	}
	for _, s := range specs {
		srv := s.toAuthServer(orgID)
		seeded, err := auth.SeedAuthServer(ctx, pool, srv, sealer)
		if err != nil {
			logger.Error("seed auth provider — skipped", "type", srv.Type, "name", srv.Name, "err", err)
			continue
		}
		if seeded {
			logger.Info("auth provider seeded", "type", srv.Type, "name", srv.Name)
		} else {
			logger.Info("auth provider already present — skipped", "type", srv.Type, "name", srv.Name)
		}
	}
	return nil
}

func assertVerifies(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, email, plaintext string) error {
	var hash string
	err := pool.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE org_id = $1 AND lower(email) = lower($2)`,
		orgID, email).Scan(&hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("user disappeared between insert and verify")
		}
		return err
	}
	return auth.VerifyPassword(hash, plaintext)
}
