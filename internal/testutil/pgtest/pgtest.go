// Package pgtest is the real-Postgres fixture for //go:build integration tests.
//
// One pgvector/pgvector:pg16 container is started per test process (lazily, on
// the first request; terminated by Main after the run, by Ryuk otherwise).
// Every test receives its own database cloned from a template that was
// migrated with the production runner (internal/server/database), so tests are
// isolated, parallel-safe and never share mutable state.
//
// Set CONSTELLATION_TEST_DATABASE_URL to a superuser DSN to use an existing
// server (CI service container) instead of starting one.
package pgtest

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // pgtestdb opens database/sql via the "pgx" driver
	"github.com/peterldowns/pgtestdb"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/alphabravocompany/constellation/internal/server/database"
)

// Image is the Postgres image under test; it matches the chart's CNPG image and
// the dev loop to the major version and ships the vector extension.
const Image = "pgvector/pgvector:pg16"

var (
	startOnce sync.Once
	startErr  error
	rootCfg   pgtestdb.Config
	container testcontainers.Container

	mu  sync.Mutex
	dbs = map[string]*pgtestdb.Config{}
)

// Main wraps testing.M for packages whose tests use this fixture: it runs the
// tests, terminates the container, and exits with the test status.
func Main(m *testing.M) {
	code := m.Run()
	stop()
	os.Exit(code)
}

// Pool returns a pgx pool on a fresh, fully migrated database owned by this
// test. Repeated calls from the same test (or its subtests) return pools on the
// same database; the pool is closed and the database dropped on cleanup.
func Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	cfg := configFor(t)
	pool, err := pgxpool.New(context.Background(), cfg.URL())
	if err != nil {
		t.Fatalf("pgtest: open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// URL returns the DSN of this test's migrated database.
func URL(t testing.TB) string {
	t.Helper()
	return configFor(t).URL()
}

// FreshURL returns the DSN of an empty, unmigrated database owned by this test,
// for exercising the migration runner itself.
func FreshURL(t testing.TB) string {
	t.Helper()
	root := rootConfig(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, root.URL())
	if err != nil {
		t.Fatalf("pgtest: connect root: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	name := fmt.Sprintf("fresh_%d_%s", time.Now().UnixNano(), strings.ToLower(sanitize(t.Name())))
	if len(name) > 60 {
		name = name[:60]
	}
	ident := pgx.Identifier{name}.Sanitize()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		t.Fatalf("pgtest: create fresh database: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), root.URL())
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)")
	})
	cfg := root
	cfg.Database = name
	return cfg.URL()
}

func configFor(t testing.TB) *pgtestdb.Config {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	name := t.Name()
	for n := name; ; {
		if c, ok := dbs[n]; ok {
			return c
		}
		i := strings.LastIndex(n, "/")
		if i < 0 {
			break
		}
		n = n[:i]
	}
	cfg := pgtestdb.Custom(t, rootConfig(t), migrator{})
	dbs[name] = cfg
	t.Cleanup(func() {
		mu.Lock()
		delete(dbs, name)
		mu.Unlock()
	})
	return cfg
}

func rootConfig(t testing.TB) pgtestdb.Config {
	t.Helper()
	startOnce.Do(start)
	if startErr != nil {
		t.Fatalf("pgtest: %v", startErr)
	}
	return rootCfg
}

func start() {
	if dsn := os.Getenv("CONSTELLATION_TEST_DATABASE_URL"); dsn != "" {
		rootCfg, startErr = parseDSN(dsn)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ctr, err := postgres.Run(ctx, Image,
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithCmd("postgres",
			"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
			"-c", "max_connections=1000", "-c", "shared_buffers=256MB"),
		testcontainers.WithTmpfs(map[string]string{"/var/lib/postgresql/data": "rw"}),
	)
	if err != nil {
		startErr = fmt.Errorf("start %s: %w (is Docker running? set CONSTELLATION_TEST_DATABASE_URL to use an external server)", Image, err)
		return
	}
	container = ctr
	host, err := ctr.Host(ctx)
	if err != nil {
		startErr = err
		return
	}
	port, err := ctr.MappedPort(ctx, "5432/tcp")
	if err != nil {
		startErr = err
		return
	}
	rootCfg = pgtestdb.Config{
		DriverName: "pgx", Host: host, Port: port.Port(),
		User: "postgres", Password: "postgres", Database: "postgres",
		Options:                   "sslmode=disable",
		TestRole:                  testRole(),
		ForceTerminateConnections: true,
	}
	startErr = waitReady(ctx, rootCfg.URL())
}

func stop() {
	if container == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = container.Terminate(ctx)
}

// testRole mirrors the production role: migrations create extensions, so the
// role that owns the template (and every clone) is a superuser.
func testRole() *pgtestdb.Role {
	return &pgtestdb.Role{Username: "constellation", Password: "constellation", Capabilities: "SUPERUSER CREATEDB"}
}

func parseDSN(dsn string) (pgtestdb.Config, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return pgtestdb.Config{}, fmt.Errorf("CONSTELLATION_TEST_DATABASE_URL: %w", err)
	}
	pw, _ := u.User.Password()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	opts := u.RawQuery
	if opts == "" {
		opts = "sslmode=disable"
	}
	return pgtestdb.Config{
		DriverName: "pgx", Host: u.Hostname(), Port: port,
		User: u.User.Username(), Password: pw, Database: strings.TrimPrefix(u.Path, "/"),
		Options: opts, TestRole: testRole(), ForceTerminateConnections: true,
	}, nil
}

func waitReady(ctx context.Context, dsn string) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn, err := pgx.Connect(ctx, dsn)
		if err == nil {
			_ = conn.Close(ctx)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("postgres not ready: %w", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// migrator adapts the production runner to pgtestdb's Migrator interface.
type migrator struct{}

func (migrator) Hash() (string, error) { return database.Hash() }

func (migrator) Migrate(ctx context.Context, db *sql.DB, _ pgtestdb.Config) error {
	if _, err := database.Migrate(ctx, db, slog.New(slog.DiscardHandler)); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, baselineSQL)
	return err
}

// BaselineOrg / BaselineAdmin are the rows every clone starts with: the demo
// org and admin that cmd/constellation-seed provisions for the dev loop, so
// tests that look up "the first org" or log in as the admin have them.
const (
	BaselineOrg           = "demo"
	BaselineAdminEmail    = "admin@demo.test"
	BaselineAdminPassword = "Constellation!1"
)

// baselineSQL mirrors the first two statements of cmd/constellation-seed.
// The hash is auth.HashPassword(BaselineAdminPassword); it is embedded rather
// than computed so this package never imports internal/auth (whose own tests
// import this package).
const baselineSQL = `
INSERT INTO orgs (name, display_name, region, ai_enabled)
VALUES ('demo', 'Demo Org', 'us-east-1', FALSE)
ON CONFLICT (name) DO NOTHING;
INSERT INTO users (org_id, email, display_name, password_hash)
SELECT id, 'admin@demo.test', 'Demo Admin',
  '$argon2id$v=19$m=65536,t=3,p=4$oEB1sGsCdO2qoCMVKzKLqg$O8sGORyt+IXFuQ7Mwt0dQVqa/VVvolCVBvJNJrWXtYg'
FROM orgs WHERE name = 'demo'
ON CONFLICT (org_id, email) DO NOTHING;
INSERT INTO role_assignments (user_id, role, scope_org_id)
SELECT u.id, 'GlobalAdmin', u.org_id FROM users u JOIN orgs o ON o.id = u.org_id
WHERE o.name = 'demo' AND u.email = 'admin@demo.test'
ON CONFLICT DO NOTHING;
INSERT INTO clusters (org_id, name, distro, cloud_provider, region, state, agent_version, last_heartbeat_at)
SELECT id, 'prod-east', 'eks', 'aws', 'us-east-1', 'connected', 'demo-agent-0.1.0', NOW()
FROM orgs WHERE name = 'demo'
ON CONFLICT (org_id, name) DO NOTHING;
`
