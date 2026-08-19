package auth

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testSessionKeyDB returns a pool against the shared test DB with the A5 table ensured, or
// skips when the DB is unreachable (mirrors the server package's DB-gated tests).
func testSessionKeyDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("skipping: cannot open test DB (%v)", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	// Idempotent: matches db/migrations/100_session_signing_keys.sql so the test runs even if
	// goose has not been pointed at this DB yet.
	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS session_signing_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    algorithm   TEXT NOT NULL,
    private_pem TEXT NOT NULL,
    public_pem  TEXT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)`); err != nil {
		pool.Close()
		t.Fatalf("ensure table: %v", err)
	}
	// Isolate from any rows left by prior runs / the real schema.
	if _, err := pool.Exec(ctx, `DELETE FROM session_signing_keys`); err != nil {
		pool.Close()
		t.Fatalf("clear table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM session_signing_keys`)
		pool.Close()
	})
	return pool
}

// TestLoadSessionKeysGeneratesAndPersists proves first-boot generates one RS256 keypair,
// persists it, and that a second load returns the same key (no regeneration) — so every
// replica shares one signing identity.
func TestLoadSessionKeysGeneratesAndPersists(t *testing.T) {
	pool := testSessionKeyDB(t)
	ctx := context.Background()

	first, err := LoadSessionKeysPEM(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("expected 1 key on first boot, got %d", len(first))
	}
	second, err := LoadSessionKeysPEM(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if string(second[0]) != string(first[0]) {
		t.Fatal("second load regenerated the key instead of reusing the persisted one")
	}
	// The persisted key must produce a working RS256 signer.
	s, err := NewSigner("constellation", "api", time.Minute, first...)
	if err != nil {
		t.Fatalf("signer from persisted key: %v", err)
	}
	tok, _, err := s.Issue(uuid.New(), uuid.New(), "a@example.com", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestRotateSessionKeyKeepsOldTokensValid is the A5 acceptance test: rotate, then a token
// issued before the rotation must still verify against the post-rotation key set.
func TestRotateSessionKeyKeepsOldTokensValid(t *testing.T) {
	pool := testSessionKeyDB(t)
	ctx := context.Background()

	before, err := LoadSessionKeysPEM(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	oldSigner, err := NewSigner("constellation", "api", time.Minute, before...)
	if err != nil {
		t.Fatal(err)
	}
	oldTok, _, err := oldSigner.Issue(uuid.New(), uuid.New(), "a@example.com", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	after, err := RotateSessionKey(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Fatalf("after rotation expected active+previous keys, got %d", len(after))
	}
	if string(after[0]) == string(before[0]) {
		t.Fatal("rotation did not change the active key")
	}
	rotatedSigner, err := NewSigner("constellation", "api", time.Minute, after...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotatedSigner.Verify(oldTok); err != nil {
		t.Fatalf("token issued before rotation must still verify: %v", err)
	}
	// New tokens are minted with the new active key and verify too.
	newTok, _, err := rotatedSigner.Issue(uuid.New(), uuid.New(), "b@example.com", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotatedSigner.Verify(newTok); err != nil {
		t.Fatalf("new token must verify: %v", err)
	}
}
