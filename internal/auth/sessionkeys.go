package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// sessionKeyStore is the minimal DB surface the session-signing keypair needs. *pgxpool.Pool
// satisfies it, so callers pass their existing pool. Begin lets the generate path take a
// transaction-scoped advisory lock so concurrent replicas booting at once generate exactly
// one keypair rather than racing to insert several active keys.
type sessionKeyStore interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// sessionKeyAdvisoryLock is an arbitrary, stable key for pg_advisory_xact_lock so the
// first-boot keypair generation is serialized cluster-wide.
const sessionKeyAdvisoryLock int64 = 0x436f6e73746c4b31 // "ConstlK1"

// LoadSessionKeysPEM returns the session JWT signing keys as PEM blobs, active key first,
// suitable for NewSigner. It reads the persisted RS256 keypair(s) from session_signing_keys,
// generating + persisting one on first use so a deployment with no JWT_KEYS env secret still
// signs sessions with RS256 and every replica shares the same key. The active key (newest)
// is returned first; the most recent previous key (if any) follows so tokens minted before a
// rotation stay verifiable until they expire.
//
// A5: the private key is the signing material; verifiers can derive the public half. We return
// the private PEM because NewSigner parses it into a private signer + public verifier in one
// step. A verifier-only deployment can instead feed the public PEMs to NewSigner once it holds
// no signing-capable key.
func LoadSessionKeysPEM(ctx context.Context, store sessionKeyStore) ([][]byte, error) {
	rows, err := store.Query(ctx,
		`SELECT private_pem FROM session_signing_keys ORDER BY active DESC, created_at DESC LIMIT 2`)
	if err != nil {
		return nil, fmt.Errorf("auth: load session keys: %w", err)
	}
	var pems [][]byte
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return nil, fmt.Errorf("auth: scan session key: %w", err)
		}
		pems = append(pems, []byte(p))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: iterate session keys: %w", err)
	}
	if len(pems) > 0 {
		return pems, nil
	}
	// First boot: generate and persist a keypair, then return it.
	privPEM, err := generateAndStoreSessionKey(ctx, store)
	if err != nil {
		return nil, err
	}
	return [][]byte{privPEM}, nil
}

// RotateSessionKey mints a fresh RS256 keypair, marks it active, and demotes the previous
// active key (it stays in the table so its already-issued tokens keep verifying until they
// expire). It returns the new keys (active first, previous second if present) so the caller
// can rebuild the in-process Signer without a restart. Older-than-previous keys are pruned so
// the table never grows unbounded; their tokens are at most one TTL old and thus expired.
func RotateSessionKey(ctx context.Context, store sessionKeyStore) ([][]byte, error) {
	if _, err := store.Exec(ctx,
		`UPDATE session_signing_keys SET active = FALSE WHERE active = TRUE`); err != nil {
		return nil, fmt.Errorf("auth: demote active session key: %w", err)
	}
	if _, err := generateAndStoreSessionKey(ctx, store); err != nil {
		return nil, err
	}
	// Keep only the active key + the single most-recent previous key.
	if _, err := store.Exec(ctx, `
DELETE FROM session_signing_keys
WHERE id NOT IN (
  SELECT id FROM session_signing_keys ORDER BY active DESC, created_at DESC LIMIT 2
)`); err != nil {
		return nil, fmt.Errorf("auth: prune session keys: %w", err)
	}
	return LoadSessionKeysPEM(ctx, store)
}

// generateAndStoreSessionKey creates a 2048-bit RSA keypair, persists it as the active key,
// and returns the private PEM. A transaction-scoped advisory lock serializes concurrent
// first-boot callers; once the lock is held we re-check for an existing active key so the
// second caller adopts the first's key instead of inserting a duplicate.
func generateAndStoreSessionKey(ctx context.Context, store sessionKeyStore) ([]byte, error) {
	tx, err := store.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: begin session key tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, sessionKeyAdvisoryLock); err != nil {
		return nil, fmt.Errorf("auth: lock session key: %w", err)
	}
	// Re-check under the lock: a racing replica may have already generated the active key.
	var existing string
	err = tx.QueryRow(ctx,
		`SELECT private_pem FROM session_signing_keys WHERE active = TRUE ORDER BY created_at DESC LIMIT 1`,
	).Scan(&existing)
	if err == nil {
		return []byte(existing), tx.Commit(ctx)
	}
	if err != pgx.ErrNoRows {
		return nil, fmt.Errorf("auth: recheck session key: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("auth: generate session key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal session public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if _, err := tx.Exec(ctx, `
INSERT INTO session_signing_keys (algorithm, private_pem, public_pem, active)
VALUES ('RS256', $1, $2, TRUE)`, string(privPEM), string(pubPEM)); err != nil {
		return nil, fmt.Errorf("auth: persist session key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("auth: commit session key: %w", err)
	}
	return privPEM, nil
}
