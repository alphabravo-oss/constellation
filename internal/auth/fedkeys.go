package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// fedSigningKeyAdvisoryLock is an arbitrary, stable key for pg_advisory_xact_lock so the
// first-boot federation keypair generation is serialized cluster-wide (distinct from the
// session-key lock so the two never contend).
const fedSigningKeyAdvisoryLock int64 = 0x436f6e73746c4664 // "ConstlFd"

// LoadFedSigningKeysPEM returns the federation join/sync signing keys as PEM blobs,
// active key first, suitable for NewFedSigner. It mirrors LoadSessionKeysPEM (A5) but
// reads the DEDICATED fed_signing_keys table (migration 105) so federation trust is
// isolated from user-session signing: rotating one never affects the other, and a fed
// verifier holds only the fed public key — a user JWT (signed by the session key) can
// never pass it, which is what rejects a generic read-findings JWT presented on /sync.
//
// On first use it generates + persists one RS256 keypair so a master mints signed join
// tokens without any operator-provided secret, and every replica shares the same key.
func LoadFedSigningKeysPEM(ctx context.Context, store sessionKeyStore) ([][]byte, error) {
	rows, err := store.Query(ctx,
		`SELECT private_pem FROM fed_signing_keys ORDER BY active DESC, created_at DESC LIMIT 2`)
	if err != nil {
		return nil, fmt.Errorf("auth: load fed signing keys: %w", err)
	}
	var pems [][]byte
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return nil, fmt.Errorf("auth: scan fed signing key: %w", err)
		}
		pems = append(pems, []byte(p))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: iterate fed signing keys: %w", err)
	}
	if len(pems) > 0 {
		return pems, nil
	}
	privPEM, err := generateAndStoreFedSigningKey(ctx, store)
	if err != nil {
		return nil, err
	}
	return [][]byte{privPEM}, nil
}

// generateAndStoreFedSigningKey creates a 2048-bit RSA keypair, persists it as the active
// federation signing key, and returns the private PEM. A transaction-scoped advisory lock
// serializes concurrent first-boot callers; once the lock is held we re-check for an
// existing active key so the second caller adopts the first's key. Mirrors
// generateAndStoreSessionKey.
func generateAndStoreFedSigningKey(ctx context.Context, store sessionKeyStore) ([]byte, error) {
	tx, err := store.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: begin fed key tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, fedSigningKeyAdvisoryLock); err != nil {
		return nil, fmt.Errorf("auth: lock fed key: %w", err)
	}
	var existing string
	err = tx.QueryRow(ctx,
		`SELECT private_pem FROM fed_signing_keys WHERE active = TRUE ORDER BY created_at DESC LIMIT 1`,
	).Scan(&existing)
	if err == nil {
		return []byte(existing), tx.Commit(ctx)
	}
	if err != pgx.ErrNoRows {
		return nil, fmt.Errorf("auth: recheck fed key: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("auth: generate fed key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal fed public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if _, err := tx.Exec(ctx, `
INSERT INTO fed_signing_keys (algorithm, private_pem, public_pem, active)
VALUES ('RS256', $1, $2, TRUE)`, string(privPEM), string(pubPEM)); err != nil {
		return nil, fmt.Errorf("auth: persist fed key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("auth: commit fed key: %w", err)
	}
	return privPEM, nil
}
