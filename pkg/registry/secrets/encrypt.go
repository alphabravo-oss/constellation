// Package secrets implements the AES-256-GCM credential wrapper used by
// registries.auth_secret.
//
// Design:
//   - One install-wide Key Encryption Key (KEK). Sourced from $CONSTELLATION_KEK
//     (32 bytes hex = 64 chars). If unset, the first call to Init() will mint a
//     fresh random KEK, persist it into org_settings under the "registry_kek"
//     key, log a WARN telling the operator to wire it into their secret store
//     (Vault / SOPS / k8s Secret) for the next reboot, and proceed.
//   - Each registry credential is JSON-marshalled, then AES-GCM sealed with a
//     random 12-byte nonce. Storage layout: nonce(12) || ciphertext || tag(16).
//   - Decrypt is symmetric. Callers pass the raw bytea from the DB column to
//     Decrypt; the function returns the original JSON bytes ready for
//     json.Unmarshal into the per-kind Auth struct.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnvKEK is the environment variable name the operator can set to inject a
// stable Key Encryption Key (32 bytes encoded as 64 hex characters).
const EnvKEK = "CONSTELLATION_KEK"

// SettingsKey is the org_settings key the Bootstrap path persists a generated
// KEK under when EnvKEK is absent.
const SettingsKey = "registry_kek"

// keyLen is the AES-256 key length in bytes.
const keyLen = 32

// nonceLen is the AES-GCM standard nonce length in bytes.
const nonceLen = 12

// Cipher is a thread-safe AES-GCM wrapper bound to a specific KEK.
type Cipher struct {
	gcm cipher.AEAD
}

// New constructs a Cipher from a raw 32-byte key.
func New(key []byte) (*Cipher, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("secrets: KEK must be %d bytes, got %d", keyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm: %w", err)
	}
	return &Cipher{gcm: gcm}, nil
}

// Seal AES-GCM-encrypts plaintext, returning nonce || ciphertext || tag.
func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secrets: nonce: %w", err)
	}
	ct := c.gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, nonceLen+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open inverts Seal: given nonce||ct||tag, returns plaintext.
func (c *Cipher) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < nonceLen+c.gcm.Overhead() {
		return nil, errors.New("secrets: ciphertext too short")
	}
	nonce := sealed[:nonceLen]
	ct := sealed[nonceLen:]
	pt, err := c.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm open: %w", err)
	}
	return pt, nil
}

// process-wide singleton — built on first call to Default().
var (
	defaultOnce sync.Once
	defaultC    *Cipher
	defaultErr  error
)

// Default returns a singleton Cipher initialised against the env-supplied or
// org_settings-bootstrapped KEK. Safe to call multiple times; the underlying
// init runs at most once per process.
func Default(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) (*Cipher, error) {
	defaultOnce.Do(func() {
		key, err := loadOrBootstrapKEK(ctx, pool, logger)
		if err != nil {
			defaultErr = err
			return
		}
		c, err := New(key)
		if err != nil {
			defaultErr = err
			return
		}
		defaultC = c
	})
	return defaultC, defaultErr
}

// loadOrBootstrapKEK reads the KEK from the env, or falls back to org_settings,
// or mints a fresh one and persists it.
func loadOrBootstrapKEK(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv(EnvKEK)); raw != "" {
		decoded, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("secrets: %s is not valid hex: %w", EnvKEK, err)
		}
		if len(decoded) != keyLen {
			return nil, fmt.Errorf("secrets: %s must decode to %d bytes, got %d", EnvKEK, keyLen, len(decoded))
		}
		if logger != nil {
			logger.Info("registry KEK sourced from env", slog.String("var", EnvKEK))
		}
		return decoded, nil
	}

	if pool != nil {
		if existing, err := readFromSettings(ctx, pool); err == nil && len(existing) == keyLen {
			if logger != nil {
				logger.Warn(
					"registry KEK loaded from org_settings (no env var). For production, set "+
						EnvKEK+" in your service environment so the secret never lives in the database.",
				)
			}
			return existing, nil
		}
	}

	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secrets: bootstrap: %w", err)
	}
	if pool != nil {
		if err := writeToSettings(ctx, pool, key); err != nil {
			return nil, fmt.Errorf("secrets: persist bootstrap kek: %w", err)
		}
	}
	if logger != nil {
		logger.Warn(
			"registry KEK auto-generated and persisted into org_settings. " +
				"For production, copy hex(key) into the " + EnvKEK +
				" service env var so the secret never lives in the database.",
		)
	}
	return key, nil
}

func readFromSettings(ctx context.Context, pool *pgxpool.Pool) ([]byte, error) {
	var hexStr string
	err := pool.QueryRow(ctx, `
SELECT settings->>$1
  FROM org_settings
 WHERE settings ? $1
 LIMIT 1`, SettingsKey).Scan(&hexStr)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("secrets: no KEK in org_settings")
		}
		return nil, err
	}
	hexStr = strings.TrimSpace(hexStr)
	if hexStr == "" {
		return nil, errors.New("secrets: empty KEK in org_settings")
	}
	return hex.DecodeString(hexStr)
}

func writeToSettings(ctx context.Context, pool *pgxpool.Pool, key []byte) error {
	// Pick any org row to stash the KEK on. We use the lowest org_id so the
	// value lands deterministically; the KEK is install-global, not per-org,
	// but we reuse org_settings to avoid a fresh table.
	var orgID string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		return fmt.Errorf("secrets: no org to bootstrap KEK into: %w", err)
	}
	_, err := pool.Exec(ctx, `
INSERT INTO org_settings (org_id, settings)
VALUES ($1::uuid, jsonb_build_object($2::text, $3::text))
ON CONFLICT (org_id) DO UPDATE
   SET settings = org_settings.settings || jsonb_build_object($2::text, $3::text),
       updated_at = NOW()`, orgID, SettingsKey, hex.EncodeToString(key))
	return err
}

// HexKey returns a hex-encoded random 32-byte key for the operator to put in
// their secret store. Intended for use by an out-of-band rotate-kek CLI.
func HexKey() (string, error) {
	k := make([]byte, keyLen)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}
