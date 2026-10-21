// Argon2id protects local account passwords, including the recovery administrator.
package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters meet the spec's "memory ≥ 64MB, iterations ≥ 3" floor (P1-US-4).
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// HashPassword returns the encoded Argon2id hash for a password.
// Encoded format follows the standard `$argon2id$v=19$m=...,t=...,p=...$salt$hash` convention so
// it's portable across language ecosystems (matches Astronomer's stored form).
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: gen salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// ErrInvalidPassword is returned by VerifyPassword on mismatch.
var ErrInvalidPassword = errors.New("auth: invalid password")

// ErrInvalidHashFormat is returned for malformed stored hashes.
var ErrInvalidHashFormat = errors.New("auth: invalid hash format")

// VerifyPassword constant-time compares `password` against `encoded`.
func VerifyPassword(encoded, password string) error {
	// Stored/restore-supplied hashes are untrusted input. Bound decoding and KDF
	// cost before allocation, and reject zero parameters that make IDKey panic.
	if len(encoded) > 256 {
		return ErrInvalidHashFormat
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return ErrInvalidHashFormat
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version || parts[2] != fmt.Sprintf("v=%d", version) {
		return ErrInvalidHashFormat
	}

	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return ErrInvalidHashFormat
	}
	// All locally issued hashes use 64 MiB / 3 passes / 4 lanes. Permit smaller
	// historical costs without letting a corrupt record request unbounded work.
	if m > argonMemory || p == 0 || p > 16 || m < 8*uint32(p) || t == 0 || t > 10 ||
		parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", m, t, p) {
		return ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return ErrInvalidHashFormat
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHashFormat
	}
	keyLen := len(expected)
	if keyLen < 16 || keyLen > 64 {
		return ErrInvalidHashFormat
	}

	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(keyLen))
	if subtle.ConstantTimeCompare(got, expected) != 1 {
		return ErrInvalidPassword
	}
	return nil
}
