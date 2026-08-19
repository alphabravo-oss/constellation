// Package auth handles local credential storage (Argon2id) + JWT issuance + OIDC SP flow.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

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
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrInvalidHashFormat
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return ErrInvalidHashFormat
	}

	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrInvalidHashFormat
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHashFormat
	}

	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(expected)))
	if subtle.ConstantTimeCompare(got, expected) != 1 {
		return ErrInvalidPassword
	}
	return nil
}

// ---- A4: password policy ----

// PasswordProfile is the per-org password strength + lifecycle policy (A4). For now
// it is constructed from DefaultPasswordProfile; the plan moves it into per-org
// system_config (B1) — the struct is the seam so that migration is a storage swap,
// not a logic rewrite.
type PasswordProfile struct {
	// MinLength is the minimum number of characters (UTF-8 runes).
	MinLength int
	// MinClasses is the minimum number of distinct character classes the password must
	// contain, out of {lowercase, uppercase, digit, symbol}.
	MinClasses int
	// MaxAge is how long a password is valid before a change is required; zero disables.
	MaxAge time.Duration
	// HistoryDepth is how many recent password hashes are retained + checked for reuse;
	// zero disables reuse checking.
	HistoryDepth int
}

// DefaultPasswordProfile is the built-in policy used until per-org profiles land (B1):
// 12+ chars, at least 3 of 4 character classes, 90-day max age, last 5 reuse-blocked.
func DefaultPasswordProfile() PasswordProfile {
	return PasswordProfile{
		MinLength:    12,
		MinClasses:   3,
		MaxAge:       90 * 24 * time.Hour,
		HistoryDepth: 5,
	}
}

// ErrWeakPassword is returned by ValidatePassword when a candidate fails the policy.
var ErrWeakPassword = errors.New("auth: password does not meet policy")

// ValidatePassword enforces a PasswordProfile against a candidate password (A4). It
// rejects empty / whitespace-only passwords, ones below MinLength, and ones that do not
// span at least MinClasses character classes. The returned error wraps ErrWeakPassword
// and carries a human-readable reason; callers surface a generic message to the client.
func ValidatePassword(profile PasswordProfile, pw string) error {
	if strings.TrimSpace(pw) == "" {
		return fmt.Errorf("%w: password is empty", ErrWeakPassword)
	}
	if n := len([]rune(pw)); n < profile.MinLength {
		return fmt.Errorf("%w: must be at least %d characters", ErrWeakPassword, profile.MinLength)
	}
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if ok {
			classes++
		}
	}
	if classes < profile.MinClasses {
		return fmt.Errorf("%w: must include at least %d of lowercase/uppercase/digit/symbol", ErrWeakPassword, profile.MinClasses)
	}
	return nil
}
