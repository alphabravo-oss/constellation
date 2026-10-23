package identity

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP interoperability; not a password or signature hash.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

type BreakGlassConfig struct {
	Enabled      bool          `json:"enabled"`
	PasswordHash string        `json:"-"`
	TOTPSecret   string        `json:"-"`
	OrgName      string        `json:"-"`
	SessionTTL   time.Duration `json:"-"`
}

func (c *BreakGlassConfig) validate() error {
	if c.OrgName == "" {
		c.OrgName = "default"
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 5 * time.Minute
	}
	if c.SessionTTL < time.Minute || c.SessionTTL > 10*time.Minute {
		return errors.New("break-glass session must be between 1 and 10 minutes")
	}
	if !c.Enabled {
		return nil
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(c.TOTPSecret))
	if err != nil || len(key) < 20 {
		return errors.New("break-glass requires a base32 TOTP secret of at least 20 bytes")
	}
	if !strings.HasPrefix(c.PasswordHash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		return errors.New("break-glass requires an Argon2id hash (64 MiB, 3 passes, 4 lanes)")
	}
	// Parse and bound the full encoded hash at startup; a mismatch is expected.
	if err := VerifyPassword(c.PasswordHash, randomToken()); !errors.Is(err, ErrInvalidPassword) {
		return errors.New("invalid break-glass password hash")
	}
	return nil
}

// totpStep accepts the current 30-second step and one step either side. The
// accepted step is consumed atomically in Postgres, preventing cross-replica replay.
func totpStep(secret, code string, now time.Time) int64 {
	if len(code) != 6 {
		return -1
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return -1
	}
	step := now.Unix() / 30
	for delta := int64(-1); delta <= 1; delta++ {
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(step+delta))
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(counter[:])
		sum := mac.Sum(nil)
		offset := sum[len(sum)-1] & 15
		value := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
		if subtle.ConstantTimeCompare([]byte(fmt.Sprintf("%06d", value)), []byte(code)) == 1 {
			return step + delta
		}
	}
	return -1
}
