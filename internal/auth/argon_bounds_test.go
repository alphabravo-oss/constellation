package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestVerifyPasswordRejectsMalformedAndUnboundedHashes(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	validShape := "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$" + key
	for name, hash := range map[string]string{
		"empty":                        "",
		"oversized":                    strings.Repeat("x", 257),
		"prefix":                       "ignored" + validShape,
		"version suffix":               strings.Replace(validShape, "v=19", "v=19ignored", 1),
		"parameter suffix":             strings.Replace(validShape, "p=4", "p=4ignored", 1),
		"zero passes":                  strings.Replace(validShape, "t=3", "t=0", 1),
		"zero lanes":                   strings.Replace(validShape, "p=4", "p=0", 1),
		"excess lanes":                 strings.Replace(validShape, "p=4", "p=255", 1),
		"excess memory":                strings.Replace(validShape, "m=65536", "m=4294967295", 1),
		"excess passes":                strings.Replace(validShape, "t=3", "t=4294967295", 1),
		"insufficient memory per lane": strings.Replace(validShape, "m=65536", "m=1", 1),
		"empty key":                    "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$",
		"empty salt":                   "$argon2id$v=19$m=65536,t=3,p=4$$" + key,
		"short key":                    "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$AA",
		"invalid base64":               "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$!",
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyPassword(hash, "irrelevant"); !errors.Is(err, ErrInvalidHashFormat) {
				t.Fatalf("expected invalid-hash error, got %v", err)
			}
		})
	}
}
