package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type signingKey struct {
	method    jwt.SigningMethod
	signKey   any
	verifyKey any
}
type keyStore interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Begin(context.Context) (pgx.Tx, error)
}

func parseSigningKeys(keys [][]byte) ([]signingKey, error) {
	if len(keys) == 0 {
		return nil, errors.New("auth: at least one key required")
	}
	parsed := make([]signingKey, 0, len(keys))
	for i, raw := range keys {
		k, err := parseSigningKey(raw)
		if err != nil {
			return nil, fmt.Errorf("auth: key %d: %w", i, err)
		}
		parsed = append(parsed, k)
	}
	if parsed[0].signKey == nil {
		return nil, errors.New("auth: active key must be signing-capable")
	}
	return parsed, nil
}
func parseSigningKey(raw []byte) (signingKey, error) {
	if block, _ := pem.Decode(raw); block != nil {
		priv, err := parsePEMPrivateKey(block)
		if err != nil {
			return signingKey{}, err
		}
		switch key := priv.(type) {
		case *rsa.PrivateKey:
			return signingKey{method: jwt.SigningMethodRS256, signKey: key, verifyKey: &key.PublicKey}, nil
		case *ecdsa.PrivateKey:
			return signingKey{method: jwt.SigningMethodES256, signKey: key, verifyKey: &key.PublicKey}, nil
		default:
			return signingKey{}, fmt.Errorf("unsupported PEM private key type %T", priv)
		}
	}
	// A5: a non-PEM raw secret would sign sessions HS256, a silent downgrade from
	// the RS256/ES256 asymmetric default. Refuse it unless the operator explicitly
	// opts in, so a 32-byte blob can never quietly weaken session signing.
	if !hs256Allowed() {
		return signingKey{}, errors.New(
			"auth: JWT key is not a PEM RSA/EC private key; HS256 is disabled " +
				"(set CONSTELLATION_ALLOW_HS256_JWT=true to opt in to symmetric session signing)")
	}
	if len(raw) < 32 {
		return signingKey{}, errors.New("HS256 secret must be >= 32 bytes")
	}
	return signingKey{method: jwt.SigningMethodHS256, signKey: raw, verifyKey: raw}, nil
}
func hs256Allowed() bool {
	v := os.Getenv("CONSTELLATION_ALLOW_HS256_JWT")
	return v == "1" || v == "true" || v == "TRUE" || v == "True"
}
func parsePEMPrivateKey(block *pem.Block) (any, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
