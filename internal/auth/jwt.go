package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the Constellation JWT payload. Mirrors astronomer-go.
type Claims struct {
	UserID uuid.UUID `json:"uid"`
	OrgID  uuid.UUID `json:"oid"`
	Email  string    `json:"email"`
	Roles  []string  `json:"roles,omitempty"`
	// Epoch is the users.session_epoch the user had at mint time (A1). The auth
	// middleware re-reads the current epoch on each request and rejects the token
	// when Epoch < users.session_epoch — the DB-backed revocation primitive that
	// invalidates prior sessions on logout / disable / delete / password-change /
	// role-change, consistently across API replicas.
	Epoch int64 `json:"epoch"`
	jwt.RegisteredClaims
}

// signingKey is one rotation slot: a JWT signing method plus the material to sign
// and/or verify with it. For asymmetric keys (RS256/ES256, the A5 default) signKey
// is the private key and verifyKey is its public half, so a verifier-only replica can
// hold just the public key. For the legacy HS256 symmetric case both fields hold the
// same []byte secret.
type signingKey struct {
	method   jwt.SigningMethod
	signKey  any // private key (or HMAC secret); nil for verify-only keys
	verifyKey any // public key (or HMAC secret)
}

// Signer issues and verifies JWTs.
type Signer struct {
	// mu guards keys so a background rotation poller can atomically swap the key set
	// (A5 hot reload) while the auth middleware concurrently verifies and the login
	// handler concurrently signs — all through the same *Signer pointer.
	mu sync.RWMutex
	// keys holds the active and a rotating "previous" key so existing tokens stay valid through
	// a rotation. New tokens are always signed with keys[0]. A5: keys[0] must be signing-capable
	// (asymmetric private key or HMAC secret); later keys may be verify-only public keys.
	keys     []signingKey
	issuer   string
	audience string
	ttl      time.Duration
}

// NewSigner constructs a Signer from raw key material; index 0 is the active signer.
//
// A5: each key is auto-detected. A PEM-encoded RSA or EC private key yields an RS256/ES256
// asymmetric signer (the production default — verifiers can hold only the public half). Any
// other byte slice (>= 32 bytes) is treated as a legacy HS256 symmetric secret, preserving
// backwards compatibility with the env-provided JWT_KEYS path and existing tests.
func NewSigner(issuer, audience string, ttl time.Duration, keys ...[]byte) (*Signer, error) {
	parsed, err := parseSigningKeys(keys)
	if err != nil {
		return nil, err
	}
	return &Signer{keys: parsed, issuer: issuer, audience: audience, ttl: ttl}, nil
}

// parseSigningKeys parses+validates a rotation key set: index 0 must be signing-capable.
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

// ReloadKeys atomically swaps the signer's rotation key set (A5 hot reload). A
// background poller calls this when session_signing_keys rotates so running
// replicas pick up the new active key and retain the previous key for verifying
// already-issued tokens — without re-wiring routes or restarting. keys[0] must be
// signing-capable; on any parse error the existing key set is left untouched.
func (s *Signer) ReloadKeys(keys ...[]byte) error {
	parsed, err := parseSigningKeys(keys)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.keys = parsed
	s.mu.Unlock()
	return nil
}

// parseSigningKey detects RS256/ES256 PEM private keys, falling back to an HS256 secret.
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

// hs256Allowed reports whether the operator has explicitly opted in to symmetric
// HS256 session signing. Default is false: sessions are RS256/ES256.
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

// Issue produces a signed JWT for the subject. epoch is the user's current
// users.session_epoch; it is embedded so the auth middleware can reject the token
// once the user's epoch is bumped (logout / disable / delete / password / role change).
//
// The returned sessionID is the JWT's jti claim. It is also the key the login path
// records in user_sessions for the A3 concurrent-session cap: the auth middleware
// rejects a JWT whose session row has been evicted. Callers that do not track sessions
// can ignore it.
func (s *Signer) Issue(userID, orgID uuid.UUID, email string, roles []string, epoch int64) (string, uuid.UUID, error) {
	return s.IssueWithTTL(s.ttl, userID, orgID, email, roles, epoch)
}

// TTL returns the deploy-time default session lifetime the signer was configured with. The
// login path passes it as the fallback to SecurityPolicy.SessionTTL so a per-org policy can
// override it per login while an unconfigured org keeps the env/deploy default (A1).
func (s *Signer) TTL() time.Duration { return s.ttl }

// IssueWithTTL is Issue with a caller-supplied absolute lifetime, so the login path can honor a
// per-org SecurityPolicy.SessionTTL without mutating the shared signer (A1). A non-positive ttl
// falls back to the signer's configured default.
func (s *Signer) IssueWithTTL(ttl time.Duration, userID, orgID uuid.UUID, email string, roles []string, epoch int64) (string, uuid.UUID, error) {
	if ttl <= 0 {
		ttl = s.ttl
	}
	now := time.Now()
	sessionID := uuid.New()
	c := Claims{
		UserID: userID,
		OrgID:  orgID,
		Email:  email,
		Roles:  roles,
		Epoch:  epoch,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{s.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			Subject:   userID.String(),
			ID:        sessionID.String(),
		},
	}
	s.mu.RLock()
	active := s.keys[0]
	s.mu.RUnlock()
	tok := jwt.NewWithClaims(active.method, c)
	signed, err := tok.SignedString(active.signKey)
	if err != nil {
		return "", uuid.Nil, err
	}
	return signed, sessionID, nil
}

// SessionID returns the jti (session id) parsed from the claims, or uuid.Nil if absent
// or malformed. Used by the auth middleware to look up the session row for the A3
// concurrent-session cap.
func (c *Claims) SessionID() uuid.UUID {
	id, err := uuid.Parse(c.ID)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// Verify parses + validates a JWT, accepting any of the rotation keys. A token signed
// before a rotation stays valid until it expires because the prior key remains in the set.
func (s *Signer) Verify(raw string) (*Claims, error) {
	s.mu.RLock()
	keys := s.keys
	s.mu.RUnlock()
	var lastErr error
	for _, key := range keys {
		c := &Claims{}
		tok, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != key.method.Alg() {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return key.verifyKey, nil
		}, jwt.WithIssuer(s.issuer), jwt.WithAudience(s.audience))
		if err == nil && tok.Valid {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Compile-time guard that the asymmetric private keys we accept satisfy crypto.Signer
// (every RSA/EC private key does; this documents the contract for parseSigningKey).
var (
	_ crypto.Signer = (*rsa.PrivateKey)(nil)
	_ crypto.Signer = (*ecdsa.PrivateKey)(nil)
)
