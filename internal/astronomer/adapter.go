// Package astronomer is the Astronomer-mode adapter: JWKS-backed JWT validation +
// astronomer_identity_map cross-reference.
//
// Constellation has two modes:
//   - Standalone: local Argon2id + OIDC SP, Constellation issues its own JWTs.
//   - Astronomer-integrated: Astronomer is the IdP; Constellation validates Astronomer JWTs
//     via Astronomer's JWKS for /api/v1/security/* routes.
//
// Both modes can run side-by-side. Routes under /api/v1/security/* are Astronomer-mounted;
// /api/v1/* root routes are standalone.
package astronomer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/jwks"
)

// Validator caches Astronomer JWKS + verifies tokens. Thin wrapper around pkg/jwks so the
// astronomer-mode flow shares the same RSA reconstruction code as the standalone OIDC SP.
type Validator struct {
	client   *jwks.Client
	issuer   string
	audience string
}

// ValidatorOption tightens token validation for an Astronomer JWT verifier.
type ValidatorOption func(*Validator)

// WithIssuer requires the Astronomer JWT iss claim to match issuer.
func WithIssuer(issuer string) ValidatorOption {
	return func(v *Validator) { v.issuer = strings.TrimSpace(issuer) }
}

// WithAudience requires the Astronomer JWT aud claim to include audience.
func WithAudience(audience string) ValidatorOption {
	return func(v *Validator) { v.audience = strings.TrimSpace(audience) }
}

// NewValidator constructs a Validator for the given Astronomer JWKS URL.
func NewValidator(jwksURL string, opts ...ValidatorOption) *Validator {
	v := &Validator{client: jwks.New(jwksURL)}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify parses + validates an Astronomer JWT. Returns the parsed claims on success.
// HMAC is rejected; only RSA / ECDSA via JWKS are accepted.
func (v *Validator) Verify(ctx context.Context, raw string) (jwt.MapClaims, error) {
	parserOpts := []jwt.ParserOption{}
	if v.issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(v.audience))
	}
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodECDSA:
			kid, _ := t.Header["kid"].(string)
			return v.client.Key(ctx, kid)
		case *jwt.SigningMethodHMAC:
			return nil, errors.New("astronomer: HS256 disabled (RS256/ES256 against JWKS only)")
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
	}, parserOpts...)
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("astronomer: invalid token: %w", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("astronomer: claims not MapClaims")
	}
	return claims, nil
}

// SubjectID extracts the stable Astronomer user key used by astronomer_identity_map.
func SubjectID(claims jwt.MapClaims) (string, error) {
	for _, key := range []string{"sub", "uid", "user_id", "id"} {
		v, ok := claims[key].(string)
		if !ok {
			continue
		}
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed, nil
		}
	}
	return "", errors.New("astronomer: token missing stable subject claim")
}

// Mapper resolves an Astronomer user id to a Constellation (user_id, org_id) pair.
type Mapper struct {
	pool *pgxpool.Pool
}

func NewMapper(pool *pgxpool.Pool) *Mapper { return &Mapper{pool: pool} }

// Resolve looks up the Constellation subject for an Astronomer identity. Returns
// ErrUnmapped when no row exists; callers should auto-provision per the org policy.
func (m *Mapper) Resolve(ctx context.Context, astronomerUserID string) (userID, orgID uuid.UUID, err error) {
	err = m.pool.QueryRow(ctx,
		`SELECT user_id, org_id FROM astronomer_identity_map WHERE astronomer_user_id = $1`,
		astronomerUserID,
	).Scan(&userID, &orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrUnmapped
	}
	return userID, orgID, err
}

// Link inserts/upserts the mapping. Used after auto-provisioning a fresh Constellation user
// for an Astronomer principal seen for the first time.
func (m *Mapper) Link(ctx context.Context, astronomerUserID string, userID, orgID uuid.UUID) error {
	_, err := m.pool.Exec(ctx,
		`INSERT INTO astronomer_identity_map (astronomer_user_id, user_id, org_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (astronomer_user_id) DO UPDATE SET user_id = EXCLUDED.user_id, org_id = EXCLUDED.org_id`,
		astronomerUserID, userID, orgID,
	)
	return err
}

// ErrUnmapped is returned by Resolve when no mapping exists.
var ErrUnmapped = errors.New("astronomer: identity not mapped to constellation subject")
