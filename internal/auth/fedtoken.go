package auth

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Federation token purposes. A join token is the short-lived credential a master
// hands an operator (or GitOps) to bootstrap a joint; a sync ticket is the
// per-cluster secret a joint then exchanges it for and presents on every poll.
const (
	FedPurposeJoin = "fed-join"
	FedPurposeSync = "fed-sync"

	// fedIssuer / fedAudience pin the join/sync tokens to the federation surface so a
	// token minted for another purpose (or a user session JWT) can never satisfy a fed
	// verification even if it were somehow signed by the same key.
	fedIssuer   = "constellation-fed"
	fedAudience = "constellation-fed"
)

// FedClaims is the payload of a federation join token or per-cluster sync ticket.
// It is deliberately minimal: the master org it scopes to, the joint cluster id (set
// on a sync ticket; empty on an org-wide join token), the purpose, and the per-cluster
// epoch at mint time. Epoch mirrors auth.Claims.Epoch (A1): the /sync validator rejects
// a ticket whose Epoch is below the fed_credentials row's current epoch, so a kick/leave
// epoch bump revokes the joint on its next poll.
type FedClaims struct {
	OrgID     uuid.UUID `json:"oid"`
	ClusterID string    `json:"cid,omitempty"`
	Purpose   string    `json:"purpose"`
	Epoch     int64     `json:"epoch"`
	jwt.RegisteredClaims
}

// FedSigner issues and verifies federation join tokens and sync tickets. It reuses the
// same rotation-capable signingKey machinery as the session Signer (A5) but with a
// dedicated key set + issuer/audience, so federation trust is fully isolated from user
// session signing.
type FedSigner struct {
	mu   sync.RWMutex
	keys []signingKey
}

// NewFedSigner builds a FedSigner from PEM key material (active key first), as returned
// by LoadFedSigningKeysPEM. Index 0 must be signing-capable.
func NewFedSigner(keys ...[]byte) (*FedSigner, error) {
	parsed, err := parseSigningKeys(keys)
	if err != nil {
		return nil, err
	}
	return &FedSigner{keys: parsed}, nil
}

// ReloadKeys atomically swaps the signer's key set so a background reloader can pick up
// a rotated fed_signing_keys row without a restart (mirrors Signer.ReloadKeys).
func (s *FedSigner) ReloadKeys(keys ...[]byte) error {
	parsed, err := parseSigningKeys(keys)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.keys = parsed
	s.mu.Unlock()
	return nil
}

// IssueJoinToken mints a short-lived, signed org-wide join token. The joint presents it
// (or a pre-shared fixed token) to POST /federation/join to obtain a per-cluster secret.
func (s *FedSigner) IssueJoinToken(orgID uuid.UUID, ttl time.Duration) (string, error) {
	tok, _, err := s.IssueJoinTokenWithJTI(orgID, ttl)
	return tok, err
}

// IssueJoinTokenWithJTI mints a join token and also returns its jti, so the caller can
// persist it (fed_join_tokens) and consume it on first exchange — making minted join
// tokens single-use instead of replayable bearer admission tokens.
func (s *FedSigner) IssueJoinTokenWithJTI(orgID uuid.UUID, ttl time.Duration) (token, jti string, err error) {
	return s.issue(FedClaims{OrgID: orgID, Purpose: FedPurposeJoin}, ttl)
}

// IssueSyncTicket mints the per-cluster sync ticket (the per-cluster secret) a joint
// presents on every poll. epoch is the fed_credentials row's current epoch; ttl<=0 mints
// a non-expiring ticket (revocation is then solely via epoch bump / revoked_at).
func (s *FedSigner) IssueSyncTicket(orgID uuid.UUID, clusterID string, epoch int64, ttl time.Duration) (string, error) {
	tok, _, err := s.issue(FedClaims{OrgID: orgID, ClusterID: clusterID, Purpose: FedPurposeSync, Epoch: epoch}, ttl)
	return tok, err
}

func (s *FedSigner) issue(c FedClaims, ttl time.Duration) (token, jti string, err error) {
	now := time.Now()
	jti = uuid.NewString()
	c.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:   fedIssuer,
		Audience: jwt.ClaimStrings{fedAudience},
		IssuedAt: jwt.NewNumericDate(now),
		Subject:  c.OrgID.String(),
		ID:       jti,
	}
	if ttl > 0 {
		c.ExpiresAt = jwt.NewNumericDate(now.Add(ttl))
	}
	s.mu.RLock()
	active := s.keys[0]
	s.mu.RUnlock()
	tok := jwt.NewWithClaims(active.method, c)
	signed, err := tok.SignedString(active.signKey)
	if err != nil {
		return "", "", err
	}
	return signed, jti, nil
}

// VerifyJoinToken validates a signed join token and returns its claims. It rejects a
// token whose purpose is not fed-join (e.g. a sync ticket) so the two credential kinds
// are not interchangeable.
func (s *FedSigner) VerifyJoinToken(raw string) (*FedClaims, error) {
	c, err := s.verify(raw)
	if err != nil {
		return nil, err
	}
	if c.Purpose != FedPurposeJoin {
		return nil, fmt.Errorf("fed: token purpose %q is not a join token", c.Purpose)
	}
	return c, nil
}

// VerifySyncTicket validates a per-cluster sync ticket's signature/claims (purpose +
// issuer/audience + expiry). The caller still checks the fed_credentials row's epoch /
// revocation against the returned ClusterID/Epoch.
func (s *FedSigner) VerifySyncTicket(raw string) (*FedClaims, error) {
	c, err := s.verify(raw)
	if err != nil {
		return nil, err
	}
	if c.Purpose != FedPurposeSync {
		return nil, fmt.Errorf("fed: token purpose %q is not a sync ticket", c.Purpose)
	}
	return c, nil
}

func (s *FedSigner) verify(raw string) (*FedClaims, error) {
	s.mu.RLock()
	keys := s.keys
	s.mu.RUnlock()
	var lastErr error
	for _, key := range keys {
		c := &FedClaims{}
		tok, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != key.method.Alg() {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return key.verifyKey, nil
		}, jwt.WithIssuer(fedIssuer), jwt.WithAudience(fedAudience))
		if err == nil && tok.Valid {
			return c, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("fed: no signing keys")
	}
	return nil, lastErr
}
