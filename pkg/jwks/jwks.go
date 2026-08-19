// Package jwks is the JWKS (RFC 7517) client used by Constellation's OIDC SP and Astronomer
// adapter. It fetches the IdP's signing keys, caches them, and reconstructs Go
// *rsa.PublicKey / ecdsa.PublicKey values from JWK n/e (or x/y) base64url-encoded fields.
//
// The package intentionally avoids github.com/lestrrat-go/jwx (heavy + frequently breaking)
// in favour of the small amount of standard-library crypto needed for the common alg set:
// RS256, RS384, RS512, ES256.
package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Client caches JWKS responses + reconstructs public keys lazily.
type Client struct {
	URL        string
	HTTPClient *http.Client
	CacheTTL   time.Duration

	mu      sync.RWMutex
	keys    map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	fetched time.Time
}

// New constructs a Client with default 5m cache TTL and a 10s HTTP timeout.
func New(url string) *Client {
	return &Client{
		URL:        url,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		CacheTTL:   5 * time.Minute,
		keys:       map[string]any{},
	}
}

// Key returns the public key for kid, refreshing the JWKS if the cache is stale or the kid
// is unknown. Returns ErrUnknownKID when the IdP doesn't advertise the kid.
func (c *Client) Key(ctx context.Context, kid string) (any, error) {
	c.mu.RLock()
	if k, ok := c.keys[kid]; ok && time.Since(c.fetched) < c.CacheTTL {
		c.mu.RUnlock()
		return k, nil
	}
	c.mu.RUnlock()

	if err := c.refresh(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
}

// ErrUnknownKID is returned when the JWKS doesn't include the requested kid.
var ErrUnknownKID = errors.New("jwks: unknown kid")

type jwksDoc struct {
	Keys []map[string]any `json:"keys"`
}

func (c *Client) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("jwks: decode: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = map[string]any{}
	for _, k := range doc.Keys {
		key, kid, err := ParseKey(k)
		if err == nil && kid != "" {
			c.keys[kid] = key
		}
	}
	c.fetched = time.Now()
	return nil
}

// ParseKey extracts a usable Go key (*rsa.PublicKey or *ecdsa.PublicKey) from a JWKS entry.
// Supports kty in {"RSA","EC"}. Returns (key, kid, error).
func ParseKey(m map[string]any) (any, string, error) {
	kid, _ := m["kid"].(string)
	kty, _ := m["kty"].(string)
	switch strings.ToUpper(kty) {
	case "RSA":
		k, err := parseRSA(m)
		return k, kid, err
	case "EC":
		k, err := parseEC(m)
		return k, kid, err
	default:
		return nil, kid, fmt.Errorf("jwks: unsupported kty %q", kty)
	}
}

func parseRSA(m map[string]any) (*rsa.PublicKey, error) {
	nB64, _ := m["n"].(string)
	eB64, _ := m["e"].(string)
	if nB64 == "" || eB64 == "" {
		return nil, errors.New("jwks: rsa key missing n/e")
	}
	nBytes, err := b64decode(nB64)
	if err != nil {
		return nil, fmt.Errorf("jwks: decode n: %w", err)
	}
	eBytes, err := b64decode(eB64)
	if err != nil {
		return nil, fmt.Errorf("jwks: decode e: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("jwks: rsa key empty n/e")
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	if pub.E <= 0 {
		return nil, errors.New("jwks: rsa key invalid exponent")
	}
	return pub, nil
}

func parseEC(m map[string]any) (*ecdsa.PublicKey, error) {
	crv, _ := m["crv"].(string)
	xB64, _ := m["x"].(string)
	yB64, _ := m["y"].(string)
	if xB64 == "" || yB64 == "" {
		return nil, errors.New("jwks: ec key missing x/y")
	}
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jwks: ec key unsupported curve %q", crv)
	}
	xBytes, err := b64decode(xB64)
	if err != nil {
		return nil, fmt.Errorf("jwks: decode x: %w", err)
	}
	yBytes, err := b64decode(yB64)
	if err != nil {
		return nil, fmt.Errorf("jwks: decode y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// b64decode tolerates accidental padding from misconfigured IdPs.
func b64decode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
