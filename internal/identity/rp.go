// Package identity implements a single OIDC relying party and an emergency admin login.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alphabravocompany/constellation/internal/identity/jwks"
	"github.com/alphabravocompany/constellation/pkg/rbac"
	"github.com/golang-jwt/jwt/v5"
)

const MaxTokenLifetime = 10 * time.Minute
const memoLimit = 10000

type OIDCConfig struct {
	IssuerURL    string            `json:"issuer_url"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"-"`
	Audience     string            `json:"audience"`
	RedirectURL  string            `json:"redirect_url"`
	RolesClaim   string            `json:"roles_claim"`
	RoleMapping  map[string]string `json:"role_mapping"`
	OrgName      string            `json:"org_name"`
	Scopes       []string          `json:"scopes"`
}

func (c *OIDCConfig) defaults() {
	if c.RolesClaim == "" {
		c.RolesClaim = "alphabravo_roles"
	}
	if c.Audience == "" {
		c.Audience = c.ClientID
	}
	if c.OrgName == "" {
		c.OrgName = "default"
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "email", "profile"}
	}
}

func (c OIDCConfig) validate() error {
	for _, raw := range []string{c.IssuerURL, c.RedirectURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
			return errors.New("OIDC requires absolute HTTPS issuer and redirect URLs")
		}
	}
	if c.ClientID == "" || c.Audience == "" {
		return errors.New("OIDC client ID and audience are required")
	}
	for group, role := range c.RoleMapping {
		if group == "" || !rbac.IsRole(role) {
			return errors.New("invalid OIDC role mapping")
		}
	}
	return nil
}

type tokenClaims struct {
	jwt.RegisteredClaims
	Email           string `json:"email"`
	Name            string `json:"name"`
	Nonce           string `json:"nonce"`
	AuthorizedParty string `json:"azp"`
}

type Principal struct {
	Subject string
	Email   string
	Name    string
	Nonce   string
	Roles   []string
	Expires time.Time
}

type Verifier struct {
	keys     *jwks.Cache
	parser   *jwt.Parser
	claim    string
	mapping  map[string]string
	clientID string
	idToken  bool
	mu       sync.Mutex
	memo     map[string]*Principal
}

func newVerifier(keys *jwks.Cache, cfg OIDCConfig, audience string, idToken bool) *Verifier {
	return &Verifier{keys: keys, parser: jwt.NewParser(jwt.WithIssuer(cfg.IssuerURL), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "ES256"})), claim: cfg.RolesClaim, mapping: cfg.RoleMapping, clientID: cfg.ClientID, idToken: idToken, memo: make(map[string]*Principal)}
}

// Verify memoizes successful signatures only. Expiry is checked on every cache hit.
// Memory is bounded to 10k tokens; no request waits for discovery or a JWKS fetch.
func (v *Verifier) Verify(raw string) (*Principal, error) {
	if len(raw) > 16*1024 {
		return nil, errors.New("token too large")
	}
	now := time.Now()
	v.mu.Lock()
	p := v.memo[raw]
	v.mu.Unlock()
	if p != nil && now.Before(p.Expires) {
		return p, nil
	}
	claims := jwt.MapClaims{}
	tok, err := v.parser.ParseWithClaims(raw, claims, v.keys.Keyfunc)
	if err != nil || !tok.Valid {
		return nil, errors.New("invalid OIDC token")
	}
	sub, _ := claims["sub"].(string)
	exp, _ := claims.GetExpirationTime()
	iat, _ := claims.GetIssuedAt()
	if sub == "" || exp == nil || iat == nil || exp.Sub(iat.Time) > MaxTokenLifetime || !exp.After(now) {
		return nil, errors.New("missing subject or invalid token lifetime (maximum 10 minutes)")
	}
	if v.idToken {
		aud, _ := claims.GetAudience()
		if len(aud) > 1 && claims["azp"] != v.clientID {
			return nil, errors.New("invalid authorized party")
		}
	}
	p = &Principal{Subject: sub, Expires: exp.Time}
	p.Email, _ = claims["email"].(string)
	p.Name, _ = claims["name"].(string)
	p.Nonce, _ = claims["nonce"].(string)
	values := claims[v.claim]
	// The platform emits {"constellation":[...]}; external providers may emit a flat array.
	if projects, ok := values.(map[string]any); ok {
		values = projects["constellation"]
	}
	var groups []string
	switch a := values.(type) {
	case string:
		groups = []string{a}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				groups = append(groups, s)
			}
		}
	}
	seen := map[string]bool{}
	for _, g := range groups {
		if role := v.mapping[g]; role != "" && !seen[role] {
			seen[role] = true
			p.Roles = append(p.Roles, role)
		}
	}
	v.mu.Lock()
	if len(v.memo) >= memoLimit {
		clear(v.memo)
	}
	v.memo[raw] = p
	v.mu.Unlock()
	return p, nil
}

type metadata struct {
	Issuer        string `json:"issuer"`
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	JWKS          string `json:"jwks_uri"`
}

type RP struct {
	cfg    OIDCConfig
	meta   metadata
	client *http.Client
	Keys   *jwks.Cache
	Access *Verifier
	ID     *Verifier
}

func NewRP(ctx context.Context, cfg OIDCConfig) (*RP, error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	r := &RP{cfg: cfg, client: client}
	if err := r.request(ctx, http.MethodGet, strings.TrimRight(cfg.IssuerURL, "/")+"/.well-known/openid-configuration", nil, &r.meta); err != nil {
		return nil, err
	}
	if r.meta.Issuer != cfg.IssuerURL {
		return nil, errors.New("OIDC discovery issuer mismatch")
	}
	for _, raw := range []string{r.meta.Authorization, r.meta.Token, r.meta.JWKS} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return nil, errors.New("OIDC discovery requires HTTPS endpoints")
		}
	}
	r.Keys = jwks.New(r.meta.JWKS, client)
	if err := r.Keys.Refresh(ctx); err != nil {
		return nil, errors.New("OIDC signing keys unavailable")
	}
	r.Access = newVerifier(r.Keys, cfg, cfg.Audience, false)
	r.ID = newVerifier(r.Keys, cfg, cfg.ClientID, true)
	return r, nil
}

func (r *RP) request(ctx context.Context, method, endpoint string, form url.Values, out any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errors.New("invalid OIDC request")
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return errors.New("OIDC provider unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC provider status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return errors.New("invalid OIDC response")
	}
	return nil
}

func randomToken() string { return base64.RawURLEncoding.EncodeToString(randBytes(32)) }
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func tokenHash(raw string) string { sum := sha256.Sum256([]byte(raw)); return fmt.Sprintf("%x", sum) }

func (r *RP) Start(state, verifier, nonce string) string {
	h := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {r.cfg.ClientID}, "redirect_uri": {r.cfg.RedirectURL}, "scope": {strings.Join(r.cfg.Scopes, " ")}, "state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(h[:])}, "code_challenge_method": {"S256"}}
	return r.meta.Authorization + "?" + q.Encode()
}

func (r *RP) Exchange(ctx context.Context, code, verifier, nonce string) (*Principal, error) {
	var tokens struct {
		ID string `json:"id_token"`
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {r.cfg.ClientID}, "client_secret": {r.cfg.ClientSecret}, "redirect_uri": {r.cfg.RedirectURL}, "code_verifier": {verifier}}
	if err := r.request(ctx, http.MethodPost, r.meta.Token, form, &tokens); err != nil {
		return nil, err
	}
	p, err := r.ID.Verify(tokens.ID)
	if err != nil {
		return nil, err
	}
	if nonce == "" || p.Nonce != nonce {
		return nil, errors.New("OIDC nonce mismatch")
	}
	return p, nil
}
