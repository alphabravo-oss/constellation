// Package identity implements a single OIDC relying party and an emergency admin login.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	sharedrp "github.com/alphabravo-oss/identity/pkg/rp"

	"github.com/alphabravocompany/constellation/pkg/rbac"
)

const MaxTokenLifetime = 10 * time.Minute

type OIDCConfig struct {
	Bundled      bool              `json:"-"`
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

type Principal struct {
	Subject string
	Email   string
	Name    string
	Nonce   string
	Roles   []string
	Expires time.Time
}

// Verifier maps verified shared-identity roles to Constellation authorization.
// Signature validation, JWKS refresh and bounded memoization belong to pkg/rp.
type Verifier struct {
	shared  *sharedrp.Verifier
	mapping map[string]string
}

func newVerifier(ctx context.Context, client *http.Client, jwksURL string, cfg OIDCConfig, audience string, idToken bool) (*Verifier, error) {
	c := sharedrp.Config{Issuer: cfg.IssuerURL, Audience: audience, JWKSURL: jwksURL, Product: "constellation", RolesClaim: cfg.RolesClaim, HTTPClient: client, MaxTokenLifetime: MaxTokenLifetime, Algorithms: []string{"RS256", "RS384", "RS512", "PS256", "ES256"}}
	if idToken {
		c.AuthorizedParty = cfg.ClientID
	}
	verifier, err := sharedrp.New(ctx, c)
	if err != nil {
		return nil, err
	}
	return &Verifier{shared: verifier, mapping: cfg.RoleMapping}, nil
}

func (v *Verifier) Verify(raw string) (*Principal, error) {
	i, err := v.shared.Verify(raw)
	if err != nil {
		return nil, errors.New("invalid OIDC token")
	}
	p := &Principal{Subject: i.Subject(), Email: i.Email(), Name: i.Name(), Nonce: i.Nonce(), Expires: i.Expires()}
	seen := make(map[string]bool)
	for _, source := range i.Roles() {
		if role := v.mapping[source]; role != "" && !seen[role] {
			seen[role] = true
			p.Roles = append(p.Roles, role)
		}
	}
	return p, nil
}

type metadata struct {
	Issuer           string   `json:"issuer"`
	Authorization    string   `json:"authorization_endpoint"`
	Token            string   `json:"token_endpoint"`
	JWKS             string   `json:"jwks_uri"`
	TokenAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

type RP struct {
	cfg    OIDCConfig
	meta   metadata
	client *http.Client
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
	var err error
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
	r.Access, err = newVerifier(ctx, client, r.meta.JWKS, cfg, cfg.Audience, false)
	if err != nil {
		return nil, errors.New("OIDC signing keys unavailable")
	}
	r.ID, err = newVerifier(ctx, client, r.meta.JWKS, cfg, cfg.ClientID, true)
	if err != nil {
		return nil, errors.New("OIDC signing keys unavailable")
	}

	return r, nil
}

func (r *RP) request(ctx context.Context, method, endpoint string, form url.Values, out any) error {
	basic := endpoint == r.meta.Token && r.cfg.ClientSecret != "" && slices.Contains(r.meta.TokenAuthMethods, "client_secret_basic")
	if basic {
		form.Del("client_secret")
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errors.New("invalid OIDC request")
	}
	if basic {
		req.SetBasicAuth(url.QueryEscape(r.cfg.ClientID), url.QueryEscape(r.cfg.ClientSecret))
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return errors.New("OIDC provider unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
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
func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

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
