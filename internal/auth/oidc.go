package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/alphabravocompany/constellation/pkg/jwks"
)

// OIDCConfig is the per-deployment OIDC SP configuration.
//
// At v1 we deliberately implement the subset needed for the common providers
// (Okta / Auth0 / Azure AD / Keycloak) — auth-code flow with PKCE, ID-token validation via
// the issuer's JWKS, no userinfo call. ID-token claims are the source of truth.
type OIDCConfig struct {
	IssuerURL    string // e.g. https://accounts.example.com
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string    // defaults to ["openid","email","profile"]
	RoleMapping  RoleMapping // group(claim)->Constellation role map applied at JIT login (parity with SAML/LDAP)
}

// OIDCClient is the minimum surface for tests + the handler. The real implementation lives
// in handler/auth_oidc.go and uses this struct.
type OIDCClient struct {
	cfg      OIDCConfig
	provider providerMetadata
	http     *http.Client
	jwks     *jwks.Client
}

type providerMetadata struct {
	Issuer        string `json:"issuer"`
	AuthURL       string `json:"authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	JWKSURL       string `json:"jwks_uri"`
	UserinfoURL   string `json:"userinfo_endpoint"`
	IntrospectURL string `json:"introspection_endpoint"`
}

// NewOIDCClient discovers the provider via the well-known endpoint.
func NewOIDCClient(ctx context.Context, cfg OIDCConfig) (*OIDCClient, error) {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(cfg.IssuerURL, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("oidc: discovery status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery body: %w", err)
	}
	var pm providerMetadata
	if err := json.Unmarshal(body, &pm); err != nil {
		return nil, fmt.Errorf("oidc: discovery decode: %w", err)
	}
	if pm.AuthURL == "" || pm.TokenURL == "" {
		return nil, errors.New("oidc: discovery missing required endpoints")
	}
	c := &OIDCClient{cfg: cfg, provider: pm, http: client}
	if pm.JWKSURL != "" {
		c.jwks = jwks.New(pm.JWKSURL)
		c.jwks.HTTPClient = client
	}
	return c, nil
}

// StartURL returns the redirect URL the browser should be sent to (auth code + PKCE + nonce).
// The caller must store `state`, `verifier`, and `nonce` in the user's session cookie and verify
// them on callback. `state` defends the redirect against CSRF; `nonce` binds the issued id_token
// to this very login attempt, defeating id_token replay/injection (OIDC core §3.1.2.1 / §15.5.2).
func (c *OIDCClient) StartURL() (authURL, state, verifier, nonce string, err error) {
	state, err = randomString(32)
	if err != nil {
		return "", "", "", "", err
	}
	verifier, err = randomString(64)
	if err != nil {
		return "", "", "", "", err
	}
	nonce, err = randomString(32)
	if err != nil {
		return "", "", "", "", err
	}
	challenge := pkceChallenge(verifier)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return c.provider.AuthURL + "?" + q.Encode(), state, verifier, nonce, nil
}

// IDTokenClaims are the user-facing claims we extract from the IdP's id_token.
type IDTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Email     string   `json:"email"`
	EmailOK   bool     `json:"email_verified"`
	Name      string   `json:"name"`
	Nonce     string   `json:"nonce"`
	Groups    []string `json:"groups"` // IdP-asserted group membership, mapped to roles via RoleMapping
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
}

// MapRoles resolves the id_token's asserted groups to Constellation role names via the configured
// RoleMapping, giving OIDC the same JIT group->role provisioning the SAML/LDAP paths already have.
func (c *OIDCClient) MapRoles(groups []string) []string {
	return c.cfg.RoleMapping.MapRoles(groups)
}

// MapScopedRoles is the scope-aware analogue of MapRoles (A2): it resolves the id_token's
// asserted groups to the full set of scoped grants (org-scope roles plus any cluster/namespace
// grants from the provider's ScopedRules), mirroring the SAML/LDAP scoped-resolution paths.
func (c *OIDCClient) MapScopedRoles(groups []string) []ScopedRole {
	return c.cfg.RoleMapping.MapScopedRoles(groups)
}

// Exchange exchanges the auth code for tokens and returns parsed id_token claims after
// verifying the JWS signature against the provider's JWKS. RS256, RS384, RS512 and ES256
// are accepted; HS-* IdPs are rejected.
//
// expectedNonce is the nonce minted by StartURL for this login attempt (carried in the
// caller's session cookie). It is MANDATORY: it must be non-empty and the id_token's `nonce`
// claim MUST equal it — this binds the token to the request and prevents replay/injection of a
// token obtained out of band. The aud claim is independently validated in verifyIDToken.
func (c *OIDCClient) Exchange(ctx context.Context, code, verifier, expectedNonce string) (*IDTokenClaims, string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.cfg.RedirectURL)
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.provider.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("oidc: token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("oidc: token status %d: %s", resp.StatusCode, body)
	}
	var tokens struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, "", fmt.Errorf("oidc: token decode: %w", err)
	}
	claims, err := c.verifyIDToken(ctx, tokens.IDToken)
	if err != nil {
		return nil, "", err
	}
	if claims.Issuer != strings.TrimRight(c.cfg.IssuerURL, "/") && claims.Issuer != c.provider.Issuer {
		return nil, "", fmt.Errorf("oidc: issuer mismatch: %s", claims.Issuer)
	}
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, "", errors.New("oidc: id_token expired")
	}
	// Nonce binding is mandatory: the caller MUST thread the per-login nonce from StartURL. The
	// previous empty-nonce back-compat path is removed — without aud+nonce both enforced a
	// sibling-app id_token on a shared JWKS could otherwise be replayed (OIDC core §3.1.2.1/§15.5.2).
	if expectedNonce == "" {
		return nil, "", errors.New("oidc: missing expected nonce")
	}
	if claims.Nonce != expectedNonce {
		return nil, "", errors.New("oidc: nonce mismatch")
	}
	return claims, tokens.AccessToken, nil
}

// verifyIDToken parses the id_token, looks up the kid in the IdP's JWKS, and verifies the
// signature. Returns the parsed claims only on success.
func (c *OIDCClient) verifyIDToken(ctx context.Context, idToken string) (*IDTokenClaims, error) {
	if c.jwks == nil {
		return nil, errors.New("oidc: jwks not configured on this OIDCClient")
	}
	tok, err := jwt.Parse(idToken, func(t *jwt.Token) (any, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodECDSA:
			kid, _ := t.Header["kid"].(string)
			return c.jwks.Key(ctx, kid)
		default:
			return nil, fmt.Errorf("oidc: unsupported signing method %v", t.Header["alg"])
		}
	},
		// aud MUST contain our client_id (OIDC core §3.1.3.7): rejects a sibling-app token minted by
		// the same issuer / signed with the same JWKS key.
		jwt.WithAudience(c.cfg.ClientID),
	)
	if err != nil || tok == nil || !tok.Valid {
		return nil, fmt.Errorf("oidc: id_token signature verify: %w", err)
	}
	raw, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("oidc: id_token claims not MapClaims")
	}
	// When the token has MULTIPLE audiences, azp MUST be present and equal our client_id
	// (OIDC core §3.1.3.7). WithAudience above only guarantees membership, not single-party.
	if auds := audValues(raw["aud"]); len(auds) > 1 {
		if azp, _ := raw["azp"].(string); azp != c.cfg.ClientID {
			return nil, errors.New("oidc: id_token azp not our client_id for multi-audience token")
		}
	}
	out := &IDTokenClaims{}
	if v, ok := raw["iss"].(string); ok {
		out.Issuer = v
	}
	if v, ok := raw["sub"].(string); ok {
		out.Subject = v
	}
	if v, ok := raw["email"].(string); ok {
		out.Email = v
	}
	if v, ok := raw["email_verified"].(bool); ok {
		out.EmailOK = v
	}
	if v, ok := raw["name"].(string); ok {
		out.Name = v
	}
	if v, ok := raw["nonce"].(string); ok {
		out.Nonce = v
	}
	out.Groups = stringSlice(raw["groups"])
	if v, ok := raw["exp"].(float64); ok {
		out.ExpiresAt = int64(v)
	}
	if v, ok := raw["iat"].(float64); ok {
		out.IssuedAt = int64(v)
	}
	return out, nil
}

// audValues normalizes the JWT `aud` claim (a string OR an array of strings per RFC 7519) into a
// slice so the multi-audience azp rule can be applied uniformly.
func audValues(v any) []string {
	switch a := v.(type) {
	case string:
		if a == "" {
			return nil
		}
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return a
	default:
		return nil
	}
}

// stringSlice normalizes a claim that may be a single string or an array of strings (e.g. `groups`)
// into a []string.
func stringSlice(v any) []string {
	switch a := v.(type) {
	case string:
		if a == "" {
			return nil
		}
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return a
	default:
		return nil
	}
}

// pkceChallenge computes the S256 PKCE challenge.
func pkceChallenge(verifier string) string {
	// Avoid pulling sha256 into observability of the surface here — but PKCE is sha256-only.
	// Implementing inline:
	h := sha256Sum([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h)
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n], nil
}
