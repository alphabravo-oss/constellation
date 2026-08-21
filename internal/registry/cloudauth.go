package registry

// Cloud-native registry authentication (REG-CLOUDAUTH-12).
//
// GCR / Artifact Registry and ACR both require a short-lived (~1h) bearer token that
// the customer would otherwise have to paste in by hand — which means a scheduled
// (non-manual) scan cadence stops working the moment that token expires. Here we mint
// those tokens from durable credentials (a GCP service-account key, or an Azure AD
// client-credentials / managed-identity), and cache them (tokencache.go) so they are
// transparently refreshed before expiry.
//
// Everything is done over net/http (no cloud SDKs): GCP uses the standard JWT-bearer
// assertion grant, Azure uses the AAD v2 token endpoint (or the IMDS endpoint for
// managed identity) followed by the ACR /oauth2 exchange dance.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// =====================================================================================
// GCP — service-account JSON key -> OAuth access token (JWT-bearer grant)
// =====================================================================================

const (
	gcpCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	gcpDefaultTokenURI    = "https://oauth2.googleapis.com/token"
	gcpJWTBearerGrant     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// serviceAccountKey is the subset of a GCP SA JSON key we need to sign a JWT.
type serviceAccountKey struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// gcpAccessToken returns a bearer token for GCR / Artifact Registry.
//
//   - If a token was supplied directly (cfg.Token), it is used as-is (back-compat with
//     the "paste a pre-acquired token" flow).
//   - Otherwise a service-account key (cfg.ServiceAccountJSON) is required and an OAuth
//     access token is minted via the JWT-bearer grant and cached until near expiry.
func (cfg Config) gcpAccessToken(ctx context.Context, client *http.Client) (string, error) {
	if strings.TrimSpace(cfg.Token) != "" {
		return cfg.Token, nil
	}
	if strings.TrimSpace(cfg.ServiceAccountJSON) == "" {
		return "", errors.New("gcp: service_account_json (or a pre-acquired token) required")
	}
	var sa serviceAccountKey
	if err := json.Unmarshal([]byte(cfg.ServiceAccountJSON), &sa); err != nil {
		return "", fmt.Errorf("gcp: parse service_account_json: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return "", errors.New("gcp: service_account_json missing client_email/private_key")
	}
	tokenURI := sa.TokenURI
	if tokenURI == "" {
		tokenURI = gcpDefaultTokenURI
	}

	key := tokenCacheKey("gcp", sa.ClientEmail, tokenURI, gcpCloudPlatformScope)
	if tok, ok := tokenCacheGet(key); ok {
		return tok, nil
	}

	assertion, err := buildGCPJWTAssertion(sa, tokenURI, gcpCloudPlatformScope, time.Now())
	if err != nil {
		return "", err
	}
	tok, exp, err := exchangeGCPAssertion(ctx, client, tokenURI, assertion)
	if err != nil {
		return "", err
	}
	tokenCachePut(key, tok, exp)
	return tok, nil
}

// buildGCPJWTAssertion builds and RS256-signs the JWT that the JWT-bearer grant
// exchanges for an access token. Split out (and pure) so it can be unit-tested
// without network access.
func buildGCPJWTAssertion(sa serviceAccountKey, tokenURI, scope string, now time.Time) (string, error) {
	priv, err := parseRSAPrivateKey(sa.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("gcp: private_key: %w", err)
	}
	header := b64url([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimsJSON, _ := json.Marshal(map[string]any{
		"iss":   sa.ClientEmail,
		"scope": scope,
		"aud":   tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	claims := b64url(claimsJSON)
	signingInput := header + "." + claims
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("gcp: sign assertion: %w", err)
	}
	return signingInput + "." + b64url(sig), nil
}

// exchangeGCPAssertion posts the signed JWT to the token endpoint and returns the
// access token with its absolute expiry.
func exchangeGCPAssertion(ctx context.Context, client *http.Client, tokenURI, assertion string) (string, time.Time, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	form := url.Values{}
	form.Set("grant_type", gcpJWTBearerGrant)
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	tok, exp, err := readOAuthToken(client, req, "gcp")
	return tok, exp, err
}

// =====================================================================================
// Azure — AAD (client-credentials or managed identity) -> ACR token
// =====================================================================================

const (
	azureAuthorityBase = "https://login.microsoftonline.com"
	azureARMScope      = "https://management.azure.com/.default"
	azureARMResource   = "https://management.azure.com/"
	azureIMDSTokenURL  = "http://169.254.169.254/metadata/identity/oauth2/token"
	// acrPullScope requests catalog + pull/metadata across all repositories, which is
	// what repository enumeration + digest resolution need.
	acrPullScope = "registry:catalog:* repository:*:pull repository:*:metadata_read"
)

// acrAccessToken returns an ACR access token for the given registry host, minting it
// from Azure AD credentials (or managed identity) and caching until near expiry.
//
// host is the bare registry hostname (e.g. "myreg.azurecr.io"). When cfg.Token is set
// it is used directly (back-compat with `az acr login --expose-token`).
func (cfg Config) acrAccessToken(ctx context.Context, client *http.Client, host string) (string, error) {
	if strings.TrimSpace(cfg.Token) != "" {
		return cfg.Token, nil
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	managed := cfg.AuthKind == "azure-managed-id"
	if !managed && (cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.TenantID == "") {
		return "", errors.New("acr: Token, or tenant_id+client_id+client_secret, or azure-managed-id auth required")
	}

	cacheKey := tokenCacheKey("acr", host, cfg.TenantID, cfg.ClientID, boolStr(managed))
	if tok, ok := tokenCacheGet(cacheKey); ok {
		return tok, nil
	}

	// 1. AAD access token.
	var (
		aadTok string
		err    error
	)
	if managed {
		aadTok, _, err = azureIMDSToken(ctx, client, azureARMResource, cfg.ClientID)
	} else {
		aadTok, _, err = azureClientCredentialsToken(ctx, client, cfg.TenantID, cfg.ClientID, cfg.ClientSecret, azureARMScope)
	}
	if err != nil {
		return "", err
	}

	// 2. Exchange the AAD token for an ACR refresh token.
	refresh, err := acrExchangeRefreshToken(ctx, client, host, cfg.TenantID, aadTok)
	if err != nil {
		return "", err
	}

	// 3. Exchange the refresh token for a scoped ACR access token.
	acrTok, exp, err := acrExchangeAccessToken(ctx, client, host, refresh, acrPullScope)
	if err != nil {
		return "", err
	}
	tokenCachePut(cacheKey, acrTok, exp)
	return acrTok, nil
}

// azureClientCredentialsRequest shapes (but does not send) the AAD v2 client-
// credentials request. Split out so tests can assert the URL and form body.
func azureClientCredentialsRequest(ctx context.Context, tenant, clientID, clientSecret, scope string) (*http.Request, error) {
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", azureAuthorityBase, url.PathEscape(tenant))
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", scope)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func azureClientCredentialsToken(ctx context.Context, client *http.Client, tenant, clientID, clientSecret, scope string) (string, time.Time, error) {
	req, err := azureClientCredentialsRequest(ctx, tenant, clientID, clientSecret, scope)
	if err != nil {
		return "", time.Time{}, err
	}
	return readOAuthToken(client, req, "aad")
}

// azureIMDSToken fetches a managed-identity token from the Azure Instance Metadata
// Service. clientID, when set, selects a specific user-assigned identity.
func azureIMDSToken(ctx context.Context, client *http.Client, resource, clientID string) (string, time.Time, error) {
	q := url.Values{}
	q.Set("api-version", "2018-02-01")
	q.Set("resource", resource)
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, azureIMDSTokenURL+"?"+q.Encode(), nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata", "true")
	return readOAuthToken(client, req, "imds")
}

// acrExchangeRefreshToken swaps an AAD access token for an ACR refresh token via the
// registry's /oauth2/exchange endpoint.
func acrExchangeRefreshToken(ctx context.Context, client *http.Client, host, tenant, aadToken string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "access_token")
	form.Set("service", host)
	if tenant != "" {
		form.Set("tenant", tenant)
	}
	form.Set("access_token", aadToken)
	endpoint := "https://" + host + "/oauth2/exchange"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	body, err := doReadBody(client, req, "acr exchange")
	if err != nil {
		return "", err
	}
	var out struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("acr: decode refresh token: %w", err)
	}
	if out.RefreshToken == "" {
		return "", errors.New("acr: exchange returned empty refresh_token")
	}
	return out.RefreshToken, nil
}

// acrExchangeAccessToken swaps an ACR refresh token for a scoped ACR access token via
// the registry's /oauth2/token endpoint.
func acrExchangeAccessToken(ctx context.Context, client *http.Client, host, refreshToken, scope string) (string, time.Time, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("service", host)
	form.Set("scope", scope)
	form.Set("refresh_token", refreshToken)
	endpoint := "https://" + host + "/oauth2/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return readOAuthToken(client, req, "acr")
}

// =====================================================================================
// shared helpers
// =====================================================================================

// oauthTokenResponse is the common OAuth token-endpoint response shape. ACR's
// /oauth2/token returns the token in access_token as well.
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	// ExpiresOn is the absolute unix expiry IMDS returns (as a string).
	ExpiresOn string `json:"expires_on"`
}

// readOAuthToken performs the request and decodes a standard OAuth token response,
// computing the absolute expiry. label prefixes error messages.
func readOAuthToken(client *http.Client, req *http.Request, label string) (string, time.Time, error) {
	body, err := doReadBody(client, req, label+" token")
	if err != nil {
		return "", time.Time{}, err
	}
	var tok oauthTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", time.Time{}, fmt.Errorf("%s: decode token: %w", label, err)
	}
	if tok.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("%s: token response missing access_token", label)
	}
	expiry := time.Now().Add(time.Hour) // conservative default when TTL is absent
	if tok.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	} else if tok.ExpiresOn != "" {
		if secs, perr := parseUnixString(tok.ExpiresOn); perr == nil {
			expiry = time.Unix(secs, 0)
		}
	}
	return tok.AccessToken, expiry, nil
}

// doReadBody sends req and returns the response body, mapping non-2xx to an error.
func doReadBody(client *http.Client, req *http.Request, what string) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: status %d: %s", what, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// parseRSAPrivateKey decodes a PEM RSA private key in PKCS#8 (GCP's default) or PKCS#1.
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not RSA")
		}
		return rk, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format (need PKCS#1 or PKCS#8 RSA)")
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func parseUnixString(s string) (int64, error) {
	s = strings.TrimSpace(s)
	var n int64
	_, err := fmt.Sscan(s, &n)
	return n, err
}
