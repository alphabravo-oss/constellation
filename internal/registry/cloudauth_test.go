package registry

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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// testSAKey builds a service-account key JSON with a freshly generated RSA key and
// returns both the JSON and the public key for signature verification.
func testSAKey(t *testing.T, email, tokenURI string) (string, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sa := map[string]string{
		"type":         "service_account",
		"client_email": email,
		"private_key":  string(keyPEM),
		"token_uri":    tokenURI,
	}
	raw, _ := json.Marshal(sa)
	return string(raw), &priv.PublicKey
}

// TestBuildGCPJWTAssertion verifies the JWT-bearer assertion structure and RS256
// signature without any network call.
func TestBuildGCPJWTAssertion(t *testing.T) {
	saJSON, pub := testSAKey(t, "svc@proj.iam.gserviceaccount.com", gcpDefaultTokenURI)
	var sa serviceAccountKey
	_ = json.Unmarshal([]byte(saJSON), &sa)

	now := time.Unix(1_700_000_000, 0)
	assertion, err := buildGCPJWTAssertion(sa, gcpDefaultTokenURI, gcpCloudPlatformScope, now)
	if err != nil {
		t.Fatalf("buildGCPJWTAssertion: %v", err)
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d parts, want 3", len(parts))
	}

	// Header.
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h map[string]string
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatalf("header decode: %v", err)
	}
	if h["alg"] != "RS256" || h["typ"] != "JWT" {
		t.Fatalf("header = %v, want RS256/JWT", h)
	}

	// Claims.
	claimsRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(claimsRaw, &claims); err != nil {
		t.Fatalf("claims decode: %v", err)
	}
	if claims["iss"] != sa.ClientEmail {
		t.Fatalf("iss = %v", claims["iss"])
	}
	if claims["aud"] != gcpDefaultTokenURI {
		t.Fatalf("aud = %v", claims["aud"])
	}
	if claims["scope"] != gcpCloudPlatformScope {
		t.Fatalf("scope = %v", claims["scope"])
	}
	if int64(claims["iat"].(float64)) != now.Unix() {
		t.Fatalf("iat = %v, want %d", claims["iat"], now.Unix())
	}
	if int64(claims["exp"].(float64)) != now.Add(time.Hour).Unix() {
		t.Fatalf("exp = %v", claims["exp"])
	}

	// Signature verifies against the SA public key.
	signingInput := parts[0] + "." + parts[1]
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature verify: %v", err)
	}
}

// TestGCPAccessToken_ExchangeAndCache exercises the JWT-bearer exchange over a mock
// token endpoint and proves the token is cached (second call issues no new request).
func TestGCPAccessToken_ExchangeAndCache(t *testing.T) {
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != gcpJWTBearerGrant {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("assertion") == "" {
			t.Errorf("missing assertion")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.mock","expires_in":3600}`))
	}))
	defer srv.Close()

	saJSON, _ := testSAKey(t, "cache-test@proj.iam.gserviceaccount.com", srv.URL+"/token")
	cfg := Config{ServiceAccountJSON: saJSON, HTTPClient: srv.Client()}

	tok, err := cfg.gcpAccessToken(context.Background(), srv.Client())
	if err != nil {
		t.Fatalf("gcpAccessToken: %v", err)
	}
	if tok != "ya29.mock" {
		t.Fatalf("token = %q", tok)
	}
	// Second call must hit the cache.
	if _, err := cfg.gcpAccessToken(context.Background(), srv.Client()); err != nil {
		t.Fatalf("second gcpAccessToken: %v", err)
	}
	if calls != 1 {
		t.Fatalf("token endpoint called %d times, want 1 (cache miss)", calls)
	}
}

// TestAzureClientCredentialsRequest asserts the AAD v2 token request shaping.
func TestAzureClientCredentialsRequest(t *testing.T) {
	req, err := azureClientCredentialsRequest(context.Background(), "tenant-123", "client-abc", "secret-xyz", azureARMScope)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	wantURL := azureAuthorityBase + "/tenant-123/oauth2/v2.0/token"
	if req.URL.String() != wantURL {
		t.Fatalf("url = %q, want %q", req.URL.String(), wantURL)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("method = %q", req.Method)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Fatalf("content-type = %q", ct)
	}
	body, _ := io.ReadAll(req.Body)
	form, _ := url.ParseQuery(string(body))
	if form.Get("grant_type") != "client_credentials" {
		t.Fatalf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("client_id") != "client-abc" || form.Get("client_secret") != "secret-xyz" {
		t.Fatalf("client creds = %q/%q", form.Get("client_id"), form.Get("client_secret"))
	}
	if form.Get("scope") != azureARMScope {
		t.Fatalf("scope = %q", form.Get("scope"))
	}
}

// TestACRExchangeDance verifies the two ACR /oauth2 exchange steps against a mock.
func TestACRExchangeDance(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/exchange":
			if r.Form.Get("grant_type") != "access_token" {
				t.Errorf("exchange grant_type = %q", r.Form.Get("grant_type"))
			}
			if r.Form.Get("access_token") != "aad-tok" {
				t.Errorf("exchange access_token = %q", r.Form.Get("access_token"))
			}
			_, _ = w.Write([]byte(`{"refresh_token":"acr-refresh"}`))
		case "/oauth2/token":
			if r.Form.Get("grant_type") != "refresh_token" {
				t.Errorf("token grant_type = %q", r.Form.Get("grant_type"))
			}
			if r.Form.Get("refresh_token") != "acr-refresh" {
				t.Errorf("token refresh_token = %q", r.Form.Get("refresh_token"))
			}
			if r.Form.Get("scope") != acrPullScope {
				t.Errorf("token scope = %q", r.Form.Get("scope"))
			}
			_, _ = w.Write([]byte(`{"access_token":"acr-access","expires_in":10800}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	rt, err := acrExchangeRefreshToken(context.Background(), srv.Client(), host, "tenant-1", "aad-tok")
	if err != nil {
		t.Fatalf("acrExchangeRefreshToken: %v", err)
	}
	if rt != "acr-refresh" {
		t.Fatalf("refresh token = %q", rt)
	}
	at, exp, err := acrExchangeAccessToken(context.Background(), srv.Client(), host, rt, acrPullScope)
	if err != nil {
		t.Fatalf("acrExchangeAccessToken: %v", err)
	}
	if at != "acr-access" {
		t.Fatalf("access token = %q", at)
	}
	if time.Until(exp) < time.Hour {
		t.Fatalf("expiry too soon: %v", exp)
	}
}
