package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIdPNonce is the fixed nonce fakeIdP stamps into its id_token, so Exchange (which now requires
// a non-empty expected nonce) can be exercised with a matching value.
const fakeIdPNonce = "fakeidp-nonce"

// fakeIdP stands up a tiny OIDC provider for tests:
//   - /.well-known/openid-configuration
//   - /jwks
//   - /token (returns an RS256-signed id_token)
func fakeIdP(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	var base string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		nBytes := priv.PublicKey.N.Bytes()
		eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := jwt.MapClaims{
			"iss":            base,
			"sub":            "user-42",
			"email":          "alice@example.test",
			"email_verified": true,
			"name":           "Alice Example",
			"iat":            time.Now().Unix(),
			"exp":            time.Now().Add(5 * time.Minute).Unix(),
			"aud":            "client-test",
			"nonce":          fakeIdPNonce,
			"groups":         []any{"platform-admins", "viewers"},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "test"
		signed, err := tok.SignedString(priv)
		if err != nil {
			t.Errorf("sign: %v", err)
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":     signed,
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	})

	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv, priv
}

func TestOIDC_Exchange_VerifiesSignature(t *testing.T) {
	srv, _ := fakeIdP(t)
	defer srv.Close()

	ctx := context.Background()
	c, err := NewOIDCClient(ctx, OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "client-test",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost:8080/api/v1/auth/oidc/callback",
	})
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}

	claims, accessToken, err := c.Exchange(ctx, "code-doesnt-matter", "verifier-doesnt-matter", fakeIdPNonce)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.Email != "alice@example.test" {
		t.Fatalf("email: %q", claims.Email)
	}
	if claims.Subject != "user-42" {
		t.Fatalf("sub: %q", claims.Subject)
	}
	if accessToken != "test-access-token" {
		t.Fatalf("access_token: %q", accessToken)
	}
	// Groups are extracted so the OIDC JIT path can map them to roles (parity with SAML/LDAP).
	if len(claims.Groups) != 2 || claims.Groups[0] != "platform-admins" {
		t.Fatalf("groups = %v, want [platform-admins viewers]", claims.Groups)
	}
}

// TestOIDC_RejectsWrongAudience proves an id_token minted for a SIBLING app (different aud) on the
// same issuer/JWKS is rejected — the H2 aud-validation fix (OIDC core §3.1.3.7).
func TestOIDC_RejectsWrongAudience(t *testing.T) {
	srv, _ := fakeIdP(t)
	defer srv.Close()
	ctx := context.Background()
	c, err := NewOIDCClient(ctx, OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "some-other-client", // token's aud is "client-test" -> must be rejected
		ClientSecret: "secret",
		RedirectURL:  "http://localhost:8080/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	if _, _, err := c.Exchange(ctx, "code", "verifier", fakeIdPNonce); err == nil {
		t.Fatalf("expected wrong-audience rejection, got nil error")
	}
}

// TestOIDC_RejectsBadSignature mounts an IdP that returns an id_token signed with a different
// key than the JWKS publishes. Verification must fail.
func TestOIDC_RejectsBadSignature(t *testing.T) {
	// Build the "good" IdP, then swap the token signer with a different key.
	badPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		// JWKS advertises the *good* public key.
		nBytes := priv.PublicKey.N.Bytes()
		eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "good", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(nBytes),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Sign with the *bad* key, but claim it's "good".
		claims := jwt.MapClaims{
			"iss": base, "sub": "user-evil", "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "good"
		signed, _ := tok.SignedString(badPriv)
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": signed, "access_token": "x"})
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	defer srv.Close()

	ctx := context.Background()
	c, err := NewOIDCClient(ctx, OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "client-test",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost:8080/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	_, _, err = c.Exchange(ctx, "x", "y", "")
	if err == nil {
		t.Fatalf("expected signature verification failure")
	}
}

// nonceIdP stands up an IdP whose /token stamps a fixed `nonce` claim into the id_token,
// letting us exercise nonce binding/validation in Exchange.
func nonceIdP(t *testing.T, tokenNonce string) *httptest.Server {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		nBytes := priv.PublicKey.N.Bytes()
		eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "test", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(nBytes),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := jwt.MapClaims{
			"iss":   base,
			"sub":   "user-42",
			"email": "alice@example.test",
			"nonce": tokenNonce,
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"aud":   "client-test",
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "test"
		signed, err := tok.SignedString(priv)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": signed, "access_token": "tok"})
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv
}

// TestOIDC_StartURL_IncludesNonce asserts StartURL mints a nonce and carries it in the
// authorize redirect (so the IdP can echo it back into the id_token).
func TestOIDC_StartURL_IncludesNonce(t *testing.T) {
	srv, _ := fakeIdP(t)
	defer srv.Close()
	c, err := NewOIDCClient(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-test", ClientSecret: "secret",
		RedirectURL: "http://localhost:8080/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	authURL, state, verifier, nonce, err := c.StartURL()
	if err != nil {
		t.Fatalf("StartURL: %v", err)
	}
	if state == "" || verifier == "" || nonce == "" {
		t.Fatalf("empty state/verifier/nonce: %q/%q/%q", state, verifier, nonce)
	}
	u, err := neturl.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authURL: %v", err)
	}
	if got := u.Query().Get("nonce"); got != nonce {
		t.Fatalf("authorize url nonce = %q, want %q", got, nonce)
	}
}

// TestOIDC_Exchange_ValidatesNonce covers the three nonce paths: a matching nonce passes,
// a mismatched expected nonce is rejected, and an empty expected nonce skips the check.
func TestOIDC_Exchange_ValidatesNonce(t *testing.T) {
	const tokenNonce = "the-expected-nonce"
	srv := nonceIdP(t, tokenNonce)
	defer srv.Close()
	ctx := context.Background()
	c, err := NewOIDCClient(ctx, OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-test", ClientSecret: "secret",
		RedirectURL: "http://localhost:8080/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}

	// Matching nonce: accepted, and surfaced on the claims.
	claims, _, err := c.Exchange(ctx, "code", "verifier", tokenNonce)
	if err != nil {
		t.Fatalf("Exchange with matching nonce: %v", err)
	}
	if claims.Nonce != tokenNonce {
		t.Fatalf("claims.Nonce = %q, want %q", claims.Nonce, tokenNonce)
	}

	// Wrong expected nonce: rejected (replay/injection defense).
	if _, _, err := c.Exchange(ctx, "code", "verifier", "attacker-supplied-nonce"); err == nil {
		t.Fatalf("expected nonce-mismatch failure")
	}

	// Empty expected nonce: now REJECTED (the back-compat bypass was removed; a nonce is mandatory).
	if _, _, err := c.Exchange(ctx, "code", "verifier", ""); err == nil {
		t.Fatalf("Exchange with empty expected nonce must be rejected (mandatory nonce binding)")
	}
}
