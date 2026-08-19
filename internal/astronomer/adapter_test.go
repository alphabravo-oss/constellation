package astronomer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestValidatorVerifyRSA round-trips an RS256 JWT against a JWKS server backed by an in-memory key.
func TestValidatorVerifyRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "test-1",
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "alice",
		"iss": "astronomer-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "test-1"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	v := NewValidator(srv.URL)
	claims, err := v.Verify(context.Background(), signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Fatalf("sub: got %v", claims["sub"])
	}
}

// TestValidatorRejectsBadSig confirms a key swap is detected.
func TestValidatorRejectsBadSig(t *testing.T) {
	good, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)

	// JWKS publishes "good"; token was signed with "other" — must reject.
	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "kid": "k", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(good.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(good.E)).Bytes()),
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "mallory", "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k"
	signed, _ := tok.SignedString(other)
	v := NewValidator(srv.URL)
	if _, err := v.Verify(context.Background(), signed); err == nil {
		t.Fatalf("expected verify failure with mismatched key")
	}
}

func TestValidatorEnforcesIssuerAudience(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "kid": "strict", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "alice",
		"iss": "https://astronomer.example",
		"aud": "constellation-security",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "strict"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	v := NewValidator(srv.URL,
		WithIssuer("https://astronomer.example"),
		WithAudience("constellation-security"),
	)
	if _, err := v.Verify(context.Background(), signed); err != nil {
		t.Fatalf("verify strict token: %v", err)
	}

	wrongAudience := NewValidator(srv.URL,
		WithIssuer("https://astronomer.example"),
		WithAudience("other-product"),
	)
	if _, err := wrongAudience.Verify(context.Background(), signed); err == nil {
		t.Fatalf("expected audience mismatch")
	}
}

func TestSubjectID(t *testing.T) {
	got, err := SubjectID(jwt.MapClaims{"sub": "  astro-user-1  "})
	if err != nil {
		t.Fatalf("SubjectID: %v", err)
	}
	if got != "astro-user-1" {
		t.Fatalf("SubjectID = %q", got)
	}

	got, err = SubjectID(jwt.MapClaims{"uid": "astro-user-2"})
	if err != nil {
		t.Fatalf("SubjectID fallback: %v", err)
	}
	if got != "astro-user-2" {
		t.Fatalf("SubjectID fallback = %q", got)
	}

	if _, err := SubjectID(jwt.MapClaims{"email": "a@example.com"}); err == nil {
		t.Fatalf("expected missing subject error")
	}
}
