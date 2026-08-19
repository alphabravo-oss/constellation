package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rsaJWK turns a real *rsa.PublicKey into a JWK map.
func rsaJWK(t *testing.T, kid string, k *rsa.PublicKey) map[string]any {
	t.Helper()
	nBytes := k.N.Bytes()
	eBytes := big.NewInt(int64(k.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func ecJWK(t *testing.T, kid string, k *ecdsa.PublicKey) map[string]any {
	t.Helper()
	return map[string]any{
		"kty": "EC",
		"kid": kid,
		"alg": "ES256",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
	}
}

func TestParseKey_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := rsaJWK(t, "k1", &priv.PublicKey)
	k, kid, err := ParseKey(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if kid != "k1" {
		t.Fatalf("kid: %q", kid)
	}
	got, ok := k.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("type: %T", k)
	}
	if got.N.Cmp(priv.PublicKey.N) != 0 || got.E != priv.PublicKey.E {
		t.Fatalf("key round-trip mismatch")
	}
}

func TestParseKey_EC(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := ecJWK(t, "ec1", &priv.PublicKey)
	k, kid, err := ParseKey(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if kid != "ec1" {
		t.Fatalf("kid: %q", kid)
	}
	got, ok := k.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("type: %T", k)
	}
	if got.X.Cmp(priv.PublicKey.X) != 0 || got.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatalf("ec key round-trip mismatch")
	}
}

func TestParseKey_Errors(t *testing.T) {
	if _, _, err := ParseKey(map[string]any{"kty": "oct"}); err == nil {
		t.Fatalf("expected error for unsupported kty")
	}
	if _, _, err := ParseKey(map[string]any{"kty": "RSA"}); err == nil {
		t.Fatalf("expected error for missing n/e")
	}
}

func TestClient_FetchesAndCaches(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{rsaJWK(t, "k1", &priv.PublicKey)},
		})
	}))
	defer srv.Close()

	c := New(srv.URL)
	ctx := context.Background()

	k, err := c.Key(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := k.(*rsa.PublicKey); !ok {
		t.Fatalf("type %T", k)
	}
	if hits != 1 {
		t.Fatalf("first call hits = %d", hits)
	}

	if _, err := c.Key(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("second call must be cached, hits = %d", hits)
	}

	if _, err := c.Key(ctx, "unknown"); err == nil {
		t.Fatalf("expected unknown kid error")
	}
	if hits != 2 {
		t.Fatalf("missing-kid forces refresh, hits = %d", hits)
	}
}
