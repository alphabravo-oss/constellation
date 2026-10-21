package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"

	"github.com/alphabravocompany/constellation/internal/identity/jwks"
)

// Benchmark the actual verifier, including its bounded memo and claim mapping.
// The HTTP counter includes failed fetches; no request in a timed loop may fetch.
func BenchmarkOIDC(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "bench", Use: "sig", Algorithm: "RS256"}}})
	}))
	defer server.Close()
	keys := jwks.New(server.URL, server.Client())
	if err := keys.Refresh(context.Background()); err != nil {
		b.Fatal(err)
	}
	cfg := OIDCConfig{IssuerURL: "https://issuer.example", ClientID: "constellation", Audience: "constellation", RolesClaim: "alphabravo_roles", RoleMapping: map[string]string{"admins": "GlobalAdmin"}}
	v := newVerifier(keys, cfg, cfg.Audience, false)
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": cfg.IssuerURL, "aud": cfg.Audience, "sub": "benchmark", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "alphabravo_roles": map[string]any{"constellation": []string{"admins"}}})
	token.Header["kid"] = "bench"
	raw, err := token.SignedString(key)
	if err != nil {
		b.Fatal(err)
	}
	for _, kind := range []string{"memoized", "first_sighting"} {
		b.Run(kind, func(b *testing.B) {
			if _, err := v.Verify(raw); err != nil {
				b.Fatal(err)
			}
			before := calls.Load()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if kind == "first_sighting" {
					v.mu.Lock()
					delete(v.memo, raw)
					v.mu.Unlock()
				}
				if _, err := v.Verify(raw); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if n := calls.Load() - before; n != 0 {
				b.Fatalf("%d network calls in request loop", n)
			}
			budget := 50 * time.Microsecond
			if kind == "first_sighting" {
				budget = 75 * time.Microsecond
			}
			if per := b.Elapsed() / time.Duration(b.N); per > budget {
				b.Fatalf("%s exceeds %s budget: %s", kind, budget, per)
			}
			b.ReportMetric(float64(calls.Load()-before), "network_calls")
		})
	}
}
