//go:build integration

package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/httprate"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestTrustedForwardedClientChain(t *testing.T) {
	t.Setenv("CONSTELLATION_TRUSTED_PROXIES", "127.0.0.1/32,10.0.0.0/24,2001:db8:1::/64")
	for _, tc := range []struct {
		name   string
		peer   string
		values []string
		want   string
	}{
		{"single", "127.0.0.1:1234", []string{"198.51.100.7"}, "198.51.100.7"},
		{"appended spoof", "127.0.0.1:1234", []string{"192.0.2.99, 198.51.100.7"}, "198.51.100.7"},
		{"trusted suffix", "127.0.0.1:1234", []string{"192.0.2.99, 198.51.100.7, 10.0.0.2"}, "198.51.100.7"},
		{"duplicate fields", "127.0.0.1:1234", []string{"192.0.2.99", "198.51.100.7, 10.0.0.2"}, "198.51.100.7"},
		{"untrusted middle", "127.0.0.1:1234", []string{"198.51.100.7, 203.0.113.8, 10.0.0.2"}, "203.0.113.8"},
		{"invalid untrusted prefix", "127.0.0.1:1234", []string{"garbage, 198.51.100.7"}, "198.51.100.7"},
		{"invalid trusted suffix", "127.0.0.1:1234", []string{"198.51.100.7, garbage"}, "127.0.0.1:1234"},
		{"empty hop", "127.0.0.1:1234", []string{"198.51.100.7,,10.0.0.2"}, "127.0.0.1:1234"},
		{"missing", "127.0.0.1:1234", nil, "127.0.0.1:1234"},
		{"empty", "127.0.0.1:1234", []string{""}, "127.0.0.1:1234"},
		{"port rejected", "127.0.0.1:1234", []string{"198.51.100.7:80"}, "127.0.0.1:1234"},
		{"ipv6", "[2001:db8:1::2]:1234", []string{"2001:db8:2::3, 2001:db8:1::4"}, "2001:db8:2::3"},
		{"mapped ipv4", "[::ffff:127.0.0.1]:1234", []string{"::ffff:198.51.100.7"}, "198.51.100.7"},
		{"zone rejected", "127.0.0.1:1234", []string{"fe80::1%eth0"}, "127.0.0.1:1234"},
		{"all trusted", "127.0.0.1:1234", []string{"10.0.0.3, 10.0.0.2"}, "10.0.0.3"},
		{"untrusted peer", "203.0.113.2:1234", []string{"198.51.100.7"}, "203.0.113.2:1234"},
		{"invalid peer", "not-an-ip", []string{"198.51.100.7"}, "not-an-ip"},
		{"too many hops", "127.0.0.1:1234", []string{strings.Repeat("10.0.0.2,", maxForwardedIPHops) + "198.51.100.7"}, "127.0.0.1:1234"},
		{"too many bytes", "127.0.0.1:1234", []string{strings.Repeat(" ", maxForwardedIPBytes) + "198.51.100.7"}, "127.0.0.1:1234"},
		{"exact hop limit", "127.0.0.1:1234", []string{"198.51.100.7" + strings.Repeat(",10.0.0.2", maxForwardedIPHops-1)}, "198.51.100.7"},
		{"exact byte limit", "127.0.0.1:1234", []string{strings.Repeat(" ", maxForwardedIPBytes-len("198.51.100.7")) + "198.51.100.7"}, "198.51.100.7"},
		{"empty last field", "127.0.0.1:1234", []string{"198.51.100.7", ""}, "127.0.0.1:1234"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			r.RemoteAddr = tc.peer
			for _, value := range tc.values {
				r.Header.Add("X-Forwarded-For", value)
			}
			r.Header.Set("True-Client-IP", "192.0.2.222")
			r.Header.Set("X-Real-IP", "192.0.2.223")
			var server Server
			server.trustedProxyRealIP()(http.HandlerFunc(func(_ http.ResponseWriter, got *http.Request) {
				if got.RemoteAddr != tc.want {
					t.Errorf("client = %q, want %q", got.RemoteAddr, tc.want)
				}
				if authctx.TrustedProxyFrom(got.Context()) != ipInNets(remoteHostIP(tc.peer), parseTrustedProxies("127.0.0.1/32,10.0.0.0/24,2001:db8:1::/64")) {
					t.Error("transport trust changed during client resolution")
				}
			})).ServeHTTP(httptest.NewRecorder(), r)
			if r.RemoteAddr != tc.peer {
				t.Error("middleware mutated caller request")
			}
		})
	}
}

func TestInvalidProxyConfigurationIgnoresForwarding(t *testing.T) {
	t.Setenv("CONSTELLATION_TRUSTED_PROXIES", "invalid")
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	var server Server
	server.trustedProxyRealIP()(http.HandlerFunc(func(_ http.ResponseWriter, got *http.Request) {
		if got.RemoteAddr != r.RemoteAddr || authctx.TrustedProxyFrom(got.Context()) {
			t.Fatal("invalid trust configuration honored forwarding")
		}
	})).ServeHTTP(httptest.NewRecorder(), r)
}

func TestForwardedSpoofCannotRotateAuthRateBucket(t *testing.T) {
	t.Setenv("CONSTELLATION_TRUSTED_PROXIES", "127.0.0.1/32")
	for _, header := range []string{"True-Client-IP", "X-Real-IP", "X-Forwarded-For"} {
		t.Run(header, func(t *testing.T) {
			var server Server
			h := server.trustedProxyRealIP()(httprate.Limit(authIPRateLimit, time.Minute,
				httprate.WithKeyFuncs(httprate.KeyByIP), httprate.WithLimitHandler(rateLimited),
			)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
			for i := 0; i <= authIPRateLimit; i++ {
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/auth/login", nil)
				r.RemoteAddr = "127.0.0.1:1234"
				r.Header.Set("X-Forwarded-For", "198.51.100.7")
				spoof := fmt.Sprintf("192.0.2.%d", i+1)
				if header == "X-Forwarded-For" {
					spoof += ", 198.51.100.7"
				}
				r.Header.Set(header, spoof)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := http.StatusNoContent
				if i == authIPRateLimit {
					want = http.StatusTooManyRequests
				}
				if w.Code != want {
					t.Fatalf("request %d: status %d, want %d", i+1, w.Code, want)
				}
			}
		})
	}
}

func TestAuthLoginRateLimitRejectsForwardedSpoof(t *testing.T) {
	t.Setenv("CONSTELLATION_TRUSTED_PROXIES", "127.0.0.1/32")
	ts, _, _, _, _ := newAuthTestServer(t)
	for i := 0; i <= authIPRateLimit; i++ {
		body := bytes.NewBufferString(`{"email":"forwarded-spoof@example.test","password":"invalid"}`)
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+"/api/v1/auth/break-glass", body)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", ts.URL)
		r.Header.Set("X-Constellation-Client", "browser")
		spoof := fmt.Sprintf("192.0.2.%d", i+1)
		r.Header.Set("True-Client-IP", spoof)
		r.Header.Set("X-Real-IP", spoof)
		r.Header.Set("X-Forwarded-For", spoof+", 198.51.100.7")
		response, err := ts.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		want := http.StatusNotFound
		if i == authIPRateLimit {
			want = http.StatusTooManyRequests
		}
		if response.StatusCode != want {
			t.Fatalf("login %d: status %d, want %d", i+1, response.StatusCode, want)
		}
	}
}
