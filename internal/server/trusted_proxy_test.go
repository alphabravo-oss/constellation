package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestTrustedProxyDecisionPrecedesRealIPRewrite(t *testing.T) {
	t.Setenv("CONSTELLATION_TRUSTED_PROXIES", "127.0.0.1/32")
	for _, tc := range []struct {
		peer    string
		trusted bool
	}{
		{"127.0.0.1:1234", true}, {"203.0.113.2:1234", false}, {"10.1.2.3:1234", false},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.RemoteAddr = tc.peer
		req.Header.Set("X-Forwarded-For", "198.51.100.20")
		// Even a preexisting context value must be replaced by the socket decision.
		req = req.WithContext(authctx.WithTrustedProxy(req.Context(), true))
		var server Server
		server.trustedProxyRealIP()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := authctx.TrustedProxyFrom(r.Context()); got != tc.trusted {
				t.Errorf("peer=%s trusted=%v want=%v", tc.peer, got, tc.trusted)
			}
			wantIP := tc.peer
			if tc.trusted {
				wantIP = "198.51.100.20"
			}
			if r.RemoteAddr != wantIP {
				t.Errorf("peer=%s rewritten=%s want=%s", tc.peer, r.RemoteAddr, wantIP)
			}
		})).ServeHTTP(httptest.NewRecorder(), req)
	}
}

func TestDefaultPrivateNetworkDoesNotAttestFederationTLS(t *testing.T) {
	t.Setenv("CONSTELLATION_TRUSTED_PROXIES", "")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/federation/join", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	var server Server
	server.trustedProxyRealIP()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authctx.TrustedProxyFrom(r.Context()) {
			t.Fatal("compatibility private ranges attested federation TLS")
		}
	})).ServeHTTP(httptest.NewRecorder(), req)
}
