package handler

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestFederationTransportProofRequiresTrustedPeer(t *testing.T) {
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(certServer.Close)
	leaf := certServer.Certificate()
	header := "X-Federation-Client-Cert"
	for _, trusted := range []bool{false, true} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://controller/api/v1/federation/join", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set(header, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})))
		if trusted {
			req = req.WithContext(authctx.WithTrustedProxy(req.Context(), true))
		}
		if fedJoinOverTLS(req) != trusted {
			t.Errorf("forwarded TLS proof trusted=%v", trusted)
		}
		if (fedClientCert(req, header) != nil) != trusted {
			t.Errorf("forwarded client certificate trusted=%v", trusted)
		}
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://controller/api/v1/federation/join", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if !fedJoinOverTLS(req) || fedClientCert(req, "") != leaf {
		t.Fatal("direct TLS proof rejected")
	}
}

func TestPerformRemoteJoinRejectsUnsafeEndpointsBeforeIO(t *testing.T) {
	for _, endpoint := range []string{"http://master.example", "https://user:password@master.example", "https://master.example/?token=secret", "https://master.example/#fragment", "/relative"} {
		if _, err := performRemoteJoin(t.Context(), nil, nil, nil, uuid.New(), endpoint, "join-token", "cluster", "cluster"); err == nil {
			t.Errorf("unsafe endpoint accepted: %s", endpoint)
		}
	}
}

func TestPerformRemoteJoinNeverRedirectsToken(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		var escaped atomic.Int32
		destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			escaped.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(destination.Close)
		master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", destination.URL)
			w.WriteHeader(code)
		}))
		t.Cleanup(master.Close)
		client := master.Client()
		_, err := performRemoteJoin(t.Context(), nil, nil, client, uuid.New(), master.URL, "join-token", "cluster", "cluster")
		if err == nil || !strings.Contains(err.Error(), "status") || escaped.Load() != 0 {
			t.Fatalf("redirect escaped=%d err=%v", escaped.Load(), err)
		}
		if client.CheckRedirect != nil {
			t.Fatal("join mutated shared client")
		}
	}
}
