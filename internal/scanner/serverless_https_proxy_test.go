package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type artifactProxyTestCase struct {
	name, proxyHost, targetHost, targetScheme string
	proxyTLS, success                         bool
	proxyRequests                             int32
}

// Proxy and origin TLS identities differ; CONNECT must use the checked address.
func TestArtifactProxyPreservesDestinationAndTLSIdentities(t *testing.T) {
	for _, tc := range []artifactProxyTestCase{
		{"distinct trusted hosts", "proxy.example.com", "example.com", "https", true, true, 1},
		{"wrong proxy certificate hostname", "proxy.invalid", "example.com", "https", true, false, 0},
		{"wrong origin certificate hostname", "proxy.example.com", "origin.invalid", "https", true, false, 1},
		{"HTTP origin through HTTPS proxy", "proxy.example.com", "example.com", "http", true, true, 1},
		{"HTTP origin through HTTP proxy", "proxy.example.com", "example.com", "http", false, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) { runArtifactProxyCase(t, tc) })
	}
}

func artifactTestOrigin(t *testing.T, tc artifactProxyTestCase, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials forwarded to artifact origin")
		}
		if r.Host != tc.targetHost {
			t.Errorf("origin Host=%q", r.Host)
		}
		if tc.targetScheme == "https" && (r.TLS == nil || r.TLS.ServerName != tc.targetHost) {
			t.Errorf("origin TLS identity=%+v", r.TLS)
		}
		_, _ = io.WriteString(w, "proxied artifact")
	})
	if tc.targetScheme == "https" {
		return httptest.NewTLSServer(handler)
	}
	return httptest.NewServer(handler)
}

func artifactTestProxy(t *testing.T, tc artifactProxyTestCase, upstreamAddress string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("artifact:fixture-pass"))
	port := "443"
	if tc.targetScheme == "http" {
		port = "80"
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Proxy-Authorization") != expectedAuth {
			t.Error("configured proxy authentication omitted")
		}
		if r.Method != http.MethodConnect || r.Host != "8.8.8.8:"+port || (tc.proxyTLS && (r.TLS == nil || r.TLS.ServerName != tc.proxyHost)) {
			t.Errorf("proxy identity method=%s authority=%q TLS=%+v", r.Method, r.Host, r.TLS)
			http.Error(w, "wrong proxy request", http.StatusBadRequest)
			return
		}
		serveArtifactTestTunnel(t, w, r, upstreamAddress)
	})
	if tc.proxyTLS {
		return httptest.NewTLSServer(handler)
	}
	return httptest.NewServer(handler)
}

func serveArtifactTestTunnel(t *testing.T, w http.ResponseWriter, r *http.Request, upstreamAddress string) {
	t.Helper()
	upstream, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", upstreamAddress)
	if err != nil {
		t.Error(err)
		http.Error(w, "upstream failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()
	tunnel, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = tunnel.Close() }()
	if _, err := fmt.Fprint(tunnel, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		t.Error(err)
		return
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(tunnel, upstream); _ = tunnel.Close() }()
	_, _ = io.Copy(upstream, tunnel)
	_ = upstream.Close()
	<-done
}

func artifactTestProxyClient(t *testing.T, tc artifactProxyTestCase, proxy *httptest.Server, dials *atomic.Int32) *http.Client {
	t.Helper()
	proxyURL, _ := url.Parse(proxy.URL)
	_, port, _ := net.SplitHostPort(proxyURL.Host)
	proxyURL.Host = net.JoinHostPort(tc.proxyHost, port)
	proxyURL.User = url.UserPassword("artifact", "fixture-pass")
	base := proxy.Client()
	base.Timeout = 5 * time.Second
	settings := base.Transport.(*http.Transport)
	if settings.TLSClientConfig != nil && settings.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("test must verify TLS certificates")
	}
	settings.Proxy = http.ProxyURL(proxyURL)
	dialer := artifactTargetDialer{
		lookup: func(_ context.Context, _, host string) ([]net.IP, error) {
			if host != tc.targetHost {
				t.Errorf("unexpected lookup %q", host)
			}
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			if address != proxyURL.Host {
				t.Errorf("configured HTTPS proxy bypassed: %q", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, proxy.Listener.Addr().String())
		},
	}
	client, cleanup, err := restrictedArtifactClient(base, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return client
}

func runArtifactProxyCase(t *testing.T, tc artifactProxyTestCase) {
	t.Helper()
	var proxyHits, originHits, dials atomic.Int32
	origin := artifactTestOrigin(t, tc, &originHits)
	t.Cleanup(origin.Close)
	proxy := artifactTestProxy(t, tc, origin.Listener.Addr().String(), &proxyHits)
	t.Cleanup(proxy.Close)
	client := artifactTestProxyClient(t, tc, proxy, &dials)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tc.targetScheme+"://"+tc.targetHost+"/artifact.zip", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	assertArtifactProxyResponse(t, tc, response, err, originHits.Load())
	if proxyHits.Load() != tc.proxyRequests || dials.Load() != 1 {
		t.Fatalf("proxy requests=%d want=%d dials=%d", proxyHits.Load(), tc.proxyRequests, dials.Load())
	}
}

func assertArtifactProxyResponse(t *testing.T, tc artifactProxyTestCase, response *http.Response, requestErr error, originHits int32) {
	t.Helper()
	if !tc.success {
		if requestErr == nil || !strings.Contains(requestErr.Error(), "certificate") {
			t.Fatalf("untrusted TLS identity accepted: %v", requestErr)
		}
		if originHits != 0 {
			t.Fatalf("untrusted TLS origin received %d requests", originHits)
		}
		return
	}
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "proxied artifact" {
		t.Fatalf("response=%q error=%v", body, err)
	}
	if originHits != 1 {
		t.Fatalf("origin requests=%d", originHits)
	}
}
