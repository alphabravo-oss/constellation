package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestArtifactDialRejectsNonPublicAnswersBeforeConnecting(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "172.16.0.1", "192.168.0.1", "0.0.0.0", "0.1.2.3", "224.0.0.1", "255.255.255.255", "100.64.0.1", "198.18.0.1", "::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1"} {
		t.Run(address, func(t *testing.T) {
			d := artifactTargetDialer{
				lookup: func(context.Context, string, string) ([]net.IP, error) {
					return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP(address)}, nil
				},
				dial: func(context.Context, string, string) (net.Conn, error) {
					t.Error("mixed public/private DNS response reached the connector")
					return nil, errors.New("unexpected dial")
				},
			}
			if _, err := d.connect(t.Context(), "tcp", "artifact.example:443"); err == nil {
				t.Fatal("unsafe DNS answer accepted")
			}
		})
	}
}

func TestArtifactDialRejectsEmptyAndFailedDNS(t *testing.T) {
	for _, lookupErr := range []error{nil, errors.New("DNS failed")} {
		d := artifactTargetDialer{
			lookup: func(context.Context, string, string) ([]net.IP, error) { return nil, lookupErr },
			dial: func(context.Context, string, string) (net.Conn, error) {
				t.Error("unverified DNS response reached connector")
				return nil, errors.New("unexpected dial")
			},
		}
		if _, err := d.connect(t.Context(), "tcp", "artifact.example:443"); err == nil {
			t.Fatal("unverifiable DNS accepted")
		}
	}
}

func TestArtifactDownloadErrorsDoNotExposePresignedURL(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1/artifact.zip?X-Amz-Signature=sensitive-fixture",
		"http://invalid host/artifact.zip?X-Amz-Signature=sensitive-fixture",
	} {
		_, _, err := downloadArtifact(t.Context(), ServerlessArtifact{HTTPClient: &http.Client{Transport: &http.Transport{}}}, target)
		if err == nil || strings.Contains(err.Error(), "sensitive-fixture") || strings.Contains(err.Error(), "X-Amz-Signature") {
			t.Fatalf("download error exposed URL credentials: %v", err)
		}
	}
}

func TestArtifactRedirectErrorsDoNotExposePresignedURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://invalid host/file?X-Amz-Signature=sensitive-fixture")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	_, _, err := downloadArtifact(t.Context(), ServerlessArtifact{AllowPrivateTargets: true, HTTPClient: server.Client()}, server.URL)
	if err == nil || strings.Contains(err.Error(), "sensitive-fixture") || strings.Contains(err.Error(), "X-Amz-Signature") {
		t.Fatalf("redirect error exposed credentials: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err = downloadArtifact(ctx, ServerlessArtifact{AllowPrivateTargets: true, HTTPClient: server.Client()}, server.URL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("download lost cancellation identity: %v", err)
	}
}

// A real HTTP redirect requires a second connection. Rebinding the same name to
// metadata/loopback between connections must never reach the trusted test server.
func TestArtifactRedirectRebindingCannotReachPrivateAddress(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "/private", http.StatusFound)
	}))
	defer server.Close()
	var lookups, connects atomic.Int32
	d := artifactTargetDialer{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			if lookups.Add(1) == 1 {
				return []net.IP{net.ParseIP("8.8.8.8")}, nil
			}
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			connects.Add(1)
			if address != "8.8.8.8:80" {
				t.Errorf("connector received unchecked address %q", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	client, cleanup, err := restrictedArtifactClient(&http.Client{Transport: &http.Transport{}}, d)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://artifact.example/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "disallowed address") || hits.Load() != 1 || connects.Load() != 1 || lookups.Load() != 2 {
		t.Fatalf("rebinding escaped: err=%v hits=%d connects=%d lookups=%d", err, hits.Load(), connects.Load(), lookups.Load())
	}
}

func TestArtifactHTTPSPreservesHostnameVerificationAndNumericDial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.TLS.ServerName != "example.com" {
			t.Errorf("hostname lost: Host=%q SNI=%q", r.Host, r.TLS.ServerName)
		}
		_, _ = io.WriteString(w, "artifact")
	}))
	defer server.Close()
	d := artifactTargetDialer{
		lookup: func(context.Context, string, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil },
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "8.8.8.8:443" {
				t.Errorf("unchecked address %q", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	// httptest's certificate includes example.com. Its client trusts the test CA.
	base := server.Client()
	client, cleanup, err := restrictedArtifactClient(base, d)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/artifact", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "artifact" {
		t.Fatalf("download: %q %v", data, err)
	}
	bad, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://wrong.example/artifact", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Do(bad); err == nil {
		_ = resp.Body.Close()
		t.Fatal("mismatched server certificate accepted")
	}
}

func TestArtifactTransportDoesNotUseInjectedTLSOrProxyBypasses(t *testing.T) {
	var connects atomic.Int32
	d := artifactTargetDialer{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			connects.Add(1)
			return nil, errors.New("unexpected dial")
		},
	}
	for _, useProxy := range []bool{false, true} {
		transport := &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				t.Error("injected TLS connector bypassed checks")
				return nil, errors.New("unexpected TLS dial")
			},
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
		if useProxy {
			proxy, err := url.Parse("http://proxy.example:3128")
			if err != nil {
				t.Fatal(err)
			}
			transport.Proxy = http.ProxyURL(proxy)
		}
		base := &http.Client{Transport: transport}
		client, cleanup, err := restrictedArtifactClient(base, d)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://artifact.example/bundle", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		cleanup()
		if err == nil || connects.Load() != 0 || base.Transport != transport || transport.DialTLSContext == nil {
			t.Fatalf("transport bypass or shared mutation: %v", err)
		}
	}
}

func TestArtifactProxyPinsDestinationAndPreservesTLSIdentity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.TLS.ServerName != "example.com" {
			t.Errorf("proxy lost target identity: Host=%q SNI=%q", r.Host, r.TLS.ServerName)
		}
		_, _ = io.WriteString(w, "proxied artifact")
	}))
	defer server.Close()
	var hits atomic.Int32
	proxy := artifactConnectProxy(t, server.Listener.Addr().String(), &hits)
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	base := server.Client()
	base.Transport.(*http.Transport).Proxy = func(req *http.Request) (*url.URL, error) {
		if req.URL.Host != "example.com" {
			t.Errorf("NO_PROXY selection lost hostname: %s", req.URL.Host)
		}
		return proxyURL, nil
	}
	d := artifactTargetDialer{
		lookup: func(context.Context, string, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil },
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != proxy.Listener.Addr().String() {
				t.Errorf("configured egress proxy bypassed: %s", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	client, cleanup, err := restrictedArtifactClient(base, d)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/artifact", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "proxied artifact" || hits.Load() != 1 {
		t.Fatalf("proxied download: %q hits=%d err=%v", data, hits.Load(), err)
	}
}

func artifactConnectProxy(t *testing.T, upstreamAddress string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodConnect || r.Host != "8.8.8.8:443" {
			t.Errorf("proxy received unresolved destination: %s %s", r.Method, r.Host)
			http.Error(w, "unexpected destination", http.StatusBadRequest)
			return
		}
		upstream, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", upstreamAddress)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = upstream.Close() }()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(conn, upstream)
			_ = conn.Close()
		}()
		_, _ = io.Copy(upstream, conn)
		_ = upstream.Close()
		<-done
	}))
}
