package notify

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestIsBlockedIP covers the destination classifier used by both the create/patch-time
// guard and the dial-time Control hook.
func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"169.254.169.254", "169.254.0.1", // link-local incl. cloud metadata
		"fe80::1",                               // IPv6 link-local
		"10.0.0.5", "172.16.0.1", "192.168.1.1", // RFC1918
		"fc00::1", "fd00:ec2::254", // ULA (incl. IPv6 metadata)
		"100.64.0.1", "100.127.255.254", // CGNAT
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", // multicast
	}
	for _, s := range blocked {
		if ip := net.ParseIP(s); !isBlockedIP(ip) {
			t.Errorf("expected %s to be blocked", s)
		}
	}
	allowed := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946",
		"100.63.255.255", "100.128.0.1", // just outside CGNAT 100.64/10
	}
	for _, s := range allowed {
		if ip := net.ParseIP(s); isBlockedIP(ip) {
			t.Errorf("expected %s to be allowed", s)
		}
	}
	if !isBlockedIP(nil) {
		t.Error("nil IP must be blocked")
	}
}

// TestPublicURLAllowed covers the create/patch-time endpoint validation.
func TestPublicURLAllowed(t *testing.T) {
	bad := map[string]string{
		"http (not https)": "http://example.com/hook",
		"ftp scheme":       "ftp://example.com",
		"loopback literal": "https://127.0.0.1/x",
		"private literal":  "https://10.0.0.1/x",
		"metadata literal": "https://169.254.169.254/latest/meta-data/iam/",
		"ipv6 loopback":    "https://[::1]:8443/x",
		"localhost host":   "https://localhost/x",
		"no host":          "https:///x",
		"garbage":          "://::::",
	}
	for name, u := range bad {
		if err := PublicURLAllowed(u); err == nil {
			t.Errorf("%s: expected rejection for %q", name, u)
		}
	}
	// A public IP literal over https must pass without a DNS lookup.
	if err := PublicURLAllowed("https://8.8.8.8/hook"); err != nil {
		t.Errorf("public IP literal should pass: %v", err)
	}
}

// TestGuardedClientBlocksLoopbackDial verifies the guard fires at DIAL time (the rebind
// backstop), not merely at create time: even handed a live loopback server URL, the
// production default client refuses to connect.
func TestGuardedClientBlocksLoopbackDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := newGuardedHTTPClient(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("guarded client should have blocked the loopback dial")
	}
	if !strings.Contains(err.Error(), "blocked dial to non-public") {
		t.Fatalf("unexpected error (want blocked-dial): %v", err)
	}
}
