//go:build integration

package server

import (
	"net/http"
	"strings"
	"testing"
)

// UI error states show a reference id: X-Request-ID is echoed on every response
// and exposed to the cross-origin dev UI through Access-Control-Expose-Headers.
func TestCORSExposesRequestID(t *testing.T) {
	_, ts, _, _, _, _, _ := newSysConfigTestServer(t)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/clusters", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID response header missing")
	}
	exposed := strings.ToLower(resp.Header.Get("Access-Control-Expose-Headers"))
	if !strings.Contains(exposed, "x-request-id") {
		t.Fatalf("Access-Control-Expose-Headers %q does not expose X-Request-ID", exposed)
	}
}
