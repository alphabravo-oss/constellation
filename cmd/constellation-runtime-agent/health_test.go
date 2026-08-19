package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestReadinessNoDP — when CONSTELLATION_DP_ENABLED isn't set, the supervisor
// is nil and the agent is "ready" as soon as it starts; readyz should answer
// 200 with status=ready, dp=disabled.
func TestReadinessNoDP(t *testing.T) {
	w := httptest.NewRecorder()
	writeReadyJSON(w, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	if got["status"] != "ready" || got["dp"] != "disabled" {
		t.Errorf("body=%v", got)
	}
}

// TestHealthzAlwaysAlive — /healthz returns 200 unconditionally; that's the
// whole point of the liveness path (any non-200 makes kubelet kill the pod).
func TestHealthzAlwaysAlive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Don't actually bind a port; just exercise the handler through a mux.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeHealthJSON(w, http.StatusOK, map[string]any{"status": "alive"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"alive"`) {
		t.Errorf("unexpected body: %s", body)
	}
	_ = ctx
}
