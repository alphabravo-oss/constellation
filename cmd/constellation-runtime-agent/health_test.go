package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
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
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Don't actually bind a port; just exercise the handler through a mux.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeHealthJSON(w, http.StatusOK, map[string]any{"status": "alive"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(request)
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
}

type readinessSupervisorFixture struct {
	ready     bool
	life      dp.LifecycleStats
	keepalive dp.ClientStats
	taps      dp.TapStats
}

func (s *readinessSupervisorFixture) Ready() bool { return s.ready }

func (s *readinessSupervisorFixture) Stats() (dp.LifecycleStats, dp.Stats, dp.ClientStats, dp.TapStats) {
	return s.life, dp.Stats{}, s.keepalive, s.taps
}

func assertDPReadinessResponse(t *testing.T, response *httptest.ResponseRecorder, source *readinessSupervisorFixture, code int, status, reason string) {
	t.Helper()
	if response.Code != code {
		t.Fatalf("HTTP status=%d want %d; body=%s", response.Code, code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	var got map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid readiness JSON: %v", err)
	}
	want := map[string]any{
		"status":          status,
		"dp_starts":       float64(source.life.StartCount),
		"dp_crashes":      float64(source.life.CrashCount),
		"dp_ka_replied":   float64(source.keepalive.Replied),
		"dp_ka_errors":    float64(source.keepalive.Errors),
		"dp_taps_added":   float64(source.taps.Added),
		"dp_taps_errors":  float64(source.taps.Errors),
		"dp_taps_current": float64(source.taps.CurrentTaps),
	}
	if reason != "" {
		want["reason"] = reason
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("readiness body=%v want %v", got, want)
	}
}

func TestReadinessUnstartedSupervisor(t *testing.T) {
	response := httptest.NewRecorder()
	writeReadyJSON(response, &dp.Supervisor{})
	assertDPReadinessResponse(t, response, &readinessSupervisorFixture{}, http.StatusServiceUnavailable, "starting", "dp not yet started")
}

func TestReadinessCurrentGenerationResponses(t *testing.T) {
	for _, test := range []struct {
		name   string
		source readinessSupervisorFixture
		code   int
		status string
		reason string
	}{
		{
			name:   "fresh-supervisor",
			code:   http.StatusServiceUnavailable,
			status: "starting",
			reason: "dp not yet started",
		},
		{
			name:   "started-without-current-reply",
			source: readinessSupervisorFixture{life: dp.LifecycleStats{StartCount: 1}},
			code:   http.StatusServiceUnavailable,
			status: "starting",
			reason: "current dp generation is not ready",
		},
		{
			name: "current-generation-ready",
			source: readinessSupervisorFixture{
				ready:     true,
				life:      dp.LifecycleStats{StartCount: 3, CrashCount: 2},
				keepalive: dp.ClientStats{Replied: 17, Errors: 4},
				taps:      dp.TapStats{Added: 6, Errors: 1, CurrentTaps: 2},
			},
			code:   http.StatusOK,
			status: "ready",
		},
		{
			// Stats and Ready are separate snapshots. A fresh reply may arrive
			// after the diagnostic counters were read; Ready remains authoritative.
			name:   "current-ready-with-earlier-diagnostic-snapshot",
			source: readinessSupervisorFixture{ready: true, life: dp.LifecycleStats{StartCount: 1}},
			code:   http.StatusOK,
			status: "ready",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeDPReadyJSON(response, &test.source)
			assertDPReadinessResponse(t, response, &test.source, test.code, test.status, test.reason)
		})
	}
}

func TestReadinessRejectsHistoricalReplies(t *testing.T) {
	for _, test := range []struct {
		name string
		life dp.LifecycleStats
	}{
		{name: "process-exited", life: dp.LifecycleStats{StartCount: 1, ExitCount: 1, CrashCount: 1}},
		{name: "replacement-awaiting-first-reply", life: dp.LifecycleStats{StartCount: 2, ExitCount: 1, CrashCount: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &readinessSupervisorFixture{
				life:      test.life,
				keepalive: dp.ClientStats{Replied: 11, Errors: 2},
				taps:      dp.TapStats{Added: 5, CurrentTaps: 3},
			}
			response := httptest.NewRecorder()
			writeDPReadyJSON(response, source)
			assertDPReadinessResponse(t, response, source, http.StatusServiceUnavailable, "starting", "current dp generation is not ready")
		})
	}
}

func TestReadinessTracksCurrentGeneration(t *testing.T) {
	source := &readinessSupervisorFixture{
		ready:     true,
		life:      dp.LifecycleStats{StartCount: 1},
		keepalive: dp.ClientStats{Replied: 7},
	}
	check := func(code int, status, reason string) {
		t.Helper()
		response := httptest.NewRecorder()
		writeDPReadyJSON(response, source)
		assertDPReadinessResponse(t, response, source, code, status, reason)
	}
	check(http.StatusOK, "ready", "")
	source.ready = false
	source.life.ExitCount++
	check(http.StatusServiceUnavailable, "starting", "current dp generation is not ready")
	source.life.StartCount++
	check(http.StatusServiceUnavailable, "starting", "current dp generation is not ready")
	source.ready = true
	source.keepalive.Replied++
	check(http.StatusOK, "ready", "")
	source.ready = false
	source.life.ExitCount++
	check(http.StatusServiceUnavailable, "starting", "current dp generation is not ready")
}
