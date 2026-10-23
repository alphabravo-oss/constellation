package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const onlineScannerConfig = `{"db_refresh_minutes":15,"offline_db":false,"refresh_now":0}`

func TestFetchScannerConfigValidation(t *testing.T) {
	cases := []struct {
		name, body string
		valid      bool
	}{
		{"online", onlineScannerConfig, true},
		{"offline", `{"db_refresh_minutes":0,"offline_db":true,"refresh_now":123}`, true},
		{"maximum interval", `{"db_refresh_minutes":43200,"offline_db":false,"refresh_now":0}`, true},
		{"future field", strings.TrimSuffix(onlineScannerConfig, "}") + `,"future":true}`, true},
		{"empty", "", false},
		{"malformed", "{", false},
		{"null", "null", false},
		{"missing fields", "{}", false},
		{"missing offline", `{"db_refresh_minutes":15,"refresh_now":0}`, false},
		{"missing interval", `{"offline_db":false,"refresh_now":0}`, false},
		{"missing signal", `{"db_refresh_minutes":15,"offline_db":false}`, false},
		{"null offline", strings.ReplaceAll(onlineScannerConfig, "false", "null"), false},
		{"wrong type", strings.ReplaceAll(onlineScannerConfig, "false", `"false"`), false},
		{"trailing document", onlineScannerConfig + "{}", false},
		{"trailing junk", onlineScannerConfig + "x", false},
		{"trailing whitespace", onlineScannerConfig + "\n ", true},
		{"negative interval", strings.ReplaceAll(onlineScannerConfig, ":15", ":-1"), false},
		{"short interval", strings.ReplaceAll(onlineScannerConfig, ":15", ":14"), false},
		{"large interval", strings.ReplaceAll(onlineScannerConfig, ":15", ":43201"), false},
		{"overflow interval", strings.ReplaceAll(onlineScannerConfig, ":15", ":999999999999999999999"), false},
		{"negative signal", strings.ReplaceAll(onlineScannerConfig, ":0", ":-1"), false},
		{"oversized", onlineScannerConfig + strings.Repeat(" ", maxScannerConfigBytes), false},
		{"exact limit", onlineScannerConfig + strings.Repeat(" ", maxScannerConfigBytes-len(onlineScannerConfig)), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/scanner/config" || r.Header.Get("Authorization") != "Bearer test-token" {
					t.Errorf("incorrect config request")
				}
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			worker := worker{controlPlane: server.URL, token: "test-token"}
			cfg, ok := worker.fetchScannerConfig(context.Background())
			if ok != tc.valid {
				t.Fatalf("valid = %v, want %v; config %+v", ok, tc.valid, cfg)
			}
			if !ok && cfg != (scannerRuntimeConfig{}) {
				t.Fatalf("invalid response returned policy: %+v", cfg)
			}
		})
	}
}

func TestFetchScannerConfigTransport(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Error("followed config redirect")
			_, _ = fmt.Fprint(w, onlineScannerConfig)
		}))
		defer destination.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
		defer server.Close()
		worker := worker{controlPlane: server.URL}
		if _, ok := worker.fetchScannerConfig(context.Background()); ok {
			t.Fatal("accepted redirect")
		}
	})
	t.Run("status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, onlineScannerConfig)
		}))
		defer server.Close()
		worker := worker{controlPlane: server.URL}
		if _, ok := worker.fetchScannerConfig(context.Background()); ok {
			t.Fatal("accepted failure status")
		}
	})
	t.Run("deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		defer server.Close()
		worker := worker{controlPlane: server.URL}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, ok := worker.fetchScannerConfig(ctx); ok {
			t.Fatal("accepted timed out body")
		}
		if scannerConfigClient.Timeout != 30*time.Second {
			t.Fatal("missing independent request timeout")
		}
	})
}

func TestDBRefreshPolicy(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	online := scannerRuntimeConfig{DBRefreshMinutes: 15, RefreshNow: 100}
	offline := online
	offline.OfflineDB = true
	p := dbRefreshPolicy{envInterval: time.Hour, remoteRequired: true}
	if p.due(now, scannerRuntimeConfig{}, false) {
		t.Fatal("download before initial remote policy")
	}
	if p.due(now, offline, false) {
		t.Fatal("invalid policy opened boot gate")
	}
	if p.due(now, offline, true) {
		t.Fatal("offline boot refreshed")
	}
	if p.due(now.Add(time.Hour), scannerRuntimeConfig{}, false) {
		t.Fatal("outage discarded offline policy")
	}
	if !p.due(now, online, true) {
		t.Fatal("first online policy did not refresh")
	}
	p.last = now
	if p.due(now.Add(time.Minute), online, true) {
		t.Fatal("historical boot signal replayed")
	}
	if !p.due(now.Add(15*time.Minute), scannerRuntimeConfig{}, false) {
		t.Fatal("outage discarded last valid interval")
	}
	newer := online
	newer.RefreshNow = 101
	if !p.due(now.Add(time.Minute), newer, true) {
		t.Fatal("new force signal ignored")
	}
	if p.due(now.Add(time.Minute), newer, true) {
		t.Fatal("force signal replayed")
	}
	if p.due(now.Add(time.Minute), online, true) {
		t.Fatal("signal rollback triggered refresh")
	}
	if p.due(now.Add(time.Minute), newer, true) {
		t.Fatal("signal replay after rollback")
	}
	offline.RefreshNow = 102
	if p.due(now.Add(time.Minute), offline, true) {
		t.Fatal("force bypassed offline")
	}
	newer.RefreshNow = 102
	if p.due(now.Add(time.Minute), newer, true) {
		t.Fatal("offline signal was queued")
	}
	p.envOffline = true
	newer.RefreshNow = 103
	if p.due(now.Add(time.Hour), newer, true) {
		t.Fatal("remote policy bypassed env offline")
	}
}

func TestDBRefreshPolicyLocalDefaults(t *testing.T) {
	now := time.Now()
	p := dbRefreshPolicy{envInterval: time.Hour}
	if !p.due(now, scannerRuntimeConfig{}, false) {
		t.Fatal("standalone initial refresh blocked")
	}
	p.last = now
	if p.due(now.Add(time.Minute), scannerRuntimeConfig{}, false) {
		t.Fatal("early local refresh")
	}
	if !p.due(now.Add(time.Hour), scannerRuntimeConfig{}, false) {
		t.Fatal("local interval ignored")
	}
	p.envInterval = 0
	if p.due(now.Add(time.Hour), scannerRuntimeConfig{}, false) {
		t.Fatal("zero interval scheduled refresh")
	}
	if p.due(now, scannerRuntimeConfig{RefreshNow: 100}, true) {
		t.Fatal("first successful policy replayed historical signal")
	}
	if !p.due(now, scannerRuntimeConfig{RefreshNow: 101}, true) {
		t.Fatal("force ignored with zero interval")
	}
}
