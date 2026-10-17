package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func fixtureBenchClaim() claimedBenchRun {
	return claimedBenchRun{ID: uuid.NewString(), ClusterID: "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130", Profile: "kube-bench", Benchmark: "eks-1.4.0", Status: "claimed"}
}

func TestClaimedBenchmarkExactInvocationAndIngestPin(t *testing.T) {
	for _, scenario := range []string{"requested pin", "auto detection", "resolved cluster"} {
		t.Run(scenario, func(t *testing.T) { runClaimedInvocationCase(t, scenario) })
	}
}
func runClaimedInvocationCase(t *testing.T, scenario string) {
	t.Helper()
	claim := fixtureBenchClaim()
	if scenario == "auto detection" {
		claim.Benchmark = ""
	}
	script, arguments := benchInvocationScript(t, false)
	var claimCalls, ingestCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/compliance/bench/claim" {
			claimCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"request": claim})
			return
		}
		if r.URL.Path != "/api/v1/agent/compliance/ingest" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		ingestCalls.Add(1)
		if r.URL.Query().Get("benchmark") != claim.Benchmark || r.URL.Query().Get("cluster_id") != claim.ClusterID || r.URL.Query().Get("profile") != claim.Profile {
			t.Error("claim execution and evidence scope disagree")
		}
		_, _ = io.WriteString(w, `{"ingested":1}`)
	}))
	defer server.Close()
	cfg := config{apiURL: server.URL, token: "fixture", profile: "kubebench", clusterID: claim.ClusterID, benchmark: "configured-old", binary: "/bin/sh", args: []string{script, "--json", "--benchmark=configured-old", "--benchmark", "another-old"}}
	if scenario == "resolved cluster" {
		cfg.clusterID = ""
	}
	received, err := claimPendingRun(t.Context(), server.Client(), cfg)
	if err != nil || received == nil {
		t.Fatalf("valid claim refused %v", err)
	}
	if err := runClaimedBenchmark(t.Context(), server.Client(), cfg, *received, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Dir(arguments))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(filepath.Base(arguments))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	expected := []string{"--json"}
	if claim.Benchmark != "" {
		expected = append(expected, "--benchmark", claim.Benchmark)
	}
	if !reflect.DeepEqual(got, expected) || claimCalls.Load() != 1 || ingestCalls.Load() != 1 {
		t.Fatalf("wrong invocation %v want%v claim%d ingest%d", got, expected, claimCalls.Load(), ingestCalls.Load())
	}
	if cfg.benchmark != "configured-old" || len(cfg.args) != 5 {
		t.Fatal("claim mutated subsequent runner configuration")
	}
}
func benchInvocationScript(t *testing.T, fail bool) (string, string) {
	t.Helper()
	directory := t.TempDir()
	arguments := filepath.Join(directory, "arguments")
	t.Setenv("BENCH_TEST_ARGUMENTS", arguments)
	script := filepath.Join(directory, "benchmark.sh")
	source := "printf '%s\\n' \"$@\" > \"$BENCH_TEST_ARGUMENTS\"\nprintf '%s' '{\"Controls\":[]}'\n"
	if fail {
		source = "exit 7\n"
	}
	if err := os.WriteFile(script, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return script, arguments
}

func TestClaimedBenchmarkRejectsUnreviewedReceipt(t *testing.T) {
	for _, change := range []string{"wrong cluster", "missing cluster", "wrong profile", "missing profile", "invalid benchmark", "wrong status", "invalid id", "trailing envelope"} {
		t.Run(change, func(t *testing.T) {
			claim := fixtureBenchClaim()
			switch change {
			case "wrong cluster":
				claim.ClusterID = uuid.NewString()
			case "missing cluster":
				claim.ClusterID = ""
			case "wrong profile":
				claim.Profile = "docker-bench"
			case "missing profile":
				claim.Profile = ""
			case "invalid benchmark":
				claim.Benchmark = "../config"
			case "wrong status":
				claim.Status = "completed"
			case "invalid id":
				claim.ID = "not-uuid"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"request": claim})
				if change == "trailing envelope" {
					_, _ = io.WriteString(w, ` {"request":{}}`)
				}
			}))
			defer server.Close()
			received, err := claimPendingRun(t.Context(), server.Client(), config{apiURL: server.URL, profile: "kube-bench", clusterID: fixtureBenchClaim().ClusterID})
			if err == nil || received != nil {
				t.Fatal("unreviewed claim accepted")
			}
		})
	}
}
func TestClaimedBenchmarkFailuresNeverRetriggerOrConfirmCompletion(t *testing.T) {
	for _, failure := range []string{"execution", "ingest status", "ingest receipt"} {
		t.Run(failure, func(t *testing.T) {
			script, _ := benchInvocationScript(t, failure == "execution")
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				posts.Add(1)
				if failure == "ingest status" {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				_, _ = io.WriteString(w, `{"completed":true}`)
			}))
			defer server.Close()
			claim := fixtureBenchClaim()
			cfg := config{apiURL: server.URL, profile: "kube-bench", clusterID: claim.ClusterID, binary: "/bin/sh", args: []string{script, "--json"}}
			if err := runClaimedBenchmark(t.Context(), server.Client(), cfg, claim, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
				t.Fatal("unconfirmed execution/evidence reported success")
			}
			expected := int32(1)
			if failure == "execution" {
				expected = 0
			}
			if posts.Load() != expected {
				t.Fatalf("failure retriggered/misreported evidence posts%d want%d", posts.Load(), expected)
			}
		})
	}
}
func TestBenchmarkCredentialsNeverFollowRedirect(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		_, _ = io.WriteString(w, `{"ingested":1}`)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	cfg := config{apiURL: redirect.URL, profile: "kube-bench"}
	if claim, err := claimPendingRun(t.Context(), redirect.Client(), cfg); err == nil || claim != nil {
		t.Fatal("redirected claim accepted")
	}
	if err := postReport(t.Context(), redirect.Client(), redirect.URL, "private-fixture-token", []byte(`{}`)); err == nil {
		t.Fatal("redirected ingest accepted")
	}
	if forwarded.Load() != 0 {
		t.Fatal("credential request forwarded across origin")
	}
}
