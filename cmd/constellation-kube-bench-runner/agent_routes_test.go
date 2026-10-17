package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChartBenchmarkRunnerUsesBoundAgentRoutes(t *testing.T) {
	const report = `{"Controls":[{"id":"1","text":"Master Node"}]}`
	cluster := "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130"
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer chart-runtime-token" || r.URL.Query().Get("cluster_id") != cluster {
			t.Errorf("lost chart credential/scope")
		}
		switch r.URL.Path {
		case "/api/v1/agent/compliance/ingest":
			body, _ := io.ReadAll(r.Body)
			if string(body) != report || r.URL.Query().Get("profile") != "kube-bench" {
				t.Error("report changed")
			}
			_, _ = io.WriteString(w, `{"ingested":1}`)
		case "/api/v1/agent/compliance/bench/claim":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("runner used user authoring path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("chart-runtime-token"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTELLATION_API_URL", server.URL)
	t.Setenv("CONSTELLATION_CLUSTER_ID", cluster)
	t.Setenv("CONSTELLATION_KUBE_BENCH_RUNNER_TOKEN", "")
	t.Setenv("CONSTELLATION_KUBE_BENCH_RUNNER_TOKEN_FILE", "")
	t.Setenv("RUNTIME_AGENT_TOKEN", "")
	t.Setenv("RUNTIME_AGENT_TOKEN_FILE", tokenFile)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.binary = "/bin/printf"
	cfg.args = []string{"%s", report}
	if err := runAndIngest(t.Context(), server.Client(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if claimed, err := claimPendingRun(t.Context(), server.Client(), cfg); err != nil || claimed {
		t.Fatalf("empty claim %v %v", claimed, err)
	}
	if len(paths) != 2 {
		t.Fatalf("missing producer calls %v", paths)
	}
	assertChartRuntimeCredential(t, "kube-bench-runner-cronjob.yaml")
	assertChartRuntimeCredential(t, "docker-bench-runner-cronjob.yaml")
}

func assertChartRuntimeCredential(t *testing.T, name string) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join("..", "..", "deploy", "charts", "constellation", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, fragment := range []string{"name: CONSTELLATION_KUBE_BENCH_RUNNER_TOKEN", "name: RUNTIME_AGENT_TOKEN_FILE", "constellation.runtimeAgentTokenSecret", "/var/run/constellation/runtime-agent-token/token"} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("%s no longer supplies runner runtime credential: %s", name, fragment)
		}
	}
}
