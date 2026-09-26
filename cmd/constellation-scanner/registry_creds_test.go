package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestRegistryAuthorityFromImageRef(t *testing.T) {
	cases := []struct {
		name     string
		imageRef string
		endpoint string
		want     string
	}{
		{"ghcr ref", "ghcr.io/acme/api:1.2.3", "", "ghcr.io"},
		{"private ref", "registry.internal:5000/team/app:tag", "", "registry.internal:5000"},
		{"docker hub short ref", "library/ubuntu:latest", "", "docker.io"},
		{"bare hub ref", "ubuntu:latest", "", "docker.io"},
		{"endpoint fallback", "", "https://harbor.example.com/v2/", "harbor.example.com"},
		{"ref beats endpoint", "quay.io/acme/api:1", "https://harbor.example.com", "quay.io"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := registryAuthority(tc.imageRef, tc.endpoint); got != tc.want {
				t.Fatalf("registryAuthority(%q,%q)=%q want %q", tc.imageRef, tc.endpoint, got, tc.want)
			}
		})
	}
}

func TestWriteDockerConfigProducesReadableAuths(t *testing.T) {
	dir := t.TempDir()
	if err := writeDockerConfig(dir, "ghcr.io", "alice", "s3cret"); err != nil {
		t.Fatalf("writeDockerConfig: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	var cfg struct {
		Auths map[string]struct {
			Auth     string `json:"auth"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entry, ok := cfg.Auths["ghcr.io"]
	if !ok {
		t.Fatalf("missing ghcr.io auth entry; got %v", cfg.Auths)
	}
	if entry.Username != "alice" || entry.Password != "s3cret" {
		t.Fatalf("user/pass = %q/%q want alice/s3cret", entry.Username, entry.Password)
	}
	wantAuth := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	if entry.Auth != wantAuth {
		t.Fatalf("auth=%q want %q", entry.Auth, wantAuth)
	}
}

func TestWriteDockerConfigDockerHubAddsLegacyIndexKey(t *testing.T) {
	dir := t.TempDir()
	if err := writeDockerConfig(dir, "docker.io", "bob", "pw"); err != nil {
		t.Fatalf("writeDockerConfig: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	var cfg struct {
		Auths map[string]json.RawMessage `json:"auths"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"docker.io", "https://index.docker.io/v1/"} {
		if _, ok := cfg.Auths[key]; !ok {
			t.Fatalf("missing auth key %q; got %v", key, cfg.Auths)
		}
	}
}

func TestWriteDockerConfigDoesNotOverwriteExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeDockerConfig(dir, "ghcr.io", "alice", "secret"); err == nil {
		t.Fatal("expected existing config to be rejected")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "existing" {
		t.Fatalf("existing config changed: %q, %v", contents, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("existing config mode changed: %v, %v", info, err)
	}
}

func TestResolveRegistryAuthPerJobIsolationAndModes(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	server := registryCredentialsServer(t, nil)
	defer server.Close()
	w := &worker{controlPlane: server.URL, token: "scanner-token", logger: nopLogger{}}

	firstID, secondID := "first", "second"
	first, releaseFirst := w.resolveRegistryAuth(context.Background(), &scanJob{ID: firstID, RegistryID: &firstID}, "ghcr.io/team/app:1")
	defer releaseFirst()
	second, releaseSecond := w.resolveRegistryAuth(context.Background(), &scanJob{ID: secondID, RegistryID: &secondID}, "ghcr.io/team/app:2")
	defer releaseSecond()
	if first.DockerConfigDir == "" || second.DockerConfigDir == "" || first.DockerConfigDir == second.DockerConfigDir {
		t.Fatalf("jobs must have distinct config dirs: %q, %q", first.DockerConfigDir, second.DockerConfigDir)
	}
	for _, auth := range []registryAuth{first, second} {
		assertPrivateDockerConfig(t, auth.DockerConfigDir, auth.Password)
	}
	releaseFirst()
	assertRemoved(t, first.DockerConfigDir)
	assertPrivateDockerConfig(t, second.DockerConfigDir, second.Password)
	releaseSecond()
	assertRemoved(t, second.DockerConfigDir)
}

func TestResolveRegistryAuthRejectsOtherRegistryEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(registryCredentials{Endpoint: "https://other.example.test", Username: "alice", Password: "private-secret"})
	}))
	defer server.Close()
	w := &worker{controlPlane: server.URL, logger: nopLogger{}}
	registryID := "registry-id"
	auth, release := w.resolveRegistryAuth(context.Background(), &scanJob{ID: "job", RegistryID: &registryID}, "registry.example.test/team/app:latest")
	defer release()
	if auth != (registryAuth{}) {
		t.Fatal("mismatched registry credentials were materialized")
	}
}

func TestExecuteJobRemovesRegistryAuthOnSuccessFailureAndCancel(t *testing.T) {
	for _, outcome := range []string{"success", "failure", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			reports := make(chan string, 1)
			server := registryCredentialsServer(t, reports)
			defer server.Close()
			seen := make(chan scanner.ScanOptions, 1)
			proceed := make(chan struct{})
			w := &worker{
				controlPlane: server.URL,
				token:        "scanner-token",
				logger:       nopLogger{},
				agg: &scanner.Aggregator{Engines: []scanner.Engine{registryTestEngine{scan: func(ctx context.Context, ref string, opts scanner.ScanOptions) (*scanner.EngineResult, error) {
					seen <- opts
					select {
					case <-proceed:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					switch outcome {
					case "failure":
						return nil, errors.New("scan failed")
					case "cancel":
						<-ctx.Done()
						return nil, ctx.Err()
					default:
						return &scanner.EngineResult{Engine: "syft", ImageRef: ref}, nil
					}
				}}}},
			}
			jobID := "job-" + outcome
			job := &scanJob{ID: jobID, TargetType: "image", TargetRef: "localhost:1/team/app@sha256:" + strings.Repeat("a", 64), RegistryID: &jobID}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				w.executeJob(ctx, job)
				close(done)
			}()
			var opts scanner.ScanOptions
			select {
			case opts = <-seen:
			case <-ctx.Done():
				t.Fatal("scan did not start")
			}
			if opts.Username != "alice" || opts.Password != jobID || opts.RegistryAuthority != "localhost:1" {
				t.Fatalf("unexpected job credentials: %+v", opts)
			}
			assertPrivateDockerConfig(t, opts.DockerConfigDir, jobID)
			close(proceed)
			if outcome == "cancel" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("job did not return")
			}
			assertRemoved(t, opts.DockerConfigDir)
			if outcome != "cancel" {
				select {
				case report := <-reports:
					want := "/complete"
					if outcome == "failure" {
						want = "/fail"
					}
					if !strings.HasSuffix(report, want) {
						t.Fatalf("report path = %q, want suffix %q", report, want)
					}
				default:
					t.Fatal("job did not report result")
				}
			}
		})
	}
}

func registryCredentialsServer(t *testing.T, reports chan<- string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/scanner/registry-credentials" {
			if request.Header.Get("Authorization") != "Bearer scanner-token" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			registryID := request.URL.Query().Get("registry_id")
			endpoint := "https://ghcr.io"
			if strings.HasPrefix(registryID, "job-") {
				endpoint = "https://localhost:1"
			}
			_ = json.NewEncoder(writer).Encode(registryCredentials{Endpoint: endpoint, Username: "alice", Password: registryID})
			return
		}
		if reports != nil {
			reports <- request.URL.Path
		}
		writer.WriteHeader(http.StatusOK)
	}))
}

func assertPrivateDockerConfig(t *testing.T, dir, password string) {
	t.Helper()
	for path, wantMode := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "config.json"): 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != wantMode {
			t.Fatalf("%s mode = %v, err = %v; want %04o", path, info, err, wantMode)
		}
	}
	contents, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), fmt.Sprintf(`"password":%q`, password)) {
		t.Fatalf("config does not contain this job's password: %s", contents)
	}
}

func assertRemoved(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("config dir %q still exists: %v", path, err)
	}
}

type registryTestEngine struct {
	scan func(context.Context, string, scanner.ScanOptions) (*scanner.EngineResult, error)
}

func (registryTestEngine) Name() string { return "syft" }

func (engine registryTestEngine) Scan(ctx context.Context, ref string, opts scanner.ScanOptions) (*scanner.EngineResult, error) {
	return engine.scan(ctx, ref, opts)
}

// TestResolveRegistryAuthNoRegistryIsNoop verifies a job without a registry_id
// short-circuits to zero-auth without touching the filesystem or network.
func TestResolveRegistryAuthNoRegistryIsNoop(t *testing.T) {
	w := &worker{logger: nopLogger{}}
	auth, cleanup := w.resolveRegistryAuth(nil, &scanJob{ID: "j1"}, "ghcr.io/x/y:1")
	defer cleanup()
	if auth.Username != "" || auth.Password != "" || auth.DockerConfigDir != "" {
		t.Fatalf("expected zero auth for registry-less job, got %+v", auth)
	}
	cleanup() // must be safe to call (no-op)
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}
