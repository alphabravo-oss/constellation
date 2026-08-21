package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
