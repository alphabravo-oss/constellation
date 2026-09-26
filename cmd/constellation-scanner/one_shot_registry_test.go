package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestOneShotConfiguredRegistryFailsBeforeScanWithoutCredentials(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		status     int
		credential registryCredentials
	}{
		{name: "fetch failure", status: http.StatusServiceUnavailable},
		{name: "missing credentials", status: http.StatusOK, credential: registryCredentials{Endpoint: "https://ghcr.io", AuthKind: "static"}},
		{name: "partial credentials", status: http.StatusOK, credential: registryCredentials{Endpoint: "https://ghcr.io", Username: "alice"}},
		{name: "wrong authority", status: http.StatusOK, credential: registryCredentials{Endpoint: "https://quay.io", Username: "alice", Password: "secret"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ambientDir := t.TempDir()
			if err := writeDockerConfig(ambientDir, "ghcr.io", "ambient", "secret"); err != nil {
				t.Fatal(err)
			}
			t.Setenv("DOCKER_CONFIG", ambientDir)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(testCase.status)
				if testCase.status == http.StatusOK {
					_ = json.NewEncoder(writer).Encode(testCase.credential)
				}
			}))
			defer server.Close()
			scans := 0
			worker := &worker{controlPlane: server.URL, token: "scanner-token", logger: nopLogger{}, agg: &scanner.Aggregator{Engines: []scanner.Engine{registryTestEngine{scan: func(context.Context, string, scanner.ScanOptions) (*scanner.EngineResult, error) {
				scans++
				return &scanner.EngineResult{Engine: "syft"}, nil
			}}}}}
			result, auth, cleanup, err := worker.scanOneShot(context.Background(), "ghcr.io/team/app:latest", "configured-registry", scanner.ScanOptions{})
			defer cleanup()
			if err == nil || result != nil || auth != (registryAuth{}) || scans != 0 {
				t.Fatalf("credential failure started scan: result=%+v auth=%+v scans=%d err=%v", result, auth, scans, err)
			}
		})
	}
}

func TestOneShotConfiguredRegistryRequiresControlPlaneAndToken(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		controlPlane string
		token        string
		registryID   string
	}{
		{name: "no control plane", token: "scanner-token", registryID: "registry"},
		{name: "no token", controlPlane: "https://example.test", registryID: "registry"},
		{name: "blank registry ID", controlPlane: "https://example.test", token: "scanner-token", registryID: " "},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			worker := &worker{controlPlane: testCase.controlPlane, token: testCase.token}
			result, _, cleanup, err := worker.scanOneShot(context.Background(), "ghcr.io/team/app:latest", testCase.registryID, scanner.ScanOptions{})
			defer cleanup()
			if err == nil || result != nil {
				t.Fatalf("missing configuration accepted: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestOneShotRegistryCredentialsAreIsolatedAndCleaned(t *testing.T) {
	ambientDir := t.TempDir()
	if err := writeDockerConfig(ambientDir, "ghcr.io", "ambient", "secret"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", ambientDir)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer scanner-token" || request.URL.Query().Get("registry_id") != "registry" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(writer).Encode(registryCredentials{Endpoint: "https://ghcr.io", Username: "alice", Password: "private-secret"})
	}))
	defer server.Close()
	var scanOptions scanner.ScanOptions
	worker := &worker{controlPlane: server.URL, token: "scanner-token", logger: nopLogger{}, agg: &scanner.Aggregator{Engines: []scanner.Engine{registryTestEngine{scan: func(_ context.Context, ref string, options scanner.ScanOptions) (*scanner.EngineResult, error) {
		scanOptions = options
		return &scanner.EngineResult{Engine: "syft", ImageRef: ref}, nil
	}}}}}
	result, auth, cleanup, err := worker.scanOneShot(context.Background(), "ghcr.io/team/app:latest", "registry", scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || auth.DockerConfigDir == "" || auth.DockerConfigDir == ambientDir || scanOptions.DockerConfigDir != auth.DockerConfigDir || scanOptions.Username != "alice" || scanOptions.Password != "private-secret" || scanOptions.RegistryAuthority != "ghcr.io" {
		t.Fatalf("one-shot auth not isolated: result=%+v auth=%+v options=%+v", result, auth, scanOptions)
	}
	assertPrivateDockerConfig(t, auth.DockerConfigDir, "private-secret")
	cleanup()
	assertRemoved(t, auth.DockerConfigDir)
}

func TestOneShotExplicitAnonymousRegistryUsesEmptyDockerConfig(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(registryCredentials{Endpoint: "https://ghcr.io", AuthKind: "none"})
	}))
	defer server.Close()
	var configDir string
	worker := &worker{controlPlane: server.URL, token: "scanner-token", logger: nopLogger{}, agg: &scanner.Aggregator{Engines: []scanner.Engine{registryTestEngine{scan: func(_ context.Context, ref string, options scanner.ScanOptions) (*scanner.EngineResult, error) {
		configDir = options.DockerConfigDir
		return &scanner.EngineResult{Engine: "syft", ImageRef: ref}, nil
	}}}}}
	_, auth, cleanup, err := worker.scanOneShot(context.Background(), "ghcr.io/team/app:latest", "registry", scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if configDir == "" || configDir == os.Getenv("DOCKER_CONFIG") || configDir != auth.DockerConfigDir {
		t.Fatalf("anonymous registry used ambient config: %q", configDir)
	}
	contents, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil || string(contents) != `{"auths":{}}` {
		t.Fatalf("anonymous config = %q, %v", contents, err)
	}
	cleanup()
	assertRemoved(t, configDir)
}

func TestOneShotScanFailureRemovesRegistryConfig(t *testing.T) {
	server := registryCredentialsServer(t, nil)
	defer server.Close()
	var configDir string
	worker := &worker{controlPlane: server.URL, token: "scanner-token", logger: nopLogger{}, agg: &scanner.Aggregator{Engines: []scanner.Engine{registryTestEngine{scan: func(_ context.Context, _ string, options scanner.ScanOptions) (*scanner.EngineResult, error) {
		configDir = options.DockerConfigDir
		return nil, errors.New("scan failed")
	}}}}}
	_, _, cleanup, err := worker.scanOneShot(context.Background(), "ghcr.io/team/app:latest", "registry", scanner.ScanOptions{})
	defer cleanup()
	if err == nil || !strings.Contains(err.Error(), "scan failed") || configDir == "" {
		t.Fatalf("scan failure = %v, config=%q", err, configDir)
	}
	assertRemoved(t, configDir)
}

func TestOneShotWithoutRegistryIDKeepsLegacyScan(t *testing.T) {
	var scanOptions scanner.ScanOptions
	worker := &worker{agg: &scanner.Aggregator{Engines: []scanner.Engine{registryTestEngine{scan: func(_ context.Context, ref string, options scanner.ScanOptions) (*scanner.EngineResult, error) {
		scanOptions = options
		return &scanner.EngineResult{Engine: "syft", ImageRef: ref}, nil
	}}}}}
	result, auth, cleanup, err := worker.scanOneShot(context.Background(), "ghcr.io/team/app:latest", "", scanner.ScanOptions{})
	defer cleanup()
	if err != nil || result == nil || auth != (registryAuth{}) || scanOptions.DockerConfigDir != "" {
		t.Fatalf("legacy one-shot scan changed: result=%+v auth=%+v options=%+v err=%v", result, auth, scanOptions, err)
	}
}
