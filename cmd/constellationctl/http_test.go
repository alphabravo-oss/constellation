package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/serverless/awslambda"
)

func TestLoginCommandValidatesResponseBeforeSaving(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		status         int
		wantError      bool
	}{
		{"success", `{"token":"fixture"}`, http.StatusOK, false},
		{"empty-token", `{}`, http.StatusOK, true},
		{"invalid-json", `{`, http.StatusOK, true},
		{"oversize", strings.Repeat(" ", (1<<20)+1), http.StatusOK, true},
		{"denied", `{"error":"denied"}`, http.StatusUnauthorized, true},
		{"redirect", `{}`, http.StatusTemporaryRedirect, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONSTELLATION_CONFIG", filepath.Join(t.TempDir(), "config.json"))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/auth/login" {
					t.Errorf("unexpected login request: %s %s", r.Method, r.URL)
				}
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.response)
			}))
			defer server.Close()
			cmd := loginCmd()
			cmd.SetArgs([]string{"--server", server.URL, "--email", "fixture@example.test"})
			cmd.SetIn(strings.NewReader("fixture\n"))
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			err := cmd.ExecuteContext(t.Context())
			if (err != nil) != tc.wantError {
				t.Fatalf("login error = %v, want error %t", err, tc.wantError)
			}
			cfg, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantError && cfg.Token != "" || !tc.wantError && cfg.Token != "fixture" {
				t.Error("unexpected persisted login state")
			}
		})
	}
}

func TestCLIRequestsRespectCancellation(t *testing.T) {
	t.Setenv("CONSTELLATION_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("CONSTELLATION_PASSWORD", "fixture")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("canceled command reached server")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cli := &authedClient{server: server.URL, token: "fixture", http: newAPIClient()}
	for name, call := range map[string]func() error{
		"interactive-login": func() error {
			_, err := loginToken(ctx, newAPIClient(), server.URL, "fixture@example.test", "fixture")
			return err
		},
		"implicit-login": func() error {
			_, err := resolveClient(ctx, server.URL, "fixture@example.test")
			return err
		},
		"cluster-list": func() error { return cli.getJSON(ctx, "/api/v1/cluster-init-bundles", nil) },
		"lambda-report": func() error {
			_, err := (awsLambdaPackageReporter{client: cli}).Report(ctx, awslambda.PackageReport{})
			return err
		},
		"repository-report": func() error {
			return (repositoryPackageReporter{client: cli}).Report(ctx, repositoryPackageReport{}, &repositoryReportResponse{})
		},
		"backup-list": func() error {
			return listViaServer(ctx, server.URL, io.Discard)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
		})
	}
}

func TestBackupListRejectsHTTPFailure(t *testing.T) {
	t.Setenv("CONSTELLATION_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "denied")
	}))
	defer server.Close()
	cmd := backupListCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--server", server.URL})
	cmd.SetErr(io.Discard)
	if err := cmd.ExecuteContext(t.Context()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected permission failure, got %v", err)
	}
	if strings.Contains(output.String(), "denied") {
		t.Fatal("HTTP error body was reported as a successful backup list")
	}
}
