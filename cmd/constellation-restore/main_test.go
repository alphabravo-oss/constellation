package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func restoreFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := os.WriteFile(path, []byte("archive fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerRestorePolicyAndUpload(t *testing.T) {
	for _, policy := range []backup.ConflictPolicy{backup.ConflictSkip, backup.ConflictOverwrite} {
		t.Run(string(policy), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertRestoreUpload(t, r, policy)
				if _, err := io.WriteString(w, `{"manifest":{"org_name":"fixture"}}`); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			if err := runServerMode(t.Context(), server.URL+"/prefix/", "fixture", restoreFixture(t), policy); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServerRestoreRejectsRedirectAndFailure(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusUnauthorized, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirected" {
					t.Error("restore followed a redirect")
				}
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
			}))
			defer server.Close()
			if err := runServerMode(t.Context(), server.URL, "fixture", restoreFixture(t), backup.ConflictSkip); err == nil || !strings.Contains(err.Error(), "server returned") {
				t.Fatalf("expected HTTP rejection, got %v", err)
			}
		})
	}
}

func TestServerRestoreRespectsCancellation(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("canceled restore reached server")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := runServerMode(ctx, server.URL, "fixture", restoreFixture(t), backup.ConflictSkip)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func assertRestoreUpload(t *testing.T, r *http.Request, policy backup.ConflictPolicy) {
	t.Helper()
	if r.Method != http.MethodPost || r.URL.Path != "/prefix/api/v1/backups/restore" || r.URL.Query().Get("on_conflict") != string(policy) {
		t.Errorf("unexpected restore request: %s %s", r.Method, r.URL)
	}
	if r.Header.Get("Authorization") != "Bearer fixture" || r.Header.Get("Content-Type") != "application/octet-stream" {
		t.Error("missing upload authentication or content type")
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil || string(raw) != "archive fixture" {
		t.Errorf("upload body: %q, %v", raw, err)
	}
}
