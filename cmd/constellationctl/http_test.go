package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

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
