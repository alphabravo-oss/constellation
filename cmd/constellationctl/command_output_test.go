package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
)

var errCommandOutputTest = errors.New("fixture output unavailable")

const commandOneTimeFixture = "one-time-output-fixture"

type failingCommandOutput struct {
	bytes.Buffer
	allow int
	calls int
}

func (out *failingCommandOutput) Write(value []byte) (int, error) {
	out.calls++
	if out.calls > out.allow {
		return 0, errCommandOutputTest
	}
	return out.Buffer.Write(value)
}

// Avoid bytes.Buffer.WriteString bypassing this writer's Write implementation.
func (out *failingCommandOutput) WriteString(value string) (int, error) {
	return out.Write([]byte(value))
}

func commandOutputFixture(t *testing.T, status int) *atomic.Int64 {
	t.Helper()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-auth" {
			t.Error("command lost its configured authentication")
		}
		w.WriteHeader(status)
		response := map[string]any{
			"id": "fixture-id", "name": "Fixture", "scopes": []string{"read-findings"},
			"raw_token": commandOneTimeFixture, "yaml": "credential: " + commandOneTimeFixture,
			"hint": "keep secure", "cluster_id": "fixture-cluster", "expires_at": "2026-11-01T00:00:00Z",
			"tokens":  []map[string]any{{"id": "fixture-id", "name": "Fixture", "scopes": []string{"read-findings"}}},
			"bundles": []map[string]any{{"id": "fixture-id", "name": "Fixture", "expires_at": "2026-11-01T00:00:00Z"}},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("CONSTELLATION_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := saveConfig(t.Context(), &config{Server: server.URL, Token: "fixture-auth"}); err != nil {
		t.Fatal(err)
	}
	return &requests
}

func outputCommands() []struct {
	name string
	make func(*string) *cobra.Command
	args []string
} {
	return []struct {
		name string
		make func(*string) *cobra.Command
		args []string
	}{
		{"token-create", func(*string) *cobra.Command { return tokensCreateCmd() }, []string{"--name", "Fixture", "--scope", "read-findings"}},
		{"token-list-table", func(*string) *cobra.Command { return tokensListCmd() }, nil},
		{"token-list-json", func(*string) *cobra.Command { return tokensListCmd() }, []string{"--json"}},
		{"token-rotate", func(*string) *cobra.Command { return tokensRotateCmd() }, []string{"fixture-id"}},
		{"token-revoke", func(*string) *cobra.Command { return tokensRevokeCmd() }, []string{"fixture-id"}},
		{"cluster-create", clusterCreateCmd, []string{"Fixture"}},
		{"cluster-list", clusterListCmd, nil},
		{"cluster-rotate", clusterRotateCmd, []string{"fixture-id"}},
		{"cluster-revoke", clusterRevokeCmd, []string{"fixture-id"}},
	}
}

func TestCredentialCommandsRejectFailedOutputWithoutReplayingOrLeaking(t *testing.T) {
	for _, fixture := range outputCommands() {
		t.Run(fixture.name, func(t *testing.T) {
			requests := commandOutputFixture(t, http.StatusOK)
			server := ""
			command := fixture.make(&server)
			// Keep Cobra usage outside the business-output write-count assertion.
			command.SilenceUsage = true
			writer := &failingCommandOutput{}
			var stderr bytes.Buffer
			command.SetOut(writer)
			command.SetErr(&stderr)
			command.SetArgs(fixture.args)
			err := command.ExecuteContext(t.Context())
			if !errors.Is(err, errCommandOutputTest) {
				t.Fatalf("output failure was not returned: %v", err)
			}
			if writer.calls != 1 || requests.Load() != 1 {
				t.Fatalf("command retried after uncertain output: writes=%d requests=%d", writer.calls, requests.Load())
			}
			if strings.Contains(err.Error()+stderr.String(), commandOneTimeFixture) || strings.Contains(err.Error()+stderr.String(), "fixture-auth") {
				t.Fatal("credential leaked in error output")
			}
		})
	}
}

func TestCredentialCommandsPreserveOutputAndHonorCancellation(t *testing.T) {
	for _, fixture := range outputCommands() {
		t.Run(fixture.name, func(t *testing.T) {
			requests := commandOutputFixture(t, http.StatusOK)
			server := ""
			command := fixture.make(&server)
			var stdout, stderr bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&stderr)
			command.SetArgs(fixture.args)
			if err := command.ExecuteContext(t.Context()); err != nil || stdout.Len() == 0 {
				t.Fatalf("successful command failed to deliver output: %v", err)
			}
			canceled, cancel := context.WithCancel(t.Context())
			cancel()
			command = fixture.make(&server)
			command.SilenceUsage = true
			stdout.Reset()
			command.SetOut(&stdout)
			command.SetErr(io.Discard)
			command.SetArgs(fixture.args)
			if err := command.ExecuteContext(canceled); !errors.Is(err, context.Canceled) {
				t.Fatalf("command lost cancellation: %v", err)
			}
			if stdout.Len() != 0 || requests.Load() != 1 {
				t.Fatal("canceled command wrote output or reached the API")
			}
		})
	}
}

func TestTokenOutputFailureAtSecretDoesNotLeakToCommandErrors(t *testing.T) {
	for _, fixture := range outputCommands() {
		if fixture.name != "token-create" && fixture.name != "token-rotate" {
			continue
		}
		t.Run(fixture.name, func(t *testing.T) {
			requests := commandOutputFixture(t, http.StatusOK)
			server := ""
			command := fixture.make(&server)
			// Keep Cobra usage outside the business-output write-count assertion.
			command.SilenceUsage = true
			writer := &failingCommandOutput{allow: 4}
			var stderr bytes.Buffer
			command.SetOut(writer)
			command.SetErr(&stderr)
			command.SetArgs(fixture.args)
			err := command.ExecuteContext(t.Context())
			if !errors.Is(err, errCommandOutputTest) || writer.calls != 5 || requests.Load() != 1 {
				t.Fatalf("failed secret output was not retained as failure: %v", err)
			}
			if strings.Contains(writer.String()+stderr.String()+err.Error(), commandOneTimeFixture) {
				t.Fatal("failed one-time output was exposed elsewhere")
			}
		})
	}
}

func TestBundleFileRemainsPrivateWhenConfirmationOutputFails(t *testing.T) {
	for _, fixture := range outputCommands() {
		if fixture.name != "cluster-create" && fixture.name != "cluster-rotate" {
			continue
		}
		t.Run(fixture.name, func(t *testing.T) {
			commandOutputFixture(t, http.StatusOK)
			path := filepath.Join(t.TempDir(), "bundle.yaml")
			server := ""
			command := fixture.make(&server)
			command.SetOut(&failingCommandOutput{})
			command.SetErr(io.Discard)
			command.SetArgs(append(append([]string{}, fixture.args...), "--output", path))
			if err := command.ExecuteContext(t.Context()); !errors.Is(err, errCommandOutputTest) {
				t.Fatalf("confirmation failure not returned: %v", err)
			}
			assertPrivateCommandBundle(t, path)
		})
	}
}

func assertPrivateCommandBundle(t *testing.T, path string) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	data, err := root.ReadFile("bundle.yaml")
	if err != nil || string(data) != "credential: "+commandOneTimeFixture {
		t.Fatal("completed private bundle was lost after confirmation failure")
	}
	info, err := root.Stat("bundle.yaml")
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("saved bundle is not private")
	}
}

func TestCredentialHTTPFailureDoesNotEchoOneTimeResponse(t *testing.T) {
	for _, fixture := range outputCommands() {
		t.Run(fixture.name, func(t *testing.T) {
			commandOutputFixture(t, http.StatusForbidden)
			server := ""
			command := fixture.make(&server)
			var stdout, stderr bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&stderr)
			command.SetArgs(fixture.args)
			err := command.ExecuteContext(t.Context())
			if err == nil || !strings.Contains(err.Error(), "403") {
				t.Fatalf("HTTP denial was reported as success: %v", err)
			}
			if strings.Contains(err.Error()+stderr.String()+stdout.String(), commandOneTimeFixture) {
				t.Fatal("credential-bearing error response was echoed")
			}
		})
	}
}

type commandWriterFunc func([]byte) (int, error)

func (write commandWriterFunc) Write(data []byte) (int, error) { return write(data) }

func TestCommandOutputRejectsShortWriteAndCanceledDelivery(t *testing.T) {
	output := commandOutput{ctx: t.Context(), writer: commandWriterFunc(func(data []byte) (int, error) { return len(data) - 1, nil })}
	output.println("fixture")
	if !errors.Is(output.result(), io.ErrShortWrite) {
		t.Fatal("short output was reported as delivered")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var written bytes.Buffer
	output = commandOutput{ctx: ctx, writer: &written}
	output.println("fixture")
	if !errors.Is(output.result(), context.Canceled) || written.Len() != 0 {
		t.Fatal("canceled output was delivered")
	}
}

type commandResponseBody struct {
	readErr, closeErr error
	closed            bool
}

func (body *commandResponseBody) Read([]byte) (int, error) { return 0, body.readErr }
func (body *commandResponseBody) Close() error             { body.closed = true; return body.closeErr }

func TestCommandResponseReadAndCloseFailuresNeverReturnSuccessfulBytes(t *testing.T) {
	for _, stage := range []string{"read", "close"} {
		t.Run(stage, func(t *testing.T) {
			body := &commandResponseBody{readErr: io.EOF}
			if stage == "read" {
				body.readErr = io.ErrUnexpectedEOF
			} else {
				body.closeErr = io.ErrUnexpectedEOF
			}
			data, err := readCommandResponse(&http.Response{Body: body})
			if !errors.Is(err, io.ErrUnexpectedEOF) || data != nil || !body.closed {
				t.Fatalf("uncertain response was accepted: data=%v err=%v closed=%v", data, err, body.closed)
			}
		})
	}
}
