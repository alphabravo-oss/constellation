package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
)

const residualBundleID = "00000000-0000-0000-0000-000000000321"
const residualBundleFixture = "registration-fixture-not-a-real-secret"

type residualPublication struct {
	name     string
	command  *cobra.Command
	args     []string
	flag     string
	requests int64
}

func residualPublications() []residualPublication {
	server := ""
	return []residualPublication{
		{"create", clusterCreateCmd(&server), []string{"Fixture"}, "--output", 1},
		{"rotate", clusterRotateCmd(&server), []string{residualBundleID}, "--output", 1},
		{"compliance", complianceExportCmd(), []string{"--framework", "nist-sp-800-53-r5", "--control", "AC-2", "--limit", "17"}, "--out", 2},
	}
}

func residualAPI(t *testing.T, fixture residualPublication, status int) *atomic.Int64 {
	t.Helper()
	_, requests := remainingHTTPConfig(t, func(w http.ResponseWriter, r *http.Request) {
		if !residualRequestMatches(t, fixture, r) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		if status != http.StatusOK {
			if _, err := io.WriteString(w, `{"error":"fixture request denied"}`); err != nil {
				t.Error(err)
			}
			return
		}
		var response any = map[string]any{
			"id": residualBundleID, "yaml": "scanner_token: " + residualBundleFixture,
			"cluster_id": "00000000-0000-0000-0000-000000000123", "expires_at": "2026-11-01T00:00:00Z",
		}
		if fixture.name == "compliance" {
			response = map[string]any{"evidence": "fixture-audit-row", "source": r.URL.Path}
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	})
	return requests
}

func residualRequestMatches(t *testing.T, fixture residualPublication, request *http.Request) bool {
	t.Helper()
	if fixture.name != "compliance" {
		path := "/api/v1/cluster-init-bundles"
		if fixture.name == "rotate" {
			path += "/" + residualBundleID + "/rotate"
		}
		if request.Method != http.MethodPost || request.URL.Path != path || request.URL.RawQuery != "" {
			t.Error("registration request changed authority or operation")
			return false
		}
		return true
	}
	if request.Method != http.MethodGet || request.URL.Query().Get("framework") != "nist-sp-800-53-r5" {
		t.Error("compliance request changed method or framework")
		return false
	}
	switch request.URL.Path {
	case "/api/v1/compliance/control-mappings":
		return true
	case "/api/v1/audit/events":
		query := request.URL.Query()
		if query.Get("control") == "AC-2" && query.Get("limit") == "17" && query.Get("with_controls") == "1" {
			return true
		}
	}
	t.Error("unexpected compliance evidence request")
	return false
}

func runResidual(ctx context.Context, fixture residualPublication, path string, writer io.Writer) error {
	command := fixture.command
	args := append([]string{}, fixture.args...)
	if path != "" {
		args = append(args, fixture.flag, path)
	}
	return executeRemainingOutput(ctx, command, writer, args...)
}

func assertResidualArtifact(t *testing.T, fixture residualPublication, path string) {
	t.Helper()
	body := publicationRead(t, path)
	if fixture.name != "compliance" {
		if string(body) != "scanner_token: "+residualBundleFixture {
			t.Fatal("registration artifact bytes changed")
		}
		return
	}
	var bundle struct {
		Framework string         `json:"framework"`
		Control   string         `json:"control_id"`
		Mappings  map[string]any `json:"mappings"`
		Audit     map[string]any `json:"audit_events"`
	}
	if err := json.Unmarshal(body, &bundle); err != nil || bundle.Framework != "nist-sp-800-53-r5" || bundle.Control != "AC-2" || bundle.Mappings["source"] != "/api/v1/compliance/control-mappings" || bundle.Audit["source"] != "/api/v1/audit/events" {
		t.Fatal("compliance evidence sources or selected control changed")
	}
}

func TestResidualPublicationPrivatelyReplacesHardlinkWithoutMutatingOriginal(t *testing.T) {
	for _, fixture := range residualPublications() {
		t.Run(fixture.name, func(t *testing.T) { checkResidualPrivateReplacement(t, fixture) })
	}
}

func checkResidualPrivateReplacement(t *testing.T, fixture residualPublication) {
	t.Helper()
	requests := residualAPI(t, fixture, http.StatusOK)
	parent := t.TempDir()
	publicationMode(t, parent, 0o750)
	original := filepath.Join(parent, "original")
	path := filepath.Join(parent, "chosen-output")
	if err := os.WriteFile(original, []byte("original complete artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	publicationMode(t, original, 0o644)
	if err := os.Link(original, path); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runResidual(t.Context(), fixture, path, &out); err != nil {
		t.Fatal(err)
	}
	assertResidualArtifact(t, fixture, path)
	if requests.Load() != fixture.requests || !strings.Contains(strings.ToLower(out.String()), "wrote") {
		t.Fatal("operation replayed or completion acknowledgement changed")
	}
	if string(publicationRead(t, original)) != "original complete artifact" {
		t.Fatal("publication mutated the linked original")
	}
	for _, row := range []struct {
		path string
		mode os.FileMode
	}{{path, 0o600}, {original, 0o644}, {parent, 0o750}} {
		info, err := os.Stat(row.path)
		if err != nil || info.Mode().Perm() != row.mode {
			t.Fatal("new output privacy or existing parent/original permissions changed")
		}
	}
}

func TestResidualPublicationRejectsSymlinkWithoutLeakingOrReplaying(t *testing.T) {
	for _, fixture := range residualPublications() {
		t.Run(fixture.name, func(t *testing.T) {
			requests := residualAPI(t, fixture, http.StatusOK)
			parent := t.TempDir()
			original := filepath.Join(parent, "original")
			if err := os.WriteFile(original, []byte("prior complete"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "output")
			if err := os.Symlink(original, path); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := runResidual(t.Context(), fixture, path, &out)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error(), residualBundleFixture) {
				t.Fatal("unsafe publication reported success or exposed credentials")
			}
			if requests.Load() != fixture.requests || string(publicationRead(t, original)) != "prior complete" {
				t.Fatal("operation replayed or symlink target changed")
			}
		})
	}
}

func TestResidualPublicationRetainsCompletedFileAfterFailedConfirmation(t *testing.T) {
	for _, fixture := range residualPublications() {
		t.Run(fixture.name, func(t *testing.T) {
			requests := residualAPI(t, fixture, http.StatusOK)
			path := filepath.Join(t.TempDir(), "output")
			if err := runResidual(t.Context(), fixture, path, &failingCommandOutput{}); !errors.Is(err, errCommandOutputTest) {
				t.Fatal("confirmation failure was reported as success")
			}
			assertResidualArtifact(t, fixture, path)
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 || requests.Load() != fixture.requests {
				t.Fatal("completed file lost privacy or operation was replayed")
			}
		})
	}
}

func TestResidualPublicationFailedSourcePreservesExistingArtifact(t *testing.T) {
	for _, fixture := range residualPublications() {
		t.Run(fixture.name, func(t *testing.T) {
			requests := residualAPI(t, fixture, http.StatusForbidden)
			path := filepath.Join(t.TempDir(), "output")
			if err := os.WriteFile(path, []byte("prior complete"), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := runResidual(t.Context(), fixture, path, &out); err == nil || out.Len() != 0 {
				t.Fatal("failed source was exported as successful evidence")
			}
			if requests.Load() != 1 || string(publicationRead(t, path)) != "prior complete" {
				t.Fatal("failed source replayed a request or replaced existing evidence")
			}
		})
	}
}

type residualCancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body residualCancelBody) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

func TestResidualPublicationCancellationAfterResponseDoesNotPublishOrReplay(t *testing.T) {
	for _, fixture := range residualPublications() {
		t.Run(fixture.name, func(t *testing.T) { checkResidualLateCancellation(t, fixture) })
	}
}

func checkResidualLateCancellation(t *testing.T, fixture residualPublication) {
	t.Helper()
	requests := residualAPI(t, fixture, http.StatusOK)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = remainingRoundTripper(func(request *http.Request) (*http.Response, error) {
		response, err := original.RoundTrip(request)
		if err == nil && (fixture.name != "compliance" || request.URL.Path == "/api/v1/audit/events") {
			response.Body = residualCancelBody{ReadCloser: response.Body, cancel: cancel}
		}
		return response, err
	})
	path := filepath.Join(t.TempDir(), "output")
	if err := os.WriteFile(path, []byte("prior complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runResidual(ctx, fixture, path, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("cancellation before publication was ignored")
	}
	if requests.Load() != fixture.requests || string(publicationRead(t, path)) != "prior complete" {
		t.Fatal("canceled publication replayed or replaced evidence")
	}
}

func TestResidualPublicationStdoutBehaviorRemainsAvailable(t *testing.T) {
	for _, fixture := range residualPublications() {
		t.Run(fixture.name, func(t *testing.T) {
			requests := residualAPI(t, fixture, http.StatusOK)
			var out bytes.Buffer
			if err := runResidual(t.Context(), fixture, "", &out); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != fixture.requests || out.Len() == 0 {
				t.Fatal("explicit stdout behavior changed or requests replayed")
			}
		})
	}
}
