//go:build integration

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/internal/serverless/awslambda"
	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
)

func remainingOutputFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func executeRemainingOutput(ctx context.Context, command *cobra.Command, writer io.Writer, args ...string) error {
	command.SilenceUsage = true
	command.SilenceErrors = true
	command.SetOut(writer)
	command.SetErr(io.Discard)
	command.SetArgs(args)
	return command.ExecuteContext(ctx)
}

func TestRemainingLocalCommandsRejectUndeliveredOutput(t *testing.T) {
	policy := remainingOutputFile(t, "policy.json", testPolicyJSON)
	record := remainingOutputFile(t, "record.json", `{"image":{"tag":"latest"}}`)
	model := remainingOutputFile(t, "model.onnx", "fixture")
	for _, fixture := range []struct {
		name string
		make func() *cobra.Command
		args []string
	}{
		{"version", versionCmd, nil},
		{"model", modelCheckCmd, []string{model}},
		{"policy-validate", policyValidateCmd, []string{policy}},
		{"policy-check", policyCheckCmd, []string{policy}},
		{"policy-record", policyCheckCmd, []string{policy, "--record", record}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			writer := &failingCommandOutput{}
			if err := executeRemainingOutput(t.Context(), fixture.make(), writer, fixture.args...); !errors.Is(err, errCommandOutputTest) {
				t.Fatalf("command returned success after losing output: %v", err)
			}
			if writer.calls != 1 {
				t.Fatalf("command kept writing after failure: %d", writer.calls)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var output bytes.Buffer
			if err := executeRemainingOutput(ctx, fixture.make(), &output, fixture.args...); !errors.Is(err, context.Canceled) || output.Len() != 0 {
				t.Fatalf("canceled command delivered output: %v %q", err, output.String())
			}
		})
	}
}

type remainingInput struct{ reads int }

func (input *remainingInput) Read([]byte) (int, error) {
	input.reads++
	return 0, errors.New("unexpected password read")
}

func remainingHTTPConfig(t *testing.T, handler http.HandlerFunc) (string, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-auth" {
			t.Error("lost configured authentication")
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	t.Setenv("CONSTELLATION_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := saveConfig(t.Context(), &config{Server: server.URL, Token: "fixture-auth"}); err != nil {
		t.Fatal(err)
	}
	return server.URL, &requests
}

func remainingHTTPSuccess(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if r.URL.Path == "/api/v1/vulndb:import" {
		reader, err := r.MultipartReader()
		if err != nil {
			t.Error(err)
			return
		}
		for range 2 {
			part, err := reader.NextPart()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := io.Copy(io.Discard, part); err != nil {
				t.Error(err)
			}
		}
		if _, err := reader.NextPart(); !errors.Is(err, io.EOF) {
			t.Errorf("multipart closing boundary missing: %v", err)
		}
	}
	if _, err := io.WriteString(w, `{"cluster_id":"fixture-cluster","state":"joint","master_url":"https://master.example.test","ok":true}`); err != nil {
		t.Error(err)
	}
}

type remainingHTTPCommand struct {
	name     string
	make     func(string, string) *cobra.Command
	args     []string
	requests int64
}

func remainingHTTPCommands() []remainingHTTPCommand {
	return []remainingHTTPCommand{
		{"federation-join", func(server, _ string) *cobra.Command { return federationJoinCmd(&server) }, []string{"--master-url", "https://master.example.test", "--token", "fixture-join"}, 1},
		{"audit-verify", func(_, _ string) *cobra.Command { return auditCmd() }, []string{"verify"}, 1},
		{"compliance-export", func(_, _ string) *cobra.Command { return complianceExportCmd() }, []string{"--framework", "nist", "--control", "AC-2"}, 2},
		{"vulndb-status", func(_, _ string) *cobra.Command { return vulndbStatusCmd() }, nil, 1},
		{"vulndb-import", func(_, dir string) *cobra.Command {
			c := vulndbImportCmd()
			c.SetArgs([]string{"--dir", dir})
			return c
		}, nil, 1},
		{"backup-list", func(server, _ string) *cobra.Command {
			c := backupListCmd()
			c.SetArgs([]string{"--server", server})
			return c
		}, nil, 1},
	}
}

func remainingFixtureCommand(fixture remainingHTTPCommand, server, dir string) (*cobra.Command, []string) {
	args := fixture.args
	if fixture.name == "vulndb-import" {
		args = []string{"--dir", dir}
	}
	if fixture.name == "backup-list" {
		args = []string{"--server", server}
	}
	return fixture.make(server, dir), args
}

func remainingBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"manifest.json", "bundle.jsonl.gz"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRemainingHTTPCommandsRejectOutputFailureWithoutReplay(t *testing.T) {
	for _, fixture := range remainingHTTPCommands() {
		t.Run(fixture.name, func(t *testing.T) {
			server, requests := remainingHTTPConfig(t, func(w http.ResponseWriter, r *http.Request) { remainingHTTPSuccess(t, w, r) })
			command, args := remainingFixtureCommand(fixture, server, remainingBundle(t))
			writer := &failingCommandOutput{}
			if err := executeRemainingOutput(t.Context(), command, writer, args...); !errors.Is(err, errCommandOutputTest) {
				t.Fatalf("false success: %v", err)
			}
			if writer.calls != 1 || requests.Load() != fixture.requests {
				t.Fatalf("operation was replayed or output kept writing: calls=%d requests=%d", writer.calls, requests.Load())
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			command, args = remainingFixtureCommand(fixture, server, remainingBundle(t))
			var output bytes.Buffer
			if err := executeRemainingOutput(ctx, command, &output, args...); !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			if output.Len() != 0 || requests.Load() != fixture.requests {
				t.Fatal("canceled command called API or delivered output")
			}
		})
	}
}

func TestBackupKeyFilesSurviveFailedConfirmationWithoutRegeneration(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	if err := executeRemainingOutput(t.Context(), backupGenKeyCmd(), &failingCommandOutput{}, private, public); !errors.Is(err, errCommandOutputTest) {
		t.Fatalf("key confirmation failed silently: %v", err)
	}
	info, err := os.Stat(private)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("completed private key was lost or exposed")
	}
	if _, err := os.Stat(public); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	path := filepath.Join(dir, "canceled.pem")
	if err := executeRemainingOutput(ctx, backupGenKeyCmd(), io.Discard, path, path+".pub"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled key command did not fail")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled command created a key")
	}
}

func TestScanSummaryStopsAfterUndeliveredFirstWrite(t *testing.T) {
	writer := &failingCommandOutput{}
	out := &commandOutput{ctx: t.Context(), writer: writer}
	printScanSummary(out, &scanner.ScanResult{ImageRef: "fixture/image:tag"})
	if !errors.Is(out.result(), errCommandOutputTest) || writer.calls != 1 {
		t.Fatal("summary ignored failed output")
	}
}

func TestIACWritesConfiguredOutputAndPreservesArtifactAfterFailedConfirmation(t *testing.T) {
	original := newExecCommand
	t.Cleanup(func() { newExecCommand = original })
	newExecCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/echo", `{"Results":[]}`)
	}
	var output bytes.Buffer
	if err := executeRemainingOutput(t.Context(), iacCheckCmd(), &output, "fixture"); err != nil || !strings.Contains(output.String(), "Results") {
		t.Fatalf("IaC result bypassed command writer: %v %q", err, output.String())
	}
	if err := executeRemainingOutput(t.Context(), iacCheckCmd(), &failingCommandOutput{}, "fixture"); !errors.Is(err, errCommandOutputTest) {
		t.Fatal("IaC output failure ignored")
	}
	path := filepath.Join(t.TempDir(), "result.sarif")
	if err := executeRemainingOutput(t.Context(), iacCheckCmd(), &failingCommandOutput{}, "fixture", "--sarif", path); !errors.Is(err, errCommandOutputTest) {
		t.Fatal("artifact confirmation failure ignored")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	data, err := root.ReadFile("result.sarif")
	if err != nil || !strings.Contains(string(data), "Results") {
		t.Fatal("completed artifact was lost after confirmation failure")
	}
}

func TestTruncatedBackupEntryCannotProduceVerifiedPartialManifest(t *testing.T) {
	var archive bytes.Buffer
	zip := gzip.NewWriter(&archive)
	tarball := tar.NewWriter(zip)
	if err := tarball.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarball.Write([]byte(`{"partial":true}`)); err != nil {
		t.Fatal(err)
	}
	// Closing gzip without closing the incomplete tar entry produces valid gzip
	// containing a truncated entry, rather than a checksum-only error.
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, _, _, err := extractCLIManifestAndSig(&archive)
	if !errors.Is(err, io.ErrUnexpectedEOF) || manifest != nil {
		t.Fatalf("partial manifest was accepted: %s %v", manifest, err)
	}
}

type remainingRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip remainingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type remainingCloseFailure struct{ io.Reader }

func (*remainingCloseFailure) Close() error { return io.ErrUnexpectedEOF }

func TestRemainingHTTPCommandsRejectReadAndCloseFailures(t *testing.T) {
	for _, fixture := range remainingHTTPCommands() {
		for _, stage := range []string{"read", "close"} {
			t.Run(fixture.name+"-"+stage, func(t *testing.T) {
				remainingHTTPFailure(t, fixture, stage)
			})
		}
	}
}

func remainingHTTPFailure(t *testing.T, fixture remainingHTTPCommand, stage string) {
	t.Helper()
	server, _ := remainingHTTPConfig(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected real HTTP request") })
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	var requests int
	http.DefaultTransport = remainingRoundTripper(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Body != nil {
			_, copyErr := io.Copy(io.Discard, req.Body)
			if err := errors.Join(copyErr, req.Body.Close()); err != nil {
				return nil, err
			}
		}
		var body io.ReadCloser = &commandResponseBody{readErr: io.ErrUnexpectedEOF}
		if stage == "close" {
			body = &remainingCloseFailure{Reader: strings.NewReader(`{"ok":true}`)}
		}
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	})
	command, args := remainingFixtureCommand(fixture, server, remainingBundle(t))
	var output bytes.Buffer
	if err := executeRemainingOutput(t.Context(), command, &output, args...); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("uncertain HTTP response accepted: %v", err)
	}
	// Backup listing intentionally streams; a close failure can occur after
	// bytes were delivered. It must still fail and must never repeat the read.
	wantOutput := ""
	if fixture.name == "backup-list" && stage == "close" {
		wantOutput = `{"ok":true}`
	}
	if output.String() != wantOutput || requests != 1 {
		t.Fatalf("failed response was printed or replayed: output=%q requests=%d", output.String(), requests)
	}
}

func TestComplianceExportRejectsMalformedEvidenceAndPreservesExactQuery(t *testing.T) {
	for _, malformed := range []string{"mappings", "events"} {
		t.Run(malformed, func(t *testing.T) {
			_, requests := remainingHTTPConfig(t, func(w http.ResponseWriter, r *http.Request) {
				remainingComplianceResponse(t, malformed, w, r)
			})
			var output bytes.Buffer
			err := executeRemainingOutput(t.Context(), complianceExportCmd(), &output, "--framework", "fw&action=injected", "--control", "AC-2")
			if err == nil || output.Len() != 0 {
				t.Fatalf("malformed evidence was exported as successful null: %v %q", err, output.String())
			}
			want := int64(1)
			if malformed == "events" {
				want = 2
			}
			if requests.Load() != want {
				t.Fatal("failed evidence was fetched again or continued")
			}
		})
	}
}

func remainingComplianceResponse(t *testing.T, malformed string, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if r.URL.Query().Get("framework") != "fw&action=injected" {
		t.Error("framework was reinterpreted as URL query syntax")
	}
	body := `{"items":[]}`
	if strings.Contains(r.URL.Path, "control-mappings") == (malformed == "mappings") {
		body = `{"incomplete":`
	}
	if _, err := io.WriteString(w, body); err != nil {
		t.Error(err)
	}
}

func TestRepositoryReportPropagatesHumanAndJSONOutputFailures(t *testing.T) {
	for _, jsonOut := range []bool{false, true} {
		out := repositoryReportResponse{PackageCount: 12, ScanJobID: "fixture-job"}
		writer := &failingCommandOutput{}
		err := writeRepositoryReport(t.Context(), writer, "repo/fixture", "commit", out, jsonOut)
		if !errors.Is(err, errCommandOutputTest) || writer.calls != 1 {
			t.Fatal("repository acknowledgement lost its output error")
		}
		var output bytes.Buffer
		if err := writeRepositoryReport(t.Context(), &output, "repo/fixture", "commit", out, jsonOut); err != nil || !strings.Contains(output.String(), "fixture-job") {
			t.Fatalf("repository acknowledgement changed: %v %q", err, output.String())
		}
	}
}

func TestServerlessSummaryPreservesCollectionAndDiagnosticFailures(t *testing.T) {
	collectErr := errors.New("fixture partial collection")
	for _, jsonOut := range []bool{false, true} {
		command := &cobra.Command{}
		command.SetContext(t.Context())
		writer := &failingCommandOutput{}
		command.SetOut(writer)
		err := writeServerlessSummary(command, awslambda.Summary{Failed: 1}, jsonOut, collectErr)
		if !errors.Is(err, errCommandOutputTest) || !errors.Is(err, collectErr) || writer.calls != 1 {
			t.Fatal("collection or output failure was discarded")
		}
	}
	command := &cobra.Command{}
	command.SetContext(t.Context())
	command.SetOut(io.Discard)
	writer := &failingCommandOutput{}
	command.SetErr(writer)
	err := writeServerlessSummary(command, awslambda.Summary{Errors: []string{"first", "second"}}, false, collectErr)
	if !errors.Is(err, collectErr) || !errors.Is(err, errCommandOutputTest) || writer.calls != 1 {
		t.Fatal("diagnostic failure was discarded or kept writing")
	}
}

func remainingBackfillFixture(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := remainingCLIDatabase(t)
	_, err := pool.Exec(t.Context(), `CREATE TABLE network_flows (LIKE public.network_flows INCLUDING ALL);
CREATE TABLE network_flow_rollups (LIKE public.network_flow_rollups INCLUDING ALL);
CREATE TABLE network_flow_rollup_state (id boolean PRIMARY KEY, watermark timestamptz, raw_pruned_before timestamptz);
INSERT INTO network_flow_rollup_state VALUES (true, now(), '1970-01-01');
CREATE TABLE pod_ips (org_id uuid, ip inet, namespace text, deployment text, pod_name text);
CREATE TABLE cluster_services (org_id uuid, cluster_ip inet, namespace text, name text);
INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol,at,bytes)
VALUES ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','cluster/127.0.0.1','app/b','tcp', now()-interval '1 minute',10);`)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func remainingCLIDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	database := db.NewFromPool(pgtest.Pool(t))
	return pgfixture.Schema(t, database.Pool())
}

func TestBackfillFailedOutputDoesNotReplayMutationOrHideCompletionFailure(t *testing.T) {
	for _, stage := range []string{"before-update", "after-update"} {
		t.Run(stage, func(t *testing.T) {
			pool := remainingBackfillFixture(t)
			writer := &failingCommandOutput{}
			want := "cluster/127.0.0.1"
			if stage == "after-update" {
				writer.allow = 1
				want = "node-local/loopback"
			}
			err := backfillNetworkFlows(t.Context(), writer, pool, 1, 10, false, "")
			if !errors.Is(err, errCommandOutputTest) || writer.calls != writer.allow+1 {
				t.Fatalf("mutation output error was ignored: %v", err)
			}
			var actual string
			if err := pool.QueryRow(t.Context(), `SELECT src_workload FROM network_flows`).Scan(&actual); err != nil || actual != want {
				t.Fatalf("unexpected relabel on failure: %s %v", actual, err)
			}
		})
	}
}

func TestExternalCommandCancellationDoesNotBecomeSuccessfulPartialOutput(t *testing.T) {
	original := newExecCommand
	t.Cleanup(func() { newExecCommand = original })
	newExecCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'partial-result'; exec sleep 30")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	output, err := runCmd(ctx, "fixture")
	if !errors.Is(err, context.DeadlineExceeded) || output != nil {
		t.Fatalf("canceled process's partial output was accepted: %s %v", output, err)
	}
}

func TestPolicyCRDExportRejectsFailedStreamAndConfirmation(t *testing.T) {
	pool := remainingCLIDatabase(t)
	_, err := pool.Exec(t.Context(), `CREATE TABLE response_rules (LIKE public.response_rules INCLUDING ALL);
INSERT INTO response_rules(org_id,name,event_type,actions,source)
VALUES ('00000000-0000-0000-0000-000000000001','fixture-rule','process','[{"type":"tag"}]','declarative');`)
	if err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	query := dsn.Query()
	query.Set("search_path", pool.Config().ConnConfig.RuntimeParams["search_path"])
	dsn.RawQuery = query.Encode()
	args := []string{"--database-url", dsn.String(), "--org", "00000000-0000-0000-0000-000000000001", "--kind", "response"}
	if err := executeRemainingOutput(t.Context(), policyExportCRDsCmd(), &failingCommandOutput{}, args...); !errors.Is(err, errCommandOutputTest) {
		t.Fatalf("failed CRD stream returned success: %v", err)
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := executeRemainingOutput(t.Context(), policyExportCRDsCmd(), &failingCommandOutput{}, append(args, "--output", path)...); !errors.Is(err, errCommandOutputTest) {
		t.Fatalf("failed CRD confirmation returned success: %v", err)
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	data, err := root.ReadFile("rules.yaml")
	if err != nil || !strings.Contains(string(data), "fixture-rule") {
		t.Fatal("completed CRD artifact was lost after confirmation failed")
	}
}
