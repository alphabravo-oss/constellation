package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

const durableReport = `{"Controls":[{"version":"eks-1.4.0","tests":[{"results":[{"test_number":"1.1.99","test_desc":"Fixture evidence","status":"FAIL","actual_value":"<value>& evidence"}]}]}]}`

type executionFixture struct {
	mu                            sync.Mutex
	request                       *compliancepkg.BenchExecutionRequest
	claimFailures, resultFailures int
	claims, results               int
	claimKeys                     []string
	badReceipt                    bool
}

func (f *executionFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer fixture-token") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if cluster := r.URL.Query().Get("cluster_id"); cluster != "" && cluster != "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/claim") {
		f.serveClaim(w, r)
		return
	}
	f.serveResult(w, r)
}

func (f *executionFixture) serveClaim(w http.ResponseWriter, r *http.Request) {
	var claim compliancepkg.BenchExecutionClaim
	if json.NewDecoder(r.Body).Decode(&claim) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.claims++
	f.claimKeys = append(f.claimKeys, claim.ClaimKey)
	if f.request == nil {
		cluster := "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130"
		id := uuid.NewString()
		f.request = &compliancepkg.BenchExecutionRequest{ID: id, RequestKey: uuid.NewString(), ClusterID: &cluster, Profile: "kube-bench", Benchmark: "eks-1.4.0", Status: "running", Revision: "2", AttemptCount: 1, RequestedAt: time.Now().UTC(), ActiveAttempt: &compliancepkg.BenchExecutionAttempt{ID: uuid.NewString(), RequestID: id, ClusterID: cluster, RunnerID: claim.RunnerID, ClaimKey: claim.ClaimKey, Node: claim.Node, Number: 1, Status: "running", StartedAt: time.Now().UTC(), LeaseExpiresAt: time.Now().Add(10 * time.Minute).UTC()}}
	}
	if f.claimFailures > 0 {
		f.claimFailures--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"request": f.request})
}

func (f *executionFixture) serveResult(w http.ResponseWriter, r *http.Request) {
	var result compliancepkg.BenchExecutionResult
	if json.NewDecoder(r.Body).Decode(&result) != nil || f.request == nil || f.request.ActiveAttempt.ID != result.AttemptID {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.results++
	if result.Outcome == "report_ingested" {
		_, digest, err := compliancepkg.CanonicalBenchReport(result.Report)
		if err != nil || digest != result.ReportSHA256 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if f.request.Status == "running" {
		f.request.Status, f.request.ActiveAttempt.Status = "failed", "failed"
		if result.Outcome == "report_ingested" {
			f.request.Status, f.request.ActiveAttempt.Status = "succeeded", "succeeded"
			f.request.ActiveAttempt.Controls, _ = compliancepkg.ValidateBenchExecutionReport(result.Report)
			f.request.ActiveAttempt.RowsIngested = f.request.ActiveAttempt.Controls.Total
		}
		f.request.Revision = "3"
		now := time.Now().UTC()
		f.request.CompletedAt, f.request.ActiveAttempt.FinishedAt = &now, &now
		f.request.ActiveAttempt.Outcome, f.request.ActiveAttempt.ReportSHA256 = result.Outcome, result.ReportSHA256
	}
	if f.resultFailures > 0 {
		f.resultFailures--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if f.badReceipt {
		_ = json.NewEncoder(w).Encode(map[string]any{"request": map[string]any{"id": f.request.ID, "status": "succeeded"}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"request": f.request})
}

func newExecutionWorkerFixture(t *testing.T, f *executionFixture) (*executionWorker, *atomic.Int32) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	dir := t.TempDir() + "/private-state"
	spool, err := openExecutionSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spool.close)
	cfg := config{apiURL: server.URL, token: "fixture-token", clusterID: "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130", profile: "kube-bench", benchmark: "configured-pin", args: []string{"--json", "--benchmark=configured-pin"}, node: "fixture-node", runnerID: uuid.NewString(), spoolDir: dir}
	var executions atomic.Int32
	worker := &executionWorker{cfg: cfg, client: server.Client(), spool: spool, execute: func(_ context.Context, actual config) ([]byte, string) {
		executions.Add(1)
		if actual.benchmark != "eks-1.4.0" || strings.Join(actual.args, " ") != "--json --benchmark eks-1.4.0" {
			t.Errorf("execution did not honor reviewed benchmark: %+v", actual.args)
		}
		return []byte(durableReport), "report_ingested"
	}}
	return worker, &executions
}

func TestExecutionWorkerLostReceiptsDoNotRerun(t *testing.T) {
	f := &executionFixture{claimFailures: 1, resultFailures: 1}
	worker, executions := newExecutionWorkerFixture(t, f)
	if err := worker.step(t.Context()); err == nil || executions.Load() != 0 {
		t.Fatal("lost claim response executed an unreviewed request")
	}
	if err := worker.step(t.Context()); err == nil || executions.Load() != 1 {
		t.Fatal("result failure was not retained after one execution")
	}
	if err := worker.step(t.Context()); err != nil || executions.Load() != 1 {
		t.Fatalf("retry reran or failed confirmed result: %v", err)
	}
	if f.claims != 2 || f.claimKeys[0] != f.claimKeys[1] || f.results != 2 || f.request.ActiveAttempt.Controls.Fail != 1 {
		t.Fatal("claim/result recovery lost exact identity or source failure evidence")
	}
	if entry, err := worker.spool.load(executionScope(worker.cfg)); err != nil || entry != nil {
		t.Fatal("confirmed durable result not forgotten")
	}
}

func TestExecutionWorkerAssertsConfiguredClusterBeforeClaim(t *testing.T) {
	f := &executionFixture{}
	worker, executions := newExecutionWorkerFixture(t, f)
	worker.cfg.clusterID = uuid.NewString()
	if err := worker.step(t.Context()); err == nil || executions.Load() != 0 || f.claims != 0 || f.request != nil {
		t.Fatal("configured/token cluster mismatch consumed a different cluster's request")
	}
}

func TestExecutionWorkerRestartRefusesUncertainExecution(t *testing.T) {
	f := &executionFixture{resultFailures: 1}
	worker, executions := newExecutionWorkerFixture(t, f)
	claim := compliancepkg.BenchExecutionClaim{ClaimKey: uuid.NewString(), RunnerID: worker.cfg.runnerID, Node: worker.cfg.node}
	req, err := executionPost(t.Context(), worker.client, worker.cfg, "requests/claim", claim)
	if err != nil {
		t.Fatal(err)
	}
	entry := &executionSpoolEntry{Version: 1, Scope: executionScope(worker.cfg), Phase: "executing", Claim: claim, Request: *req}
	if err := worker.spool.save(entry); err != nil {
		t.Fatal(err)
	}
	if err := worker.step(t.Context()); err == nil || executions.Load() != 0 {
		t.Fatal("uncertain pre-crash process was rerun")
	}
	if err := worker.step(t.Context()); err != nil || executions.Load() != 0 || f.request.ActiveAttempt.Outcome != "interrupted" {
		t.Fatalf("interrupted result not durably confirmed: %v", err)
	}
}

func TestExecutionWorkerUnconfirmedReceiptAndTokenChange(t *testing.T) {
	f := &executionFixture{badReceipt: true}
	worker, executions := newExecutionWorkerFixture(t, f)
	if err := worker.step(t.Context()); err == nil || executions.Load() != 1 {
		t.Fatal("malformed receipt falsely completed execution")
	}
	worker.cfg.token = "fixture-token-rotated"
	if err := worker.step(t.Context()); err == nil || f.results != 1 {
		t.Fatal("pending result rebound to replacement credential")
	}
	worker.cfg.token = "fixture-token"
	f.badReceipt = false
	if err := worker.step(t.Context()); err != nil || executions.Load() != 1 {
		t.Fatalf("original result not recoverable: %v", err)
	}
}

func TestExecutionSpoolPrivateBoundedAndExclusive(t *testing.T) {
	dir := t.TempDir() + "/private"
	spool, err := openExecutionSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.close()
	if second, err := openExecutionSpool(dir); err == nil {
		second.close()
		t.Fatal("two workers can own one spool")
	}
	entry := &executionSpoolEntry{Version: 1, Scope: "owned", Phase: "claiming"}
	if err := spool.save(entry); err != nil {
		t.Fatal(err)
	}
	info, err := spool.root.Stat("execution.json")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("sensitive report state is not private")
	}
	entry.Result.Report = json.RawMessage(`"` + strings.Repeat("x", executionSpoolMax) + `"`)
	if err := spool.save(entry); err == nil {
		t.Fatal("unreloadable journal accepted")
	}
	if loaded, err := spool.load("owned"); err != nil || loaded.Result.Report != nil {
		t.Fatal("failed oversized write damaged durable prior entry")
	}
	entry.Result.Report = json.RawMessage(`"` + strings.Repeat("x", compliancepkg.BenchExecutionMaxReport-2) + `"`)
	if err := spool.save(entry); err != nil {
		t.Fatalf("maximum bounded report was not durable: %v", err)
	}
	if loaded, err := spool.load("owned"); err != nil || len(loaded.Result.Report) != compliancepkg.BenchExecutionMaxReport {
		t.Fatal("accepted maximum report did not survive reload")
	}
	if second, err := openExecutionSpool("relative-state"); err == nil {
		second.close()
		t.Fatal("relative spool directory accepted")
	}
}

func TestExecutionWorkerInvalidReportIsFailedWithoutSecurityClaim(t *testing.T) {
	f := &executionFixture{}
	worker, executions := newExecutionWorkerFixture(t, f)
	worker.execute = func(context.Context, config) ([]byte, string) {
		executions.Add(1)
		return []byte(`{"Controls":[]}`), "report_ingested"
	}
	if err := worker.step(t.Context()); err != nil || executions.Load() != 1 || f.request.Status != "failed" || f.request.ActiveAttempt.Outcome != "invalid_report" || f.request.ActiveAttempt.Controls.Total != 0 {
		t.Fatalf("empty report implied successful assessment: %v", err)
	}
}

type cancelClaimTransport struct {
	next   http.RoundTripper
	cancel context.CancelFunc
}

func (transport cancelClaimTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := transport.next.RoundTrip(r)
	if err == nil && strings.HasSuffix(r.URL.Path, "/claim") {
		response.Body = cancelClaimBody{ReadCloser: response.Body, cancel: transport.cancel}
	}
	return response, err
}

type cancelClaimBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body cancelClaimBody) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

func TestExecutionWorkerCancellationAfterClaimDoesNotExecute(t *testing.T) {
	f := &executionFixture{}
	worker, executions := newExecutionWorkerFixture(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	worker.client = &http.Client{Transport: cancelClaimTransport{next: http.DefaultTransport, cancel: cancel}}
	if err := worker.step(ctx); err == nil || executions.Load() != 0 {
		t.Fatal("canceled successful claim started benchmark")
	}
	worker.client = http.DefaultClient
	if err := worker.step(t.Context()); err != nil || executions.Load() != 0 || f.request.ActiveAttempt.Outcome != "interrupted" {
		t.Fatalf("canceled intent was rerun or lost on recovery: %v", err)
	}
}
