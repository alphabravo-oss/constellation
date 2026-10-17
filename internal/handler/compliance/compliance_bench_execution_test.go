package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

const validExecutionReport = `{"Controls":[{"version":"eks-1.4.0","tests":[{"results":[{"test_number":"1.1.99","test_desc":"Source control","status":"FAIL","actual_value":"fixture"}]}]}]}`

func benchV2Call(t *testing.T, f *complianceAgentFixture, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	if token == "" {
		router.Post("/requests", f.service.CreateBenchRequest)
		router.Get("/requests", f.service.ListBenchRequests)
		router.Get("/requests/{id}", f.service.GetBenchRequest)
		router.Post("/requests/{id}/retry", f.service.RetryBenchRequest)
	} else {
		router.Use(handler.RuntimeAgentTokenMiddleware(f.database.Pool()))
		router.Post("/claim", f.service.ClaimBenchRequest)
		router.Post("/requests/{id}/heartbeat", f.service.HeartbeatBenchRequest)
		router.Post("/requests/{id}/result", f.service.ResultBenchRequest)
	}
	r := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(raw))
	if token == "" {
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: f.org, UserID: f.user}))
	} else {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func benchV2Request(t *testing.T, w *httptest.ResponseRecorder, status int) compliancepkg.BenchExecutionRequest {
	t.Helper()
	var result struct {
		Request compliancepkg.BenchExecutionRequest `json:"request"`
	}
	if w.Code != status || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Request.ID == "" {
		t.Fatalf("unexpected benchmark response %d %s", w.Code, w.Body.String())
	}
	return result.Request
}

func createBenchV2(t *testing.T, f *complianceAgentFixture, cluster string) compliancepkg.BenchExecutionRequest {
	t.Helper()
	query := ""
	if cluster != "" {
		query = "?cluster_id=" + cluster
	}
	return benchV2Request(t, benchV2Call(t, f, http.MethodPost, "/requests"+query, "", benchCreateInput{RequestKey: uuid.NewString(), Profile: "kube-bench"}), http.StatusAccepted)
}

func claimBenchV2(t *testing.T, f *complianceAgentFixture) compliancepkg.BenchExecutionRequest {
	t.Helper()
	return benchV2Request(t, benchV2Call(t, f, http.MethodPost, "/claim", f.token, compliancepkg.BenchExecutionClaim{ClaimKey: uuid.NewString(), RunnerID: uuid.NewString(), Node: "test-node"}), http.StatusOK)
}

func successfulBenchResult(t *testing.T, attempt string) compliancepkg.BenchExecutionResult {
	t.Helper()
	raw, digest, err := compliancepkg.CanonicalBenchReport([]byte(validExecutionReport))
	if err != nil {
		t.Fatal(err)
	}
	return compliancepkg.BenchExecutionResult{AttemptID: attempt, Outcome: "report_ingested", ReportSHA256: digest, Report: raw}
}

func TestBenchExecutionSuccessAndIdempotency(t *testing.T) {
	f := newComplianceAgentFixture(t)
	input := benchCreateInput{RequestKey: uuid.NewString(), Profile: "kubebench", Benchmark: " eks-1.4.0 "}
	path := "/requests?cluster_id=" + f.cluster.String()
	first := benchV2Request(t, benchV2Call(t, f, http.MethodPost, path, "", input), http.StatusAccepted)
	second := benchV2Request(t, benchV2Call(t, f, http.MethodPost, path, "", input), http.StatusAccepted)
	if first.ID != second.ID || first.Status != "queued" {
		t.Fatal("create replay queued a different request")
	}
	input.Benchmark = "gke-1.6.0"
	if w := benchV2Call(t, f, http.MethodPost, path, "", input); w.Code != http.StatusConflict {
		t.Fatalf("conflicting create accepted %d %s", w.Code, w.Body.String())
	}
	if w := f.call(t, "bench/claim", "", f.token, true); w.Code != http.StatusNoContent {
		t.Fatal("legacy worker stole durable queued request")
	}
	claim := compliancepkg.BenchExecutionClaim{ClaimKey: uuid.NewString(), RunnerID: uuid.NewString(), Node: "test-node"}
	a := benchV2Request(t, benchV2Call(t, f, http.MethodPost, "/claim", f.token, claim), http.StatusOK)
	b := benchV2Request(t, benchV2Call(t, f, http.MethodPost, "/claim", f.token, claim), http.StatusOK)
	if a.ActiveAttempt.ID != b.ActiveAttempt.ID || b.AttemptCount != 1 {
		t.Fatal("lost claim receipt created a second execution")
	}
	assertBenchResultIdempotency(t, f, a)
}

func assertBenchResultIdempotency(t *testing.T, f *complianceAgentFixture, claimed compliancepkg.BenchExecutionRequest) {
	t.Helper()
	path := "/requests/" + claimed.ID + "/result"
	input := successfulBenchResult(t, claimed.ActiveAttempt.ID)
	done := benchV2Request(t, benchV2Call(t, f, http.MethodPost, path, f.token, input), http.StatusOK)
	if done.Status != "succeeded" || done.ActiveAttempt.Controls.Fail != 1 || done.ActiveAttempt.RowsIngested < 1 {
		t.Fatalf("execution confused security failure with execution failure: %+v", done)
	}
	var before, after string
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT evaluated_at::text FROM compliance_checks WHERE org_id=$1 LIMIT 1`, f.org).Scan(&before); err != nil {
		t.Fatal(err)
	}
	replay := benchV2Request(t, benchV2Call(t, f, http.MethodPost, path, f.token, input), http.StatusOK)
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT evaluated_at::text FROM compliance_checks WHERE org_id=$1 LIMIT 1`, f.org).Scan(&after); err != nil || before != after || done.Revision != replay.Revision {
		t.Fatalf("result replay refreshed evidence or revision: %v", err)
	}
	var audits int
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='compliance.bench.v2.completed'`, f.org).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("completion audit replayed %d %v", audits, err)
	}
	input.ReportSHA256 = strings.Repeat("0", 64)
	if w := benchV2Call(t, f, http.MethodPost, path, f.token, input); w.Code != http.StatusBadRequest {
		t.Fatal("tampered digest accepted")
	}
}

func TestBenchExecutionLeaseAndReviewedRetries(t *testing.T) {
	f := newComplianceAgentFixture(t)
	req := createBenchV2(t, f, "")
	for number := 1; number <= 3; number++ {
		claimed := claimBenchV2(t, f)
		if claimed.ID != req.ID || claimed.ClusterID == nil || *claimed.ClusterID != f.cluster.String() || claimed.RequestedClusterID != nil || claimed.AttemptCount != number {
			t.Fatalf("orgwide claim lost exact execution identity %+v", claimed)
		}
		if _, err := f.database.Pool().Exec(t.Context(), `UPDATE compliance_bench_attempts SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1`, claimed.ActiveAttempt.ID); err != nil {
			t.Fatal(err)
		}
		observed := benchV2Request(t, benchV2Call(t, f, http.MethodGet, "/requests/"+req.ID, "", nil), http.StatusOK)
		if observed.Status != "interrupted" || observed.ActiveAttempt.Status != "interrupted" {
			t.Fatal("expired lease still shown running")
		}
		assertExpiredBenchAttempt(t, f, claimed)
		path := "/requests/" + req.ID + "/retry"
		if w := benchV2Call(t, f, http.MethodPost, path, "", map[string]string{"reviewed_revision": "1"}); w.Code != http.StatusConflict {
			t.Fatal("stale retry revision accepted")
		}
		w := benchV2Call(t, f, http.MethodPost, path, "", map[string]string{"reviewed_revision": observed.Revision})
		if number == 3 {
			if w.Code != http.StatusConflict {
				t.Fatal("more than three attempts accepted")
			}
		} else {
			_ = benchV2Request(t, w, http.StatusAccepted)
		}
	}
}

func assertExpiredBenchAttempt(t *testing.T, f *complianceAgentFixture, req compliancepkg.BenchExecutionRequest) {
	t.Helper()
	for _, action := range []string{"heartbeat", "result"} {
		body := any(map[string]string{"attempt_id": req.ActiveAttempt.ID})
		if action == "result" {
			body = successfulBenchResult(t, req.ActiveAttempt.ID)
		}
		if w := benchV2Call(t, f, http.MethodPost, "/requests/"+req.ID+"/"+action, f.token, body); w.Code != http.StatusConflict {
			t.Fatalf("expired %s accepted %d %s", action, w.Code, w.Body.String())
		}
	}
}

func TestBenchExecutionConcurrentClaim(t *testing.T) {
	f := newComplianceAgentFixture(t)
	createBenchV2(t, f, f.cluster.String())
	claim := compliancepkg.BenchExecutionClaim{ClaimKey: uuid.NewString(), RunnerID: uuid.NewString(), Node: "test-node"}
	results := make(chan compliancepkg.BenchExecutionRequest, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			results <- benchV2Request(t, benchV2Call(t, f, http.MethodPost, "/claim", f.token, claim), http.StatusOK)
		})
	}
	wg.Wait()
	close(results)
	var id string
	for req := range results {
		if id != "" && id != req.ActiveAttempt.ID {
			t.Fatal("concurrent claim retry executed twice")
		}
		id = req.ActiveAttempt.ID
	}
}

func TestBenchExecutionScopesMalformedAndRollback(t *testing.T) {
	f := newComplianceAgentFixture(t)
	if w := benchV2Call(t, f, http.MethodPost, "/requests?cluster_id="+f.foreign.String(), "", benchCreateInput{RequestKey: uuid.NewString()}); w.Code != http.StatusNotFound {
		t.Fatal("foreign create accepted")
	}
	if w := benchV2Call(t, f, http.MethodPost, "/requests", "", benchCreateInput{RequestKey: uuid.NewString(), Profile: "docker-bench"}); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "unsupported_profile") {
		t.Fatal("unsupported docker execution advertised")
	}
	createBenchV2(t, f, f.cluster.String())
	claimed := claimBenchV2(t, f)
	if w := benchV2Call(t, f, http.MethodPost, "/requests/"+claimed.ID+"/heartbeat?cluster_id="+f.sibling.String(), f.token, map[string]string{"attempt_id": claimed.ActiveAttempt.ID}); w.Code != http.StatusForbidden {
		t.Fatal("sibling cluster heartbeat accepted")
	}
	assertMalformedBenchResults(t, f, claimed)
	installBenchCompletionAuditFailure(t, f)
	w := benchV2Call(t, f, http.MethodPost, "/requests/"+claimed.ID+"/result", f.token, successfulBenchResult(t, claimed.ActiveAttempt.ID))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "private") {
		t.Fatalf("audit failure confirmed or leaked %d %s", w.Code, w.Body.String())
	}
	var status string
	var count int
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT status,(SELECT count(*) FROM compliance_checks WHERE org_id=$2) FROM compliance_bench_run_requests WHERE id=$1`, claimed.ID, f.org).Scan(&status, &count); err != nil || status != "running" || count != 0 {
		t.Fatalf("partial completion %s %d %v", status, count, err)
	}
}

func assertMalformedBenchResults(t *testing.T, f *complianceAgentFixture, req compliancepkg.BenchExecutionRequest) {
	t.Helper()
	for _, report := range []string{`{}`, `{"Controls":[]}`, `{"Controls":[{"tests":[{"results":[{"status":"PASS"}]}]}]}`} {
		raw, digest, err := compliancepkg.CanonicalBenchReport([]byte(report))
		if err != nil {
			t.Fatal(err)
		}
		w := benchV2Call(t, f, http.MethodPost, "/requests/"+req.ID+"/result", f.token, compliancepkg.BenchExecutionResult{AttemptID: req.ActiveAttempt.ID, Outcome: "report_ingested", Report: raw, ReportSHA256: digest})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("empty/incomplete report accepted %d %s", w.Code, w.Body.String())
		}
	}
}

func installBenchCompletionAuditFailure(t *testing.T, f *complianceAgentFixture) {
	t.Helper()
	name := "bench_result_" + strings.ReplaceAll(f.org.String(), "-", "")
	query := `CREATE FUNCTION ` + name + `()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.org_id='` + f.org.String() + `'::uuid AND NEW.action='compliance.bench.v2.completed' THEN RAISE EXCEPTION 'private completion failure';END IF;RETURN NEW;END$$;CREATE TRIGGER ` + name + ` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION ` + name + `()`
	if _, err := f.database.Pool().Exec(t.Context(), query); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.database.Pool().Exec(context.WithoutCancel(t.Context()), `DROP TRIGGER IF EXISTS `+name+` ON audit_events;DROP FUNCTION IF EXISTS `+name+`()`)
	})
}

func TestBenchExecutionTenantTokenAndAttemptFences(t *testing.T) {
	f := newComplianceAgentFixture(t)
	createBenchV2(t, f, f.cluster.String())
	req := claimBenchV2(t, f)
	other, tokenID, err := handler.IssueRuntimeAgentToken(t.Context(), f.database.Pool(), f.org, "other execution credential", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.bind(t, tokenID, f.org, f.cluster)
	body := successfulBenchResult(t, req.ActiveAttempt.ID)
	path := "/requests/" + req.ID + "/result"
	if w := benchV2Call(t, f, http.MethodPost, path, other, body); w.Code != http.StatusForbidden {
		t.Fatal("replacement cluster credential completed another token's attempt")
	}
	body.AttemptID = uuid.NewString()
	if w := benchV2Call(t, f, http.MethodPost, path, f.token, body); w.Code != http.StatusConflict {
		t.Fatal("foreign attempt identity completed request")
	}
	foreign := newComplianceAgentFixture(t)
	if w := benchV2Call(t, foreign, http.MethodGet, "/requests/"+req.ID, "", nil); w.Code != http.StatusNotFound {
		t.Fatal("foreign tenant read request")
	}
	if w := benchV2Call(t, foreign, http.MethodPost, path, foreign.token, successfulBenchResult(t, req.ActiveAttempt.ID)); w.Code != http.StatusNotFound {
		t.Fatal("foreign tenant completed request")
	}
	if _, err := f.database.Pool().Exec(t.Context(), `UPDATE clusters SET org_id=$1 WHERE id=$2`, f.foreignOrg, f.cluster); err != nil {
		t.Fatal(err)
	}
	if w := benchV2Call(t, f, http.MethodPost, path, f.token, successfulBenchResult(t, req.ActiveAttempt.ID)); w.Code != http.StatusForbidden {
		t.Fatal("changed cluster ownership allowed completion")
	}
}

func TestBenchExecutionPagedReadsDoNotIncludeLegacyOrSibling(t *testing.T) {
	f := newComplianceAgentFixture(t)
	_, err := f.database.Pool().Exec(t.Context(), `INSERT INTO compliance_bench_run_requests(org_id,cluster_id,requested_cluster_id,protocol_version,status,request_key,request_hash)
SELECT $1,$2,$2,2,'queued',gen_random_uuid(),'fixture' FROM generate_series(1,205)`, f.org, f.cluster)
	if err != nil {
		t.Fatal(err)
	}
	f.queue(t, f.org, &f.cluster)
	createBenchV2(t, f, f.sibling.String())
	w := benchV2Call(t, f, http.MethodGet, "/requests?limit=100&offset=200&cluster_id="+f.cluster.String(), "", nil)
	var result struct {
		Requests []compliancepkg.BenchExecutionRequest `json:"requests"`
		Total    int                                   `json:"total"`
		HasMore  bool                                  `json:"has_more"`
		Legacy   bool                                  `json:"legacy_requests_included"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Total != 205 || len(result.Requests) != 5 || result.HasMore || result.Legacy {
		t.Fatalf("wrong continuation or source scope %d %s", w.Code, w.Body.String())
	}
}

func TestBenchExecutionExpiryUsesCurrentClockAfterTransactionWait(t *testing.T) {
	f := newComplianceAgentFixture(t)
	createBenchV2(t, f, f.cluster.String())
	req := claimBenchV2(t, f)
	tx, err := f.database.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackBenchRequest(t.Context(), tx)
	if _, err := tx.Exec(t.Context(), `UPDATE compliance_bench_attempts SET lease_expires_at=clock_timestamp()+INTERVAL '30 milliseconds' WHERE id=$1`, req.ActiveAttempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SELECT pg_sleep(0.06)`); err != nil {
		t.Fatal(err)
	}
	observed, err := loadBenchRequest(t.Context(), tx, f.org, uuid.MustParse(req.ID), true)
	if err != nil || observed.Status != "interrupted" || observed.ActiveAttempt.Status != "interrupted" {
		t.Fatalf("transaction-start timestamp revived expired execution %+v %v", observed, err)
	}
}

type benchClaimBarrierTx struct {
	pgx.Tx
	ready   chan struct{}
	release chan struct{}
}

func (tx benchClaimBarrierTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "FOR UPDATE OF r") {
		close(tx.ready)
		select {
		case <-ctx.Done():
		case <-tx.release:
		}
	}
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func TestBenchExecutionRepeatClaimRechecksTerminalAfterLock(t *testing.T) {
	f := newComplianceAgentFixture(t)
	createBenchV2(t, f, f.cluster.String())
	input := compliancepkg.BenchExecutionClaim{ClaimKey: uuid.NewString(), RunnerID: uuid.NewString(), Node: "fixture-node"}
	req := benchV2Request(t, benchV2Call(t, f, http.MethodPost, "/claim", f.token, input), http.StatusOK)
	tx, err := f.database.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackBenchRequest(t.Context(), tx)
	barrier := benchClaimBarrierTx{Tx: tx, ready: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-barrier.release:
		default:
			close(barrier.release)
		}
	}()
	result := make(chan error, 1)
	go func() {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/claim", nil)
		out, err := repeatBenchClaim(r, barrier, complianceWriteScope{orgID: f.org, clusterID: &f.cluster, agentID: &f.tokenID}, input, req.ActiveAttempt.ID)
		if err == nil && out.ID != "" {
			err = errors.New("terminal execution returned as an active claim")
		}
		result <- err
	}()
	<-barrier.ready
	benchV2Request(t, benchV2Call(t, f, http.MethodPost, "/requests/"+req.ID+"/result", f.token, compliancepkg.BenchExecutionResult{AttemptID: req.ActiveAttempt.ID, Outcome: "exec_failed"}), http.StatusOK)
	close(barrier.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
