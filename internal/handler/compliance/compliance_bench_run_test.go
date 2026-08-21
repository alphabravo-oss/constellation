package compliance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// TestBenchRun_EnqueueAndClaim is the CMP-RUN-31 regression: RunBench writes a
// pending request row (the on-demand trigger), and ClaimBenchRun atomically hands
// it to the runner exactly once, marking it claimed.
func TestBenchRun_EnqueueAndClaim(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := t.Context()

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'CMP Run Org')`, orgID, "cmp-run-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'CMP Run')`, userID, orgID, "cmp-run-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'cluster-run')`, clusterID, orgID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	h := NewCompliance(d, audit.New(pool))
	subj := authctx.Subject{UserID: userID, OrgID: orgID}

	// Enqueue an on-demand kube-bench run scoped to the cluster.
	runReq := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/bench/run?profile=kube-bench&cluster_id="+clusterID.String(), nil)
	runReq = runReq.WithContext(authctx.WithSubject(runReq.Context(), subj))
	runResp := httptest.NewRecorder()
	h.RunBench(runResp, runReq)
	if runResp.Code != http.StatusAccepted {
		t.Fatalf("RunBench status %d: %s", runResp.Code, runResp.Body.String())
	}

	// The expected row exists and is pending.
	var reqID uuid.UUID
	var status, profile string
	if err := pool.QueryRow(ctx, `
SELECT id, status, profile FROM compliance_bench_run_requests
 WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&reqID, &status, &profile); err != nil {
		t.Fatalf("select request row: %v", err)
	}
	if status != "pending" || profile != "kube-bench" {
		t.Fatalf("row status=%q profile=%q, want pending/kube-bench", status, profile)
	}

	// The runner claims it: 200 with the request, and it flips to claimed.
	claimReq := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/bench/claim?profile=kube-bench&cluster_id="+clusterID.String(), nil)
	claimReq = claimReq.WithContext(authctx.WithSubject(claimReq.Context(), subj))
	claimResp := httptest.NewRecorder()
	h.ClaimBenchRun(claimResp, claimReq)
	if claimResp.Code != http.StatusOK {
		t.Fatalf("ClaimBenchRun status %d: %s", claimResp.Code, claimResp.Body.String())
	}
	var claimed struct {
		Request BenchRunRequest `json:"request"`
	}
	if err := json.Unmarshal(claimResp.Body.Bytes(), &claimed); err != nil {
		t.Fatalf("decode claim: %v", err)
	}
	if claimed.Request.ID != reqID.String() {
		t.Fatalf("claimed id=%q, want %q", claimed.Request.ID, reqID)
	}
	if claimed.Request.Status != "claimed" {
		t.Fatalf("claimed status=%q, want claimed", claimed.Request.Status)
	}

	// The queue is now empty: a second claim returns 204.
	claim2 := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/bench/claim?profile=kube-bench&cluster_id="+clusterID.String(), nil)
	claim2 = claim2.WithContext(authctx.WithSubject(claim2.Context(), subj))
	claim2Resp := httptest.NewRecorder()
	h.ClaimBenchRun(claim2Resp, claim2)
	if claim2Resp.Code != http.StatusNoContent {
		t.Fatalf("second ClaimBenchRun status %d, want 204: %s", claim2Resp.Code, claim2Resp.Body.String())
	}

	// A docker-bench runner must NOT pick up the kube-bench request.
	if _, err := pool.Exec(ctx, `UPDATE compliance_bench_run_requests SET status='pending', claimed_at=NULL WHERE id=$1`, reqID); err != nil {
		t.Fatalf("reset row: %v", err)
	}
	dockerClaim := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/bench/claim?profile=docker-bench&cluster_id="+clusterID.String(), nil)
	dockerClaim = dockerClaim.WithContext(authctx.WithSubject(dockerClaim.Context(), subj))
	dockerResp := httptest.NewRecorder()
	h.ClaimBenchRun(dockerResp, dockerClaim)
	if dockerResp.Code != http.StatusNoContent {
		t.Fatalf("docker-bench claim of a kube-bench request status %d, want 204", dockerResp.Code)
	}
}
