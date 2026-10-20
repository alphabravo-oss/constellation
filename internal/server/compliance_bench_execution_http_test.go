//go:build integration

package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler"
)

func TestBenchExecutionRegisteredHTTPAuthenticationAndResult(t *testing.T) {
	_, server, pool, signer, admin, auditor, org := newSysConfigTestServer(t)
	cluster := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'bench v2 HTTP')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	agent, tokenID, err := handler.IssueRuntimeAgentToken(t.Context(), pool, org, "durable bench HTTP", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO cluster_init_bundles(org_id,cluster_id,name,expires_at,runtime_agent_token_id,kek_fingerprint,contents_encrypted)VALUES($1,$2,$3,NOW()+INTERVAL '1 hour',$4,'test','\x00')`, org, cluster, uuid.NewString(), tokenID); err != nil {
		t.Fatal(err)
	}
	jwt := issueFor(t, signer, admin, org, 0)
	readOnly := issueFor(t, signer, auditor, org, 0)
	pat := seedCompliancePAT(t, pool, admin, "manage-policies")
	base := server.URL + "/api/v1/compliance/bench/requests?cluster_id=" + cluster.String()
	for _, tc := range []struct {
		token  string
		status int
	}{{jwt, http.StatusAccepted}, {pat, http.StatusAccepted}, {readOnly, http.StatusForbidden}, {agent, http.StatusUnauthorized}} {
		status, body := doJSON(t, http.MethodPost, base, tc.token, map[string]string{"request_key": uuid.NewString(), "profile": "kube-bench"})
		if status != tc.status {
			t.Fatalf("wrong user-route authorization %d %v", status, body)
		}
	}
	claimURL := server.URL + "/api/v1/agent/compliance/bench/requests/claim"
	claim := map[string]string{"claim_key": uuid.NewString(), "runner_id": uuid.NewString(), "node": "fixture-node"}
	assertBenchConfiguredClusterRejected(t, server.URL, agent, pool, org, claim)
	for _, user := range []string{jwt, pat} {
		if status, _ := doJSON(t, http.MethodPost, claimURL, user, claim); status != http.StatusUnauthorized {
			t.Fatal("user credential was granted bound-agent claim access")
		}
	}
	status, body := doJSON(t, http.MethodPost, claimURL, agent, claim)
	if status != http.StatusOK {
		t.Fatalf("bound agent failed to claim %d %v", status, body)
	}
	request, ok := body["request"].(map[string]any)
	if !ok || request["cluster_id"] != cluster.String() || request["status"] != "running" {
		t.Fatalf("claim lost exact bound cluster %v", body)
	}
	attempt := request["active_attempt"].(map[string]any)
	status, body = doJSON(t, http.MethodPost, server.URL+"/api/v1/agent/compliance/bench/requests/"+request["id"].(string)+"/result", agent, map[string]string{"attempt_id": attempt["id"].(string), "outcome": "exec_failed"})
	if status != http.StatusOK || body["request"].(map[string]any)["status"] != "failed" {
		t.Fatalf("execution failure was not durably terminal through real route %d %v", status, body)
	}
	if status, _ := doJSON(t, http.MethodGet, server.URL+"/api/v1/compliance/bench/requests/"+request["id"].(string), readOnly, nil); status != http.StatusOK {
		t.Fatal("read-only user cannot observe durable request")
	}
	if status, _ := doJSON(t, http.MethodPost, server.URL+"/api/v1/compliance/bench/requests/"+request["id"].(string)+"/retry", readOnly, map[string]string{"reviewed_revision": "2"}); status != http.StatusForbidden {
		t.Fatal("read-only user can retry a benchmark")
	}
}

func assertBenchConfiguredClusterRejected(t *testing.T, base, agent string, pool *pgxpool.Pool, org uuid.UUID, claim map[string]string) {
	t.Helper()
	path := base + "/api/v1/agent/compliance/bench/requests/claim?cluster_id=" + uuid.NewString()
	if status, _ := doJSON(t, http.MethodPost, path, agent, claim); status != http.StatusForbidden {
		t.Fatal("mismatched configured cluster consumed a request")
	}
	var attempts, queued int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM compliance_bench_attempts WHERE org_id=$1),(SELECT count(*) FROM compliance_bench_run_requests WHERE org_id=$1 AND protocol_version=2 AND status='queued')`, org).Scan(&attempts, &queued); err != nil || attempts != 0 || queued != 2 {
		t.Fatalf("mismatched cluster created attempt or consumed queue: attempts=%d queued=%d err=%v", attempts, queued, err)
	}
}
