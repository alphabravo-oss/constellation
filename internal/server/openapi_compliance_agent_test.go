package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler"
)

func TestComplianceAgentRoutesRequireSeparateAuthentication(t *testing.T) {
	server, err := newSpecServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/agent/compliance/ingest", "/api/v1/agent/compliance/bench/claim"} {
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("missing agentauth: %s code%d", path, w.Code)
		}
	}
}

func TestComplianceRegisteredRoutesPreserveJWTAndPAT(t *testing.T) {
	_, server, pool, signer, admin, auditor, org := newSysConfigTestServer(t)
	cluster := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'bench route')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	agent, id, err := handler.IssueRuntimeAgentToken(t.Context(), pool, org, "bench route", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO cluster_init_bundles(org_id,cluster_id,name,expires_at,runtime_agent_token_id,kek_fingerprint,contents_encrypted)VALUES($1,$2,$3,NOW()+INTERVAL '1 hour',$4,'test','\x00')`, org, cluster, uuid.NewString(), id); err != nil {
		t.Fatal(err)
	}
	jwt := issueFor(t, signer, admin, org, 0)
	readOnlyJWT := issueFor(t, signer, auditor, org, 0)
	allowedPAT := seedCompliancePAT(t, pool, admin, "manage-policies")
	readPAT := seedCompliancePAT(t, pool, admin, "read-findings")
	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{"JWT", jwt, http.StatusAccepted}, {"PAT", allowedPAT, http.StatusAccepted},
		{"Auditor", readOnlyJWT, http.StatusForbidden}, {"read-only PAT", readPAT, http.StatusForbidden},
		{"agent cannot author", agent, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertComplianceUserAuthorization(t, server.URL, cluster, tc.token, tc.want)
		})
	}
	for _, token := range []string{jwt, allowedPAT} {
		status, body := doJSON(t, http.MethodPost, server.URL+"/api/v1/agent/compliance/bench/claim", token, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("usercredential accepted on agentroute %d %v", status, body)
		}
	}
	if status, body := doJSON(t, http.MethodPost, server.URL+"/api/v1/compliance/bench/run?cluster_id="+cluster.String(), jwt, nil); status != http.StatusAccepted {
		t.Fatalf("prepare owned agent task %d %v", status, body)
	}
	status, body := doJSON(t, http.MethodPost, server.URL+"/api/v1/agent/compliance/bench/claim", agent, nil)
	if status != http.StatusOK {
		t.Fatalf("bound agent could not claim %d %v", status, body)
	}
	request, ok := body["request"].(map[string]any)
	if !ok || request["cluster_id"] != cluster.String() {
		t.Fatalf("claim not exactcluster %v", body)
	}
}

func seedCompliancePAT(t *testing.T, pool *pgxpool.Pool, user uuid.UUID, scope string) string {
	t.Helper()
	raw, hash := mintTestPAT(t)
	scopes := `["` + scope + `"]`
	if _, err := pool.Exec(t.Context(), `INSERT INTO api_tokens(id,user_id,name,token_hash,scopes,status)VALUES($1,$2,'bench scope',$3,$4::jsonb,'active')`, uuid.New(), user, hash, scopes); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOpenAPIComplianceAgentScopeContract(t *testing.T) {
	raw, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"ingest", "bench/claim"} {
		operation := complianceSpecOperation(t, spec.Paths["/api/v1/agent/compliance/"+suffix]["post"])
		if len(operation.Security) != 1 || operation.Security[0]["runtimeAgent"] == nil {
			t.Fatalf("agentauth not documented for %s", suffix)
		}
		for _, status := range []string{"200", "400", "401", "403", "500"} {
			if operation.Responses[status] == nil {
				t.Fatalf("%s missing %s", suffix, status)
			}
		}
		if !strings.Contains(operation.Description, "server resolves an owned cluster") {
			t.Fatalf("scope qualification missing %s", suffix)
		}
	}
	claim := complianceSpecOperation(t, spec.Paths["/api/v1/agent/compliance/bench/claim"]["post"])
	if claim.Responses["204"] == nil || !strings.Contains(claim.Description, "atomically bound") {
		t.Fatal("claim empty/binding semantics missing")
	}
	for _, suffix := range []string{"ingest", "bench/run", "bench/claim"} {
		if complianceSpecOperation(t, spec.Paths["/api/v1/compliance/"+suffix]["post"]).Responses["404"] == nil {
			t.Fatalf("legacyownership not documented %s", suffix)
		}
	}
}

type complianceAgentOperation struct {
	Description string           `json:"description"`
	Security    []map[string]any `json:"security"`
	Responses   map[string]any   `json:"responses"`
}

func complianceSpecOperation(t *testing.T, raw json.RawMessage) complianceAgentOperation {
	t.Helper()
	var operation complianceAgentOperation
	if err := json.Unmarshal(raw, &operation); err != nil {
		t.Fatal(err)
	}
	return operation
}

func assertComplianceUserAuthorization(t *testing.T, base string, cluster uuid.UUID, token string, want int) {
	t.Helper()
	const report = `{"Controls":[{"id":"1","text":"Master Node","tests":[{"section":"1.2","desc":"API Server","results":[{"test_number":"1.2.22","test_desc":"Ensure audit policy file is set","status":"FAIL","actual_value":"audit policy missing","scored":true}]}]}]}`
	var payload any
	if err := json.Unmarshal([]byte(report), &payload); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"ingest", "bench/run", "bench/claim"} {
		expected := want
		var body any
		if action == "ingest" {
			body = payload
		}
		if want == http.StatusAccepted && action != "bench/run" {
			expected = http.StatusOK
		}
		status, response := doJSON(t, http.MethodPost, base+"/api/v1/compliance/"+action+"?cluster_id="+cluster.String(), token, body)
		if status != expected {
			t.Fatalf("%s status%d want%d body%v", action, status, expected, response)
		}
	}
}
