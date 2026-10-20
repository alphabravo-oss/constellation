//go:build integration

package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type complianceAgentFixture struct {
	database                                         *db.DB
	service                                          *Compliance
	org, foreignOrg, cluster, sibling, foreign, user uuid.UUID
	token                                            string
	tokenID                                          uuid.UUID
}

func newComplianceAgentFixture(t *testing.T) *complianceAgentFixture {
	t.Helper()
	f := &complianceAgentFixture{database: openTestDB(t), org: uuid.New(), foreignOrg: uuid.New(), cluster: uuid.New(), sibling: uuid.New(), foreign: uuid.New(), user: uuid.New()}
	t.Cleanup(f.database.Close)
	pool := f.database.Pool()
	for _, id := range []uuid.UUID{f.org, f.foreignOrg} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name)VALUES($1,$2,$2)`, id, "bench-scope-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(t.Context(), `DELETE FROM orgs WHERE id IN($1,$2)`, f.org, f.foreignOrg) })
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'own'),($3,$2,'sibling'),($4,$5,'foreign')`, f.cluster, f.org, f.sibling, f.foreign, f.foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,org_id,email,display_name)VALUES($1,$2,$3,'bench scope')`, f.user, f.org, f.user.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	var err error
	f.token, f.tokenID, err = handler.IssueRuntimeAgentToken(t.Context(), pool, f.org, "bench scope", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.bind(t, f.tokenID, f.org, f.cluster)
	f.service = NewCompliance(f.database, audit.New(pool))
	return f
}
func (f *complianceAgentFixture) bind(t *testing.T, token, org, cluster uuid.UUID) {
	t.Helper()
	_, err := f.database.Pool().Exec(t.Context(), `INSERT INTO cluster_init_bundles(org_id,cluster_id,name,expires_at,runtime_agent_token_id,kek_fingerprint,contents_encrypted)VALUES($1,$2,$3,NOW()+INTERVAL '1 hour',$4,'test','\x00')`, org, cluster, uuid.NewString(), token)
	if err != nil {
		t.Fatal(err)
	}
}
func (f *complianceAgentFixture) call(t *testing.T, action, query, token string, agent bool) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/v1/compliance/" + action + query
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewBufferString(kbClusterSampleJSON))
	w := httptest.NewRecorder()
	var endpoint http.HandlerFunc
	switch action {
	case "ingest":
		endpoint = f.service.Ingest
		if agent {
			endpoint = f.service.AgentIngest
		}
	case "bench/run":
		endpoint = f.service.RunBench
	case "bench/claim":
		endpoint = f.service.ClaimBenchRun
		if agent {
			endpoint = f.service.AgentClaimBenchRun
		}
	default:
		t.Fatal("unknown test operation")
	}
	if agent {
		r.Header.Set("Authorization", "Bearer "+token)
		handler.RuntimeAgentTokenMiddleware(f.database.Pool())(endpoint).ServeHTTP(w, r)
	} else {
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: f.org, UserID: f.user}))
		endpoint(w, r)
	}
	return w
}
func (f *complianceAgentFixture) queue(t *testing.T, org uuid.UUID, cluster *uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.database.Pool().QueryRow(t.Context(), `INSERT INTO compliance_bench_run_requests(org_id,cluster_id,profile)VALUES($1,$2,'kube-bench')RETURNING id`, org, cluster).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestComplianceUserWritesRequireOwnedCluster(t *testing.T) {
	f := newComplianceAgentFixture(t)
	for _, action := range []string{"ingest", "bench/run", "bench/claim"} {
		t.Run(action, func(t *testing.T) {
			for _, cluster := range []uuid.UUID{f.foreign, uuid.New()} {
				w := f.call(t, action, "?cluster_id="+cluster.String(), "", false)
				if w.Code != http.StatusNotFound {
					t.Fatalf("foreign/unknown %s=%d %s", action, w.Code, w.Body.String())
				}
			}
			for _, query := range []string{"?cluster_id=%zz", "?cluster_id=" + f.cluster.String() + "&cluster_id=" + f.foreign.String()} {
				if w := f.call(t, action, query, "", false); w.Code != http.StatusBadRequest {
					t.Fatalf("invalidselector %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
	var checks, requests int
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT (SELECT count(*) FROM compliance_checks WHERE org_id=$1),(SELECT count(*) FROM compliance_bench_run_requests WHERE org_id=$1)`, f.org).Scan(&checks, &requests); err != nil || checks != 0 || requests != 0 {
		t.Fatalf("refused writes persisted: checks%d requests%d err%v", checks, requests, err)
	}
}

func TestComplianceAgentIngestBindsExactOwnedCluster(t *testing.T) {
	f := newComplianceAgentFixture(t)
	if w := f.call(t, "ingest", "?profile=kube-bench", f.token, true); w.Code != http.StatusOK {
		t.Fatalf("bound report %d %s", w.Code, w.Body.String())
	}
	for _, cluster := range []uuid.UUID{f.sibling, f.foreign, uuid.New()} {
		if w := f.call(t, "ingest", "?cluster_id="+cluster.String(), f.token, true); w.Code != http.StatusForbidden {
			t.Fatalf("bound override %d %s", w.Code, w.Body.String())
		}
	}
	var total, own int
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT count(*),count(*)FILTER(WHERE cluster_id=$2)FROM compliance_checks WHERE org_id=$1`, f.org, f.cluster).Scan(&total, &own); err != nil || total == 0 || own != total {
		t.Fatalf("wrong scope total%d own%d err%v", total, own, err)
	}
}

func TestComplianceAgentRejectsUnresolvedAndConflictingBinding(t *testing.T) {
	for _, binding := range []string{"unbound multi cluster", "sibling conflict", "foreign bundle", "foreign cluster"} {
		t.Run(binding, func(t *testing.T) {
			f := newComplianceAgentFixture(t)
			token, id, err := handler.IssueRuntimeAgentToken(t.Context(), f.database.Pool(), f.org, "bad binding", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			switch binding {
			case "sibling conflict":
				f.bind(t, id, f.org, f.cluster)
				f.bind(t, id, f.org, f.sibling)
			case "foreign bundle":
				f.bind(t, id, f.foreignOrg, f.foreign)
			case "foreign cluster":
				f.bind(t, id, f.org, f.foreign)
			}
			for _, action := range []string{"ingest", "bench/claim"} {
				if w := f.call(t, action, "", token, true); w.Code != http.StatusForbidden {
					t.Fatalf("badbinding %s=%d %s", action, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestComplianceAgentClaimBindsOrgWideAndExcludesOtherTasks(t *testing.T) {
	f := newComplianceAgentFixture(t)
	sibling := f.queue(t, f.org, &f.sibling)
	foreign := f.queue(t, f.foreignOrg, &f.foreign)
	// Old bad rows must not leak through an org-wide legacy selector either.
	misattributed := f.queue(t, f.org, &f.foreign)
	inherited := f.queue(t, f.org, nil)
	own := f.queue(t, f.org, &f.cluster)
	for _, expected := range []uuid.UUID{inherited, own} {
		w := f.call(t, "bench/claim", "?profile=kube-bench", f.token, true)
		var envelope struct {
			Request BenchRunRequest `json:"request"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || w.Code != http.StatusOK || envelope.Request.ID != expected.String() || envelope.Request.ClusterID != f.cluster.String() {
			t.Fatalf("badclaim %d %s err%v", w.Code, w.Body.String(), err)
		}
	}
	if w := f.call(t, "bench/claim", "", f.token, true); w.Code != http.StatusNoContent {
		t.Fatalf("crossscope task claimed %d %s", w.Code, w.Body.String())
	}
	assertBenchTasksPending(t, f, []uuid.UUID{sibling, foreign, misattributed})
	var bound uuid.UUID
	var count int
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT cluster_id FROM compliance_bench_run_requests WHERE id=$1`, inherited).Scan(&bound); err != nil || bound != f.cluster {
		t.Fatalf("orgwide not persistently bound %s %v", bound, err)
	}
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='compliance.bench.claimed' AND target_id=$2 AND before->>'org_wide'='true' AND after->>'cluster_id'=$3`, f.org, inherited.String(), f.cluster.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("boundclaim not traceable count%d err%v", count, err)
	}
}
func assertBenchTasksPending(t *testing.T, f *complianceAgentFixture, ids []uuid.UUID) {
	t.Helper()
	for _, id := range ids {
		var status string
		if err := f.database.Pool().QueryRow(t.Context(), `SELECT status FROM compliance_bench_run_requests WHERE id=$1`, id).Scan(&status); err != nil || status != "pending" {
			t.Fatalf("foreign/sibling task mutated %s %v", status, err)
		}
	}
}
func TestComplianceLegacyUserScopeStillWorks(t *testing.T) {
	f := newComplianceAgentFixture(t)
	for _, action := range []string{"ingest", "bench/run"} {
		for _, query := range []string{"", "?cluster_id=" + f.cluster.String()} {
			w := f.call(t, action, query, "", false)
			if w.Code != http.StatusOK && w.Code != http.StatusAccepted {
				t.Fatalf("legacyuser %s %d %s", action, w.Code, w.Body.String())
			}
		}
	}
	if w := f.call(t, "bench/claim", "?cluster_id="+f.cluster.String(), "", false); w.Code != http.StatusOK {
		t.Fatalf("legacyclaim %d %s", w.Code, w.Body.String())
	}
	// A user subject alone does not authenticate the separate agent handler.
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/agent/compliance/ingest", strings.NewReader(kbClusterSampleJSON))
	r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: f.org, UserID: f.user}))
	w := httptest.NewRecorder()
	f.service.AgentIngest(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("user context substituted for agentauth: %d", w.Code)
	}
}

func TestComplianceAgentClaimAuditFailureRollsBack(t *testing.T) {
	f := newComplianceAgentFixture(t)
	request := f.queue(t, f.org, nil)
	name := "bench_fail_" + strings.ReplaceAll(f.org.String(), "-", "")
	sql := `CREATE FUNCTION ` + name + `()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.org_id='` + f.org.String() + `'::uuid AND NEW.action='compliance.bench.claimed' THEN RAISE EXCEPTION 'isolated claim failure'; END IF; RETURN NEW; END$$`
	if _, err := f.database.Pool().Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.Pool().Exec(t.Context(), `CREATE TRIGGER `+name+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION `+name+`()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.database.Pool().Exec(context.WithoutCancel(t.Context()), `DROP TRIGGER IF EXISTS `+name+` ON audit_events;DROP FUNCTION IF EXISTS `+name+`()`)
	})
	w := f.call(t, "bench/claim", "", f.token, true)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "isolated claim failure") {
		t.Fatalf("false/sensitive receipt %d %s", w.Code, w.Body.String())
	}
	var status string
	var cluster *uuid.UUID
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT status,cluster_id FROM compliance_bench_run_requests WHERE id=$1`, request).Scan(&status, &cluster); err != nil || status != "pending" || cluster != nil {
		t.Fatalf("failedclaim changedtask %s %v %v", status, cluster, err)
	}
}

func TestComplianceAgentClaimDoesNotDuplicate(t *testing.T) {
	f := newComplianceAgentFixture(t)
	f.queue(t, f.org, &f.cluster)
	results := make(chan int, 2)
	for range 2 {
		go func() { results <- f.call(t, "bench/claim", "", f.token, true).Code }()
	}
	counts := map[int]int{}
	for range 2 {
		counts[<-results]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusNoContent] != 1 {
		t.Fatalf("duplicate/concurrent claim %v", counts)
	}
}
