//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func dlpToken(t *testing.T, f dlpSecurityFixture, org uuid.UUID) *handler.RuntimeAgentToken {
	t.Helper()
	_, id, err := handler.IssueRuntimeAgentToken(t.Context(), f.store.db.Pool(), org, "dlp-scope-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &handler.RuntimeAgentToken{ID: id, OrgID: org}
}

func bindDLPToken(t *testing.T, f dlpSecurityFixture, token *handler.RuntimeAgentToken, org, cluster uuid.UUID) {
	t.Helper()
	if _, err := f.store.db.Pool().Exec(t.Context(), `INSERT INTO cluster_init_bundles(org_id,cluster_id,name,expires_at,runtime_agent_token_id,kek_fingerprint,contents_encrypted)VALUES($1,$2,$3,NOW()+INTERVAL '1 hour',$4,'fixture','\x00'::bytea)`, org, cluster, "dlp-binding-"+uuid.NewString(), token.ID); err != nil {
		t.Fatal(err)
	}
}

func dlpAgentRequest(t *testing.T, f dlpSecurityFixture, token *handler.RuntimeAgentToken, query string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := t.Context()
	if token != nil {
		ctx = handler.WithRuntimeAgentToken(ctx, token)
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/runtime-dlp-rules:bundle?"+query, nil)
	w := httptest.NewRecorder()
	(&RuntimeDLPHTTP{store: f.store}).AgentBundle(w, req)
	return w
}

func TestDLPAgentRejectsEveryUnresolvedOrDifferentClusterBeforeSeed(t *testing.T) {
	f := newDLPSecurityFixture(t)
	bound := dlpToken(t, f, f.org)
	bindDLPToken(t, f, bound, f.org, f.cluster)
	unbound := dlpToken(t, f, f.org)
	ambiguous := dlpToken(t, f, f.org)
	bindDLPToken(t, f, ambiguous, f.org, f.cluster)
	bindDLPToken(t, f, ambiguous, f.org, f.sibling)
	foreignBinding := dlpToken(t, f, f.org)
	bindDLPToken(t, f, foreignBinding, f.otherOrg, f.foreign)
	mixedBinding := dlpToken(t, f, f.org)
	bindDLPToken(t, f, mixedBinding, f.org, f.foreign)
	cases := []struct {
		name   string
		token  *handler.RuntimeAgentToken
		query  string
		status int
	}{
		{"no token", nil, "cluster_id=" + f.cluster.String(), 401},
		{"sibling", bound, "cluster_id=" + f.sibling.String(), 403},
		{"foreign", bound, "cluster_id=" + f.foreign.String(), 403},
		{"missing cluster", bound, "cluster_id=" + uuid.NewString(), 403},
		{"unbound multi cluster", unbound, "cluster_id=" + f.cluster.String(), 403},
		{"ambiguous bindings", ambiguous, "cluster_id=" + f.cluster.String(), 403},
		{"foreign bundle org", foreignBinding, "cluster_id=" + f.foreign.String(), 403},
		{"foreign cluster owner", mixedBinding, "cluster_id=" + f.foreign.String(), 403},
		{"duplicate cluster", bound, "cluster_id=" + f.cluster.String() + "&cluster_id=" + f.sibling.String(), 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := dlpAgentRequest(t, f, tc.token, tc.query)
			if w.Code != tc.status {
				t.Fatalf("status%d want%d %s", w.Code, tc.status, w.Body.String())
			}
			if f.count(t, "runtime_dlp_rules") != 3 || f.count(t, "audit_events") != 0 {
				t.Fatal("rejected agent seeded or audited rules")
			}
			f.store.seeded.Range(func(_, _ any) bool { t.Error("rejected agent poisoned seed cache"); return false })
		})
	}
}

func TestDLPBuiltinSeedAuditFailureIsAtomicAndRetryable(t *testing.T) {
	f := newDLPSecurityFixture(t)
	token := dlpToken(t, f, f.org)
	bindDLPToken(t, f, token, f.org, f.cluster)
	remove := rejectDLPAudit(t, f)
	w := dlpAgentRequest(t, f, token, "cluster_id="+f.cluster.String())
	if w.Code != 500 || strings.Contains(w.Body.String(), "fixture") {
		t.Fatalf("seed failure must not serve partial bundle %d %s", w.Code, w.Body.String())
	}
	if f.count(t, "runtime_dlp_rules") != 3 || f.count(t, "audit_events") != 0 {
		t.Fatal("seed audit failure left partial inserts")
	}
	if _, ok := f.store.seeded.Load(dlpSeedScope{f.org, f.cluster}); ok {
		t.Fatal("failed seed cached")
	}
	remove()
	w = dlpAgentRequest(t, f, token, "cluster_id="+f.cluster.String())
	if w.Code != 200 {
		t.Fatalf("retry%d %s", w.Code, w.Body.String())
	}
	expected := len(AllBuiltinPacks())
	if f.count(t, "runtime_dlp_rules") != 3+expected || f.count(t, "audit_events") != expected {
		t.Fatal("retry did not commit complete audited builtin pack")
	}
	assertDLPSeedDefaults(t, f)
	if f.count(t, "fed_rule_revisions") != 0 {
		t.Fatal("builtin seed changed federation behavior")
	}
	if _, ok := f.store.seeded.Load(dlpSeedScope{f.org, f.cluster}); !ok {
		t.Fatal("successful seed not cached")
	}
	assertDLPBuiltinEditsSurvive(t, f, token, expected)
}

func assertDLPSeedDefaults(t *testing.T, f dlpSecurityFixture) {
	t.Helper()
	var invalid int
	if err := f.store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM runtime_dlp_rules WHERE org_id=$1 AND source='builtin' AND (mode<>'monitor' OR cfg_type<>'predefined' OR created_by IS NOT NULL)`, f.org).Scan(&invalid); err != nil {
		t.Fatal(err)
	}
	if invalid != 0 {
		t.Fatal("builtin defaults changed")
	}
	if err := f.store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND actor_id IS NOT NULL`, f.org).Scan(&invalid); err != nil || invalid != 0 {
		t.Fatalf("builtin falsely attributed to user %d %v", invalid, err)
	}
}

func assertDLPBuiltinEditsSurvive(t *testing.T, f dlpSecurityFixture, token *handler.RuntimeAgentToken, expected int) {
	t.Helper()
	// An operator's edited builtin must survive both another process and cached polls.
	name := AllBuiltinPacks()[0].Name
	if _, err := f.store.db.Pool().Exec(t.Context(), `UPDATE runtime_dlp_rules SET description='operator edit',mode='disabled' WHERE org_id=$1 AND name=$2`, f.org, name); err != nil {
		t.Fatal(err)
	}
	if n, err := f.store.EnsureBuiltins(t.Context(), f.org, f.cluster); err != nil || n != 0 {
		t.Fatalf("idempotent seed%d %v", n, err)
	}
	w := dlpAgentRequest(t, f, token, "cluster_id="+f.cluster.String())
	if w.Code != 200 || f.count(t, "audit_events") != expected {
		t.Fatalf("repeat poll%d %s", w.Code, w.Body.String())
	}
	var description, mode string
	if err := f.store.db.Pool().QueryRow(t.Context(), `SELECT description,mode FROM runtime_dlp_rules WHERE org_id=$1 AND name=$2`, f.org, name).Scan(&description, &mode); err != nil || description != "operator edit" || mode != "disabled" {
		t.Fatalf("seed overwrote operator edits %s %s %v", description, mode, err)
	}
}

func TestDLPSeedRequiresCurrentOwnedClusterAndCacheIncludesOrganization(t *testing.T) {
	f := newDLPSecurityFixture(t)
	for _, cluster := range []uuid.UUID{f.foreign, uuid.New()} {
		if n, err := f.store.EnsureBuiltins(t.Context(), f.org, cluster); err == nil || n != 0 {
			t.Fatal("seed accepted unowned cluster")
		}
		if err := f.store.ensureBuiltinsOnce(t.Context(), f.org, cluster); err == nil {
			t.Fatal("cached seed accepted unowned cluster")
		}
	}
	if err := f.store.ensureBuiltinsOnce(t.Context(), f.org, f.cluster); err != nil {
		t.Fatal(err)
	}
	// A cache entry from an earlier owner must not authorize reads/writes or
	// prevent the current owner from obtaining its own builtin pack.
	if _, err := f.store.db.Pool().Exec(t.Context(), `UPDATE clusters SET org_id=$1 WHERE id=$2`, f.otherOrg, f.cluster); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ensureBuiltinsOnce(t.Context(), f.org, f.cluster); err == nil {
		t.Fatal("stale cache authorized former owner")
	}
	if err := f.store.ensureBuiltinsOnce(t.Context(), f.otherOrg, f.cluster); err != nil {
		t.Fatal(err)
	}
	for _, org := range []uuid.UUID{f.org, f.otherOrg} {
		if _, ok := f.store.seeded.Load(dlpSeedScope{org, f.cluster}); !ok {
			t.Fatal("organization cache key missing")
		}
	}
	var count int
	if err := f.store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM runtime_dlp_rules WHERE org_id=$1 AND cluster_id=$2`, f.otherOrg, f.cluster).Scan(&count); err != nil || count != len(AllBuiltinPacks()) {
		t.Fatalf("current owner pack%d %v", count, err)
	}
}

func TestDLPAgentSingleClusterFallbackStillWorks(t *testing.T) {
	f := newDLPSecurityFixture(t)
	// The existing resolver permits an unbound token only when its organization
	// has one exact cluster. Preserve this legacy provisioning contract.
	token := dlpToken(t, f, f.otherOrg)
	w := dlpAgentRequest(t, f, token, "cluster_id="+f.foreign.String())
	if w.Code != 200 {
		t.Fatalf("single cluster fallback%d %s", w.Code, w.Body.String())
	}
	var envelope struct {
		Rules []DLPRule `json:"rules"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || len(envelope.Rules) != len(AllBuiltinPacks()) {
		t.Fatalf("fallback bundle incomplete %v", err)
	}
	for _, rule := range envelope.Rules {
		if rule.OrgID != f.otherOrg || rule.ClusterID != f.foreign {
			t.Fatal("fallback returned foreign scope")
		}
	}
}

func dlpImportRequest(t *testing.T, f dlpSecurityFixture, cluster uuid.UUID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(authctx.WithSubject(t.Context(), authctx.Subject{OrgID: f.org, UserID: f.actor}), http.MethodPost, "/runtime-signatures:import?cluster_id="+cluster.String(), bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	(&RuntimeSignaturesHTTP{store: f.store}).Import(w, req)
	return w
}

func TestDLPPreservesPartialImportAndAuditsEachCommittedRule(t *testing.T) {
	f := newDLPSecurityFixture(t)
	bundle := `apiVersion: constellation/v1
kind: DPISignatureBundle
rules:
  - name: imported-waf
    category: waf
    severity: 6
    mode: enforce
    patterns: ["secret"]
  - name: imported-waf
    category: waf
    severity: 6
    patterns: ["secret"]
  - name: invalid-pattern
    severity: 6
    patterns: [".*"]
  - name: forbidden-dlp
    category: dlp
    severity: 6
    patterns: ["secret"]
`
	for _, cluster := range []uuid.UUID{f.foreign, uuid.New()} {
		if w := dlpImportRequest(t, f, cluster, bundle); w.Code != 404 {
			t.Fatalf("foreign import%d %s", w.Code, w.Body.String())
		}
	}
	w := dlpImportRequest(t, f, f.cluster, bundle)
	if w.Code != 200 {
		t.Fatalf("partial import%d %s", w.Code, w.Body.String())
	}
	var result struct {
		Created, Updated int
		Results          []struct{ Status, Error string }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Created != 1 || result.Updated != 0 || len(result.Results) != 4 {
		t.Fatalf("partial contract changed %+v", result)
	}
	for i, status := range []string{"created", "skipped", "error", "error"} {
		if result.Results[i].Status != status {
			t.Fatalf("result%d %+v", i, result)
		}
	}
	if f.count(t, "audit_events") != 1 || f.count(t, "fed_rule_revisions") != 1 {
		t.Fatal("partial import did not preserve committed audit/federation")
	}
	var mode string
	if err := f.store.db.Pool().QueryRow(t.Context(), `SELECT mode FROM runtime_dlp_rules WHERE org_id=$1 AND name='imported-waf'`, f.org).Scan(&mode); err != nil || mode != "monitor" {
		t.Fatalf("import enforced without promotion %s %v", mode, err)
	}
	rejectDLPAudit(t, f)
	w = dlpImportRequest(t, f, f.cluster, strings.ReplaceAll(bundle, "imported-waf", "rejected-waf"))
	if w.Code != 200 || strings.Contains(w.Body.String(), "fixture") {
		t.Fatalf("failed import exposed internals or lost partial contract%d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Created != 0 || result.Results[0].Status != "error" || result.Results[1].Status != "error" {
		t.Fatalf("audit-failed imports claimed success %+v %v", result, err)
	}
	if f.count(t, "runtime_dlp_rules") != 4 || f.count(t, "audit_events") != 1 || f.count(t, "fed_rule_revisions") != 1 {
		t.Fatal("failed import committed side effects")
	}
}

func TestDLPBuiltinMidBatchFailureDoesNotCommitPartialPack(t *testing.T) {
	f := newDLPSecurityFixture(t)
	pool := f.store.db.Pool()
	function := pgx.Identifier{"reject_seed_" + uuid.NewString()}.Sanitize()
	trigger := pgx.Identifier{"reject_seed_" + uuid.NewString()}.Sanitize()
	sql := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.org_id='%s'::uuid AND NEW.source='builtin' AND EXISTS(SELECT 1 FROM runtime_dlp_rules WHERE org_id=NEW.org_id AND source='builtin') THEN RAISE EXCEPTION 'fixture second builtin rejected'; END IF; RETURN NEW; END $$`, function, f.org)
	if _, err := pool.Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TRIGGER `+trigger+` BEFORE INSERT ON runtime_dlp_rules FOR EACH ROW EXECUTE FUNCTION `+function+`() `); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, query := range []string{`DROP TRIGGER IF EXISTS ` + trigger + ` ON runtime_dlp_rules`, `DROP FUNCTION IF EXISTS ` + function + `() `} {
			if _, err := pool.Exec(context.Background(), query); err != nil {
				t.Error(err)
			}
		}
	})
	if err := f.store.ensureBuiltinsOnce(t.Context(), f.org, f.cluster); err == nil {
		t.Fatal("seed failure was hidden")
	}
	if f.count(t, "runtime_dlp_rules") != 3 || f.count(t, "audit_events") != 0 {
		t.Fatal("mid-batch failure committed partial pack or audit")
	}
	if _, ok := f.store.seeded.Load(dlpSeedScope{f.org, f.cluster}); ok {
		t.Fatal("mid-batch failure was cached")
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER `+trigger+` ON runtime_dlp_rules`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ensureBuiltinsOnce(t.Context(), f.org, f.cluster); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "runtime_dlp_rules") != 3+len(AllBuiltinPacks()) {
		t.Fatal("mid-batch failure did not retry full pack")
	}
}
