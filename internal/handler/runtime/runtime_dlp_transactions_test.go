package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type dlpSecurityFixture struct {
	store                                           *RuntimeDLPStore
	org, otherOrg, actor, cluster, sibling, foreign uuid.UUID
	ids                                             map[DLPCategory]uuid.UUID
}

func newDLPSecurityFixture(t *testing.T) dlpSecurityFixture {
	t.Helper()
	d := openTestDB(t)
	t.Cleanup(d.Close)
	f := dlpSecurityFixture{store: NewRuntimeDLPStore(d, audit.New(d.Pool())), org: uuid.New(), otherOrg: uuid.New(), actor: uuid.New(), cluster: uuid.New(), sibling: uuid.New(), foreign: uuid.New(), ids: map[DLPCategory]uuid.UUID{}}
	for _, org := range []uuid.UUID{f.org, f.otherOrg} {
		if _, err := d.Pool().Exec(t.Context(), `INSERT INTO orgs(id,name,display_name)VALUES($1,$2,$2)`, org, "dlp-security-"+org.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, query := range []string{`DELETE FROM fed_rule_revisions WHERE org_id IN($1,$2)`, `DELETE FROM runtime_dlp_rules WHERE org_id IN($1,$2)`, `DELETE FROM orgs WHERE id IN($1,$2)`} {
			if _, err := d.Pool().Exec(context.Background(), query, f.org, f.otherOrg); err != nil {
				t.Error(err)
			}
		}
	})
	if _, err := d.Pool().Exec(t.Context(), `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, f.cluster, f.org, f.sibling, f.foreign, f.otherOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(t.Context(), `INSERT INTO federation_state(org_id,state,revision)VALUES($1,'master',1)`, f.org); err != nil {
		t.Fatal(err)
	}
	for _, category := range []DLPCategory{CategoryDLP, CategorySignature, CategoryWAF} {
		id := uuid.New()
		f.ids[category] = id
		if _, err := d.Pool().Exec(t.Context(), `INSERT INTO runtime_dlp_rules(id,org_id,cluster_id,name,category,severity,patterns,description,scope_macs)VALUES($1,$2,$3,$4,$4,5,'["original-secret"]','original description','["aa:bb"]')`, id, f.org, f.cluster, string(category)); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f dlpSecurityFixture) count(t *testing.T, table string) int {
	t.Helper()
	var count int
	if err := f.store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()+` WHERE org_id=$1`, f.org).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func dlpSecurityRequest(t *testing.T, f dlpSecurityFixture, signatures bool, org, id uuid.UUID, operation string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := "/runtime-dlp-rules"
	if signatures {
		path = "/runtime-signatures"
	}
	method := http.MethodPost
	if operation != "create" {
		path += "/" + id.String()
	}
	switch operation {
	case "update":
		method = http.MethodPut
	case "delete":
		method = http.MethodDelete
	case "create":
	default:
		path += "/" + operation
	}
	req := httptest.NewRequestWithContext(authctx.WithSubject(t.Context(), authctx.Subject{OrgID: org, UserID: f.actor}), method, path, bytes.NewReader(raw))
	req.Header.Set("X-Request-Id", "dlp-security-request")
	w := httptest.NewRecorder()
	h := &RuntimeDLPHTTP{store: f.store}
	if signatures {
		h = (&RuntimeSignaturesHTTP{store: f.store}).mutationHTTP()
	}
	handlers := map[string]http.HandlerFunc{"create": h.Create, "update": h.Update, "promote": h.Promote, "demote": h.Demote, "disable": h.Disable, "delete": h.Delete}
	if signatures && operation == "create" {
		(&RuntimeSignaturesHTTP{store: f.store}).Create(w, req)
	} else {
		handlers[operation](w, req)
	}
	return w
}

func dlpSecurityBody(cluster uuid.UUID, category DLPCategory) map[string]any {
	return map[string]any{"cluster_id": cluster, "name": "new-" + string(category), "category": category, "severity": 6, "patterns": []string{"created-secret"}}
}

// The trigger is organization-specific, allowing shuffled package tests to run
// against the same isolated database without rejecting another fixture's audit.
func rejectDLPAudit(t *testing.T, f dlpSecurityFixture) func() {
	t.Helper()
	return rejectDLPAuditSQLState(t, f, "P0001")
}

func rejectDLPAuditSQLState(t *testing.T, f dlpSecurityFixture, code string) func() {
	t.Helper()
	function := pgx.Identifier{"reject_dlp_" + uuid.NewString()}.Sanitize()
	trigger := pgx.Identifier{"reject_dlp_" + uuid.NewString()}.Sanitize()
	pool := f.store.db.Pool()
	if _, err := pool.Exec(t.Context(), fmt.Sprintf(`CREATE FUNCTION %s()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid THEN RAISE EXCEPTION 'dlp audit fixture rejected' USING ERRCODE='%s', CONSTRAINT='audit_fixture_unique'; END IF; RETURN NEW; END $$`, function, f.org, code)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TRIGGER `+trigger+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION `+function+`() `); err != nil {
		t.Fatal(err)
	}
	removed := false
	remove := func() {
		if removed {
			return
		}
		removed = true
		for _, query := range []string{`DROP TRIGGER IF EXISTS ` + trigger + ` ON audit_events`, `DROP FUNCTION IF EXISTS ` + function + `() `} {
			if _, err := pool.Exec(context.Background(), query); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(remove)
	return remove
}

func TestDLPAuditFailureRollsBackEveryFamilyAndMutation(t *testing.T) {
	f := newDLPSecurityFixture(t)
	rejectDLPAudit(t, f)
	for _, category := range []DLPCategory{CategoryDLP, CategorySignature, CategoryWAF} {
		before, err := f.store.Get(t.Context(), f.org, f.ids[category])
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range []string{"create", "update", "promote", "demote", "disable", "delete"} {
			t.Run(string(category)+"/"+operation, func(t *testing.T) {
				assertDLPAuditRollback(t, f, before, category, operation)
			})
		}
	}
	rule := DLPRule{OrgID: f.org, ClusterID: f.cluster, Name: "direct-create", Category: CategoryDLP, Mode: DLPModeMonitor, Severity: 6, Patterns: json.RawMessage(`["secret"]`)}
	if id, err := f.store.Insert(t.Context(), &rule, ""); err == nil || id != uuid.Nil || rule.ID != uuid.Nil || rule.Version != 0 {
		t.Fatalf("uncommitted identity escaped %+v %s %v", rule, id, err)
	}
}

func assertDLPAuditRollback(t *testing.T, f dlpSecurityFixture, before *DLPRule, category DLPCategory, operation string) {
	t.Helper()
	body := map[string]any{"patterns": []string{"must-rollback"}, "severity": 8, "description": "must roll back", "scope_macs": []string{}}
	signatures := category != CategoryDLP
	if operation == "create" {
		body = dlpSecurityBody(f.cluster, category)
		signatures = category == CategorySignature
	}
	w := dlpSecurityRequest(t, f, signatures, f.org, before.ID, operation, body)
	if w.Code != 500 || strings.Contains(w.Body.String(), "fixture") {
		t.Fatalf("must fail without DB details: %d %s", w.Code, w.Body.String())
	}
	after, err := f.store.Get(t.Context(), f.org, before.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("audit failure changed row before%+v after%+v %v", before, after, err)
	}
	if f.count(t, "runtime_dlp_rules") != 3 || f.count(t, "audit_events") != 0 || f.count(t, "fed_rule_revisions") != 0 {
		t.Fatal("failed transaction left mutation, audit or federation side effect")
	}
}

func TestDLPForeignOwnershipAndSignatureCategoryAreCheckedAtMutation(t *testing.T) {
	f := newDLPSecurityFixture(t)
	malformed := uuid.New()
	if _, err := f.store.db.Pool().Exec(t.Context(), `INSERT INTO runtime_dlp_rules(id,org_id,cluster_id,name,category,severity,patterns)VALUES($1,$2,$3,'bad-scope','signature',5,'["secret"]')`, malformed, f.org, f.foreign); err != nil {
		t.Fatal(err)
	}
	assertDLPForeignWrites(t, f, malformed)
	for _, operation := range []string{"update", "promote", "demote", "disable", "delete"} {
		if w := dlpSecurityRequest(t, f, true, f.org, f.ids[CategoryDLP], operation, map[string]any{"severity": 8}); w.Code != 404 {
			t.Fatalf("wrong category %s %d", operation, w.Code)
		}
	}
	if f.count(t, "audit_events") != 0 || f.count(t, "fed_rule_revisions") != 0 {
		t.Fatal("scope failures had side effects")
	}
	if _, err := f.store.Get(t.Context(), f.org, malformed); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign retained row exposed %v", err)
	}
}

func assertDLPForeignWrites(t *testing.T, f dlpSecurityFixture, malformed uuid.UUID) {
	t.Helper()
	for _, signatures := range []bool{false, true} {
		for _, cluster := range []uuid.UUID{f.foreign, uuid.New()} {
			w := dlpSecurityRequest(t, f, signatures, f.org, uuid.Nil, "create", dlpSecurityBody(cluster, CategoryDLP))
			if w.Code != 404 {
				t.Fatalf("foreign create %d %s", w.Code, w.Body.String())
			}
		}
		for _, operation := range []string{"update", "promote", "demote", "disable", "delete"} {
			for _, target := range []struct{ org, id uuid.UUID }{{f.org, malformed}, {f.otherOrg, f.ids[CategorySignature]}} {
				if w := dlpSecurityRequest(t, f, signatures, target.org, target.id, operation, map[string]any{"severity": 8}); w.Code != 404 {
					t.Fatalf("foreign %s %d %s", operation, w.Code, w.Body.String())
				}
			}
		}
	}
}

func committedDLP(t *testing.T, w *httptest.ResponseRecorder, status int) DLPRule {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status%d want%d %s", w.Code, status, w.Body.String())
	}
	var rule DLPRule
	if err := json.Unmarshal(w.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.ID == uuid.Nil || rule.DPRuleID <= 0 || rule.Version < 1 || rule.CreatedAt.IsZero() || rule.UpdatedAt.IsZero() {
		t.Fatalf("incomplete committed receipt %+v", rule)
	}
	return rule
}

func TestDLPCommittedAuditsDefaultsAndPatchCompatibility(t *testing.T) {
	f := newDLPSecurityFixture(t)
	for _, category := range []DLPCategory{CategoryDLP, CategorySignature, CategoryWAF} {
		rule := committedDLP(t, dlpSecurityRequest(t, f, category == CategorySignature, f.org, uuid.Nil, "create", dlpSecurityBody(f.cluster, category)), 201)
		if rule.Category != category || rule.ApplyDir != defaultDLPDirection(category, 0) || rule.Mode != DLPModeMonitor || rule.Source != "user" {
			t.Fatalf("wrong defaults %+v", rule)
		}
		var actor *uuid.UUID
		var after map[string]any
		var action, request string
		if err := f.store.db.Pool().QueryRow(t.Context(), `SELECT actor_id,action,after,request_id FROM audit_events WHERE org_id=$1 AND target_id=$2 ORDER BY id DESC LIMIT 1`, f.org, rule.ID.String()).Scan(&actor, &action, &after, &request); err != nil {
			t.Fatal(err)
		}
		if actor == nil || *actor != f.actor || action != audit.ActionPolicyCreate || after["cluster_id"] != f.cluster.String() || after["category"] != string(category) || request != "dlp-security-request" {
			t.Fatalf("wrong create audit %s %+v", action, after)
		}
		if w := dlpSecurityRequest(t, f, false, f.org, uuid.Nil, "create", dlpSecurityBody(f.cluster, category)); w.Code != 409 {
			t.Fatalf("duplicate status%d", w.Code)
		}
	}
	original := f.ids[CategoryDLP]
	updated := committedDLP(t, dlpSecurityRequest(t, f, false, f.org, original, "update", map[string]any{"patterns": []string{"changed", "another"}, "scope_macs": []string{}, "severity": 8}), 200)
	if len(updated.ScopeMACs) != 0 || updated.Description != "original description" || updated.Severity != 8 {
		t.Fatalf("patch changed omitted fields or failed clear %+v", updated)
	}
	var before, after map[string]any
	if err := f.store.db.Pool().QueryRow(t.Context(), `SELECT before,after FROM audit_events WHERE org_id=$1 AND target_id=$2 ORDER BY id DESC LIMIT 1`, f.org, original.String()).Scan(&before, &after); err != nil {
		t.Fatal(err)
	}
	if before["rule_count"] != float64(1) || after["rule_count"] != float64(2) || before["version"] != float64(1) || after["version"] != float64(updated.Version) {
		t.Fatalf("mutated audit snapshots before%+v after%+v", before, after)
	}
	for _, operation := range []string{"promote", "demote", "disable"} {
		committedDLP(t, dlpSecurityRequest(t, f, false, f.org, original, operation, nil), 200)
	}
	if w := dlpSecurityRequest(t, f, false, f.org, original, "delete", nil); w.Code != 200 {
		t.Fatalf("delete%d %s", w.Code, w.Body.String())
	}
	if f.count(t, "fed_rule_revisions") != 8 {
		t.Fatalf("expected only committed federation effects got%d", f.count(t, "fed_rule_revisions"))
	}
}

func TestDLPInvalidUpdatesDoNotWrite(t *testing.T) {
	f := newDLPSecurityFixture(t)
	for _, body := range []map[string]any{{"severity": 10}, {"severity": -1}, {"patterns": []string{}}, {"patterns": []string{".*"}}, {"patterns": []map[string]string{{"pattern": "secret", "context": "invalid"}}}} {
		w := dlpSecurityRequest(t, f, false, f.org, f.ids[CategoryDLP], "update", body)
		if w.Code != 400 {
			t.Fatalf("invalid patch %d %s", w.Code, w.Body.String())
		}
	}
	if f.count(t, "audit_events") != 0 || f.count(t, "fed_rule_revisions") != 0 {
		t.Fatal("invalid patch wrote effects")
	}
}

func TestDLPAuditUniqueFailureIsNotReportedAsExistingRule(t *testing.T) {
	f := newDLPSecurityFixture(t)
	rejectDLPAuditSQLState(t, f, "23505")
	w := dlpSecurityRequest(t, f, false, f.org, uuid.Nil, "create", dlpSecurityBody(f.cluster, CategoryDLP))
	if w.Code != 500 || strings.Contains(w.Body.String(), "fixture") {
		t.Fatalf("audit unique failure mislabeled or leaked: %d %s", w.Code, w.Body.String())
	}
	if f.count(t, "runtime_dlp_rules") != 3 || f.count(t, "audit_events") != 0 || f.count(t, "fed_rule_revisions") != 0 {
		t.Fatal("audit unique failure committed rule or federation")
	}
}
