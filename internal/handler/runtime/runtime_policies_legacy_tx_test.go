package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func legacyPolicyRequest(t *testing.T, f reviewedPolicyFixture, org, id uuid.UUID, operation string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path, method := "/runtime-policies/"+id.String(), http.MethodPost
	switch operation {
	case "create":
		path = "/runtime-policies"
	case "update":
		method = http.MethodPut
	case "delete":
		method = http.MethodDelete
	default:
		path += "/" + operation
	}
	ctx := authctx.WithSubject(t.Context(), authctx.Subject{OrgID: org, UserID: f.actor})
	r := httptest.NewRequestWithContext(ctx, method, path, bytes.NewReader(raw))
	r.Header.Set("X-Request-Id", "legacy-fixture-request")
	w := httptest.NewRecorder()
	switch operation {
	case "create":
		f.h.Create(w, r)
	case "update":
		f.h.Update(w, r)
	case "promote":
		f.h.Promote(w, r)
	case "demote":
		f.h.Demote(w, r)
	case "disable":
		f.h.Disable(w, r)
	case "delete":
		f.h.Delete(w, r)
	}
	return w
}

func legacyCreateBody(cluster uuid.UUID) map[string]any {
	return map[string]any{"cluster_id": cluster, "workload": "app/new", "namespace": "app", "name": "created legacy policy", "mode": "monitor", "rules": []any{}}
}

func rejectLegacyPolicyAudit(t *testing.T, f reviewedPolicyFixture) {
	t.Helper()
	pool := f.h.store.db.Pool()
	function := pgx.Identifier{"reject_legacy_" + uuid.NewString()}.Sanitize()
	trigger := pgx.Identifier{"reject_legacy_" + uuid.NewString()}.Sanitize()
	sql := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid THEN RAISE EXCEPTION 'fixture legacy audit rejected'; END IF; RETURN NEW; END $$`, function, f.org)
	if _, err := pool.Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TRIGGER `+trigger+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION `+function+`() `); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, sql := range []string{`DROP TRIGGER IF EXISTS ` + trigger + ` ON audit_events`, `DROP FUNCTION IF EXISTS ` + function + `()`} {
			if _, err := pool.Exec(context.Background(), sql); err != nil {
				t.Error(err)
			}
		}
	})
}

func TestLegacyPolicyAuditFailureRollsBackEveryMutation(t *testing.T) {
	f := reviewedFixture(t)
	before, err := f.h.store.Get(t.Context(), f.org, f.id)
	if err != nil {
		t.Fatal(err)
	}
	rejectLegacyPolicyAudit(t, f)
	for _, operation := range []string{"create", "update", "promote", "demote", "disable", "delete"} {
		t.Run(operation, func(t *testing.T) {
			body := map[string]any{"name": "must roll back", "def_action": 7, "apply_dir": 1, "rules": []any{map[string]any{"action": 7, "port": 80}}}
			if operation == "create" {
				body = legacyCreateBody(f.cluster)
			}
			w := legacyPolicyRequest(t, f, f.org, f.id, operation, body)
			if w.Code != 500 || strings.Contains(w.Body.String(), "fixture legacy audit rejected") {
				t.Fatalf("mutation must fail without SQL details: %d %s", w.Code, w.Body.String())
			}
			assertLegacyPolicyUnchanged(t, f, before)
		})
	}
	t.Run("store insert caller does not receive uncommitted identity", func(t *testing.T) {
		p := RuntimePolicy{OrgID: f.org, ClusterID: f.cluster, Workload: "app/direct", Namespace: "app", Name: "direct", Mode: PolicyModeMonitor, DefAction: 2, ApplyDir: 3}
		if id, err := f.h.store.Insert(t.Context(), &p, "direct-insert"); err == nil || id != uuid.Nil || p.ID != uuid.Nil || p.Version != 0 {
			t.Fatalf("uncommitted identity escaped: %s %+v %v", id, p, err)
		}
		assertLegacyPolicyUnchanged(t, f, before)
	})
	t.Run("system mode caller also rolls back", func(t *testing.T) {
		if err := f.h.store.SetMode(t.Context(), f.org, f.id, PolicyModeEnforce, uuid.Nil, true, "system-mode"); err == nil {
			t.Fatal("audit failure committed system mode")
		}
		assertLegacyPolicyUnchanged(t, f, before)
	})
}

func assertLegacyPolicyUnchanged(t *testing.T, f reviewedPolicyFixture, before *RuntimePolicy) {
	t.Helper()
	after, err := f.h.store.Get(t.Context(), f.org, f.id)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("audit failure changed policy: before%+v after%+v %v", before, after, err)
	}
	var policies int
	if err := f.h.store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM runtime_policies WHERE org_id=$1`, f.org).Scan(&policies); err != nil {
		t.Fatal(err)
	}
	if policies != 1 || f.countAudit(t) != 0 {
		t.Fatal("audit failure left a policy or audit side effect")
	}
}

func TestLegacyPolicyRequiresExactOwnedClusterOnCreateAndExistingWrites(t *testing.T) {
	f := reviewedFixture(t)
	for _, cluster := range []uuid.UUID{f.foreignCluster, uuid.New()} {
		w := legacyPolicyRequest(t, f, f.org, uuid.Nil, "create", legacyCreateBody(cluster))
		if w.Code != 404 {
			t.Fatalf("unowned cluster create status=%d %s", w.Code, w.Body.String())
		}
		p := RuntimePolicy{OrgID: f.org, ClusterID: cluster, Workload: "app/direct", Namespace: "app", Name: "foreign", Mode: PolicyModeMonitor, DefAction: 2, ApplyDir: 3}
		if _, err := f.h.store.Insert(t.Context(), &p, ""); err == nil || p.ID != uuid.Nil {
			t.Fatal("store insert accepted unowned cluster")
		}
	}
	// The historic schema has no ownership FK. A preexisting malformed row must
	// not be a route around the same current cluster ownership requirement.
	malformed := uuid.New()
	if _, err := f.h.store.db.Pool().Exec(t.Context(), `INSERT INTO runtime_policies(id,org_id,cluster_id,workload,namespace,name) VALUES($1,$2,$3,'app/foreign','app','retained foreign scope')`, malformed, f.org, f.foreignCluster); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"update", "promote", "demote", "disable", "delete"} {
		if w := legacyPolicyRequest(t, f, f.org, malformed, operation, map[string]any{"name": "do not write"}); w.Code != 404 {
			t.Fatalf("unowned retained policy %s status%d", operation, w.Code)
		}
		if w := legacyPolicyRequest(t, f, f.foreignOrg, f.id, operation, map[string]any{"name": "do not write"}); w.Code != 404 {
			t.Fatalf("foreign org policy %s status%d", operation, w.Code)
		}
	}
	got, err := f.h.store.Get(t.Context(), f.org, malformed)
	if err != nil || got.Name != "retained foreign scope" || got.Mode != PolicyModeMonitor || got.Version != 1 || f.countAudit(t) != 0 {
		t.Fatalf("unowned policy was modified %+v %v", got, err)
	}
}

type legacyPolicyAuditRow struct {
	action        string
	actor         *uuid.UUID
	before, after map[string]any
	request       string
}

func lastLegacyPolicyAudit(t *testing.T, f reviewedPolicyFixture, id uuid.UUID) legacyPolicyAuditRow {
	t.Helper()
	var row legacyPolicyAuditRow
	var before, after []byte
	if err := f.h.store.db.Pool().QueryRow(t.Context(), `SELECT action,actor_id,before,after,COALESCE(request_id,'') FROM audit_events WHERE org_id=$1 AND target_id=$2 ORDER BY id DESC LIMIT 1`, f.org, id.String()).Scan(&row.action, &row.actor, &before, &after, &row.request); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(before, &row.before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &row.after); err != nil {
		t.Fatal(err)
	}
	return row
}

func assertLegacyPolicyReceipt(t *testing.T, w *httptest.ResponseRecorder, want int) RuntimePolicy {
	t.Helper()
	if w.Code != want {
		t.Fatalf("policy response status%d want%d: %s", w.Code, want, w.Body.String())
	}
	var p RuntimePolicy
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.ID == uuid.Nil || p.DPPolicyID <= 0 || p.Version <= 0 || p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Fatalf("response omitted committed policy metadata %+v", p)
	}
	return p
}

func TestLegacyPolicyCreateAndUpdateAuditCaptureCommittedBeforeAndAfter(t *testing.T) {
	f := reviewedFixture(t)
	body := legacyCreateBody(f.cluster)
	created := assertLegacyPolicyReceipt(t, legacyPolicyRequest(t, f, f.org, uuid.Nil, "create", body), 201)
	event := lastLegacyPolicyAudit(t, f, created.ID)
	if event.action != audit.ActionPolicyCreate || event.before != nil || event.after["cluster_id"] != f.cluster.String() || event.after["revision"] != "1" {
		t.Fatalf("incorrect create audit %+v", event)
	}
	if w := legacyPolicyRequest(t, f, f.org, uuid.Nil, "create", body); w.Code != 409 {
		t.Fatalf("duplicate status%d", w.Code)
	}
	updated := assertLegacyPolicyReceipt(t, legacyPolicyRequest(t, f, f.org, f.id, "update", map[string]any{"name": "renamed", "rules": []any{map[string]any{"port": 80, "action": 2}, map[string]any{"port": 443, "action": 7}}}), 200)
	if updated.Version != 2 || updated.Name != "renamed" || updated.Mode != PolicyModeMonitor {
		t.Fatalf("wrong committed update %+v", updated)
	}
	event = lastLegacyPolicyAudit(t, f, f.id)
	if event.action != audit.ActionPolicyUpdate || event.before["name"] != "reviewed" || event.after["name"] != "renamed" || event.before["rule_count"] != float64(1) || event.after["rule_count"] != float64(2) || event.before["revision"] != "1" || event.after["revision"] != "2" {
		t.Fatalf("before snapshot was mutated: %+v", event)
	}
	if event.actor == nil || *event.actor != f.actor || event.request != "legacy-fixture-request" {
		t.Fatal("audit actor/request missing")
	}
}

func TestLegacyPolicyModeAndDeleteAuditStayAtomicAndCompatible(t *testing.T) {
	f := reviewedFixture(t)
	promoted := assertLegacyPolicyReceipt(t, legacyPolicyRequest(t, f, f.org, f.id, "promote", nil), 200)
	if promoted.Mode != PolicyModeEnforce || promoted.Version != 2 {
		t.Fatalf("wrong promoted receipt %+v", promoted)
	}
	if event := lastLegacyPolicyAudit(t, f, f.id); event.action != audit.ActionPolicyPromote || event.before["mode"] != "monitor" || event.after["mode"] != "enforce" {
		t.Fatalf("wrong promote audit %+v", event)
	}
	if err := f.h.store.SetMode(t.Context(), f.org, f.id, PolicyModeMonitor, uuid.Nil, true, "auto-rollback"); err != nil {
		t.Fatal(err)
	}
	if event := lastLegacyPolicyAudit(t, f, f.id); event.action != audit.ActionPolicyAutoRollback || event.actor != nil || event.after["mode"] != "monitor" {
		t.Fatalf("wrong system audit %+v", event)
	}
	disabled := assertLegacyPolicyReceipt(t, legacyPolicyRequest(t, f, f.org, f.id, "disable", nil), 200)
	if disabled.Mode != PolicyModeDisabled || disabled.Version != 4 {
		t.Fatalf("wrong disabled receipt %+v", disabled)
	}
	if w := legacyPolicyRequest(t, f, f.org, f.id, "delete", nil); w.Code != 200 {
		t.Fatalf("delete status%d", w.Code)
	}
	if event := lastLegacyPolicyAudit(t, f, f.id); event.action != audit.ActionPolicyDelete || event.after != nil || event.before["revision"] != "4" {
		t.Fatalf("wrong delete audit %+v", event)
	}
	if _, err := f.h.store.Get(t.Context(), f.org, f.id); err == nil {
		t.Fatal("delete did not commit")
	}
}

func TestLegacyPolicyConcurrentPatchesDoNotLoseFields(t *testing.T) {
	f := reviewedFixture(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make(chan int, 2)
	for _, body := range []map[string]any{{"name": "concurrent name"}, {"def_action": 7}} {
		wg.Add(1)
		go func(body map[string]any) {
			defer wg.Done()
			<-start
			codes <- legacyPolicyRequest(t, f, f.org, f.id, "update", body).Code
		}(body)
	}
	close(start)
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 {
			t.Fatalf("concurrent patch status%d", code)
		}
	}
	got, err := f.h.store.Get(t.Context(), f.org, f.id)
	if err != nil || got.Name != "concurrent name" || got.DefAction != 7 || got.Version != 3 || f.countAudit(t) != 2 {
		t.Fatalf("lost concurrent patch or audit %+v %v", got, err)
	}
	rows, err := f.h.store.db.Pool().Query(t.Context(), `SELECT before->>'revision',after->>'revision' FROM audit_events WHERE org_id=$1 ORDER BY id`, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for version := 1; rows.Next(); version++ {
		var before, after string
		if err := rows.Scan(&before, &after); err != nil {
			t.Fatal(err)
		}
		if before != fmt.Sprint(version) || after != fmt.Sprint(version+1) {
			t.Fatalf("audit skipped locked state: %s->%s", before, after)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
