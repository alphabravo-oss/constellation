//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type reviewedPolicyFixture struct {
	h                                                            *RuntimePoliciesHTTP
	org, actor, cluster, sibling, foreignOrg, foreignCluster, id uuid.UUID
}

func reviewedFixture(t *testing.T) reviewedPolicyFixture {
	t.Helper()
	d := openTestDB(t)
	t.Cleanup(d.Close)
	p := d.Pool()
	ctx := context.Background()
	f := reviewedPolicyFixture{org: uuid.New(), actor: uuid.New(), cluster: uuid.New(), sibling: uuid.New(), foreignOrg: uuid.New(), foreignCluster: uuid.New(), id: uuid.New()}
	f.h = NewRuntimePoliciesHTTP(d, audit.New(p))
	for _, org := range []uuid.UUID{f.org, f.foreignOrg} {
		if _, err := p.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "reviewed-policy-"+org.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = p.Exec(ctx, `DELETE FROM runtime_policies WHERE org_id IN($1,$2)`, f.org, f.foreignOrg)
		_, _ = p.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, f.org, f.foreignOrg)
	})
	if _, err := p.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, f.cluster, f.org, f.sibling, f.foreignCluster, f.foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO runtime_policies(id,org_id,cluster_id,workload,namespace,name,rules) VALUES($1,$2,$3,'app/api','app','reviewed','[{"port":443,"action":2}]')`, f.id, f.org, f.cluster); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f reviewedPolicyFixture) request(ctx context.Context, id, org uuid.UUID, operation string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	path := "/runtime-policies/" + id.String() + "/reviewed"
	if operation != "update" && operation != "delete" {
		path += "/" + operation
	}
	req := httptest.NewRequestWithContext(ctx, "POST", path, &buf)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id.String())
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rc)
	req = req.WithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org, UserID: f.actor}))
	res := httptest.NewRecorder()
	switch operation {
	case "update":
		f.h.ReviewedUpdate(res, req)
	case "promote":
		f.h.ReviewedPromote(res, req)
	case "demote":
		f.h.ReviewedDemote(res, req)
	case "disable":
		f.h.ReviewedDisable(res, req)
	case "delete":
		f.h.ReviewedDelete(res, req)
	}
	return res
}
func (f reviewedPolicyFixture) countAudit(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.h.store.db.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND target_id=$2`, f.org, f.id.String()).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
func TestRuntimePolicyReviewedRevisionAndExactScope(t *testing.T) {
	f := reviewedFixture(t)
	for _, c := range []struct {
		org, cluster uuid.UUID
		version      string
		want         int
	}{{f.org, f.cluster, "", 428}, {f.org, f.cluster, "01", 400}, {f.org, f.cluster, "+1", 400}, {f.org, f.cluster, "9223372036854775808", 400}, {f.org, f.cluster, "0", 400}, {f.org, f.sibling, "1", 404}, {f.org, f.foreignCluster, "1", 404}, {f.foreignOrg, f.foreignCluster, "1", 404}} {
		res := f.request(t.Context(), f.id, c.org, "update", map[string]any{"cluster_id": c.cluster, "expected_version": c.version, "name": "do not save"})
		if res.Code != c.want {
			t.Fatalf("guard %d want%d %s", res.Code, c.want, res.Body.String())
		}
	}
	if f.countAudit(t) != 0 {
		t.Fatal("guard failure appended audit")
	}
	version := 1
	for _, operation := range []string{"update", "promote", "demote", "disable"} {
		body := map[string]any{"cluster_id": f.cluster, "expected_version": strconv.Itoa(version)}
		if operation == "update" {
			body["name"] = "name-only edit"
		}
		res := f.request(t.Context(), f.id, f.org, operation, body)
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", operation, res.Code, res.Body.String())
		}
		var got RuntimePolicy
		if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		version++
		if got.ID != f.id || got.ClusterID != f.cluster || got.OrgID != f.org || got.Workload != "app/api" || got.Version != int64(version) || got.Revision != strconv.Itoa(version) || got.Name != "name-only edit" {
			t.Fatalf("receipt %+v", got)
		}
		beforeCount := f.countAudit(t)
		for _, staleOperation := range []string{"update", "promote", "demote", "disable", "delete"} {
			stale := f.request(t.Context(), f.id, f.org, staleOperation, map[string]any{"cluster_id": f.cluster, "expected_version": strconv.Itoa(version - 1)})
			if stale.Code != 409 {
				t.Fatalf("stale%s %d %s", staleOperation, stale.Code, stale.Body.String())
			}
		}
		if f.countAudit(t) != beforeCount {
			t.Fatal("stale writes appended audit")
		}
	}
	if f.countAudit(t) != 4 {
		t.Fatal("missing successful atomic audit")
	}
	res := f.request(t.Context(), f.id, f.org, "delete", map[string]any{"cluster_id": f.cluster, "expected_version": strconv.Itoa(version)})
	var receipt map[string]any
	_ = json.Unmarshal(res.Body.Bytes(), &receipt)
	if res.Code != 200 || receipt["deleted"] != f.id.String() || receipt["revision"] != strconv.Itoa(version) || receipt["cluster_id"] != f.cluster.String() || receipt["workload"] != "app/api" || f.countAudit(t) != 5 {
		t.Fatalf("delete receipt %d %s", res.Code, res.Body.String())
	}
	if _, err := f.h.store.Get(context.Background(), f.org, f.id); err == nil {
		t.Fatal("delete retained policy")
	}
}
func TestRuntimePolicyReviewedConcurrentWriteOneWinner(t *testing.T) {
	f := reviewedFixture(t)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, name := range []string{"first", "second"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			res := f.request(t.Context(), f.id, f.org, "update", map[string]any{"cluster_id": f.cluster, "expected_version": "1", "name": name})
			codes <- res.Code
		}(name)
	}
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[200] != 1 || counts[409] != 1 || f.countAudit(t) != 1 {
		t.Fatalf("concurrent %+v", counts)
	}
	got, err := f.h.store.Get(context.Background(), f.org, f.id)
	if err != nil || got.Revision != "2" {
		t.Fatalf("version %+v %v", got, err)
	}
}
func TestRuntimePolicyReviewedAuditFailureRollsBackAndLegacyRenameInvalidates(t *testing.T) {
	f := reviewedFixture(t)
	pool := f.h.store.db.Pool()
	ctx := context.Background()
	function := pgx.Identifier{"reject_reviewed_" + uuid.New().String()}.Sanitize()
	trigger := pgx.Identifier{"reject_reviewed_" + uuid.New().String()}.Sanitize()
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid THEN RAISE EXCEPTION 'fixture audit rejected'; END IF; RETURN NEW; END $$`, function, f.org)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER `+trigger+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION `+function+`() `); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+trigger+` ON audit_events`)
		_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+function+`()`)
	})
	for _, operation := range []string{"update", "promote", "delete"} {
		res := f.request(t.Context(), f.id, f.org, operation, map[string]any{"cluster_id": f.cluster, "expected_version": "1"})
		if res.Code != 500 {
			t.Fatalf("audit %s %d %s", operation, res.Code, res.Body.String())
		}
		got, err := f.h.store.Get(ctx, f.org, f.id)
		if err != nil || got.Revision != "1" || got.Mode != PolicyModeMonitor || f.countAudit(t) != 0 {
			t.Fatalf("audit failure committed %+v %v", got, err)
		}
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER `+trigger+` ON audit_events`); err != nil {
		t.Fatal(err)
	}
	// An old replica's name-only edit still advances the same revision.
	req := httptest.NewRequestWithContext(t.Context(), "PUT", "/runtime-policies/"+f.id.String(), bytes.NewBufferString(`{"name":"legacy rename"}`))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: f.org, UserID: f.actor}))
	res := httptest.NewRecorder()
	f.h.Update(res, req)
	if res.Code != 200 {
		t.Fatalf("legacy %d %s", res.Code, res.Body.String())
	}
	got, err := f.h.store.Get(ctx, f.org, f.id)
	if err != nil || got.Revision != "2" {
		t.Fatalf("legacy revision %+v %v", got, err)
	}
	stale := f.request(t.Context(), f.id, f.org, "update", map[string]any{"cluster_id": f.cluster, "expected_version": "1"})
	if stale.Code != 409 {
		t.Fatalf("legacy stale %d %s", stale.Code, stale.Body.String())
	}
}

func TestRuntimePolicyReviewedOldReplicaNameWriteBumpsRevision(t *testing.T) {
	f := reviewedFixture(t)
	ctx := context.Background()
	before, err := f.h.store.Get(ctx, f.org, f.id)
	if err != nil {
		t.Fatal(err)
	}
	// This is the pre-175 replica SQL; only the database trigger can observe it.
	if _, err := f.h.store.db.Pool().Exec(ctx, `UPDATE runtime_policies SET name='old replica rename',updated_by=$1 WHERE id=$2 AND org_id=$3`, f.actor, f.id, f.org); err != nil {
		t.Fatal(err)
	}
	after, err := f.h.store.Get(ctx, f.org, f.id)
	if err != nil || after.Revision != "2" || !after.UpdatedAt.After(before.UpdatedAt) {
		t.Fatalf("old replica revision %+v %v", after, err)
	}
	res := f.request(t.Context(), f.id, f.org, "update", map[string]any{"cluster_id": f.cluster, "expected_version": "1", "name": "stale overwrite"})
	if res.Code != 409 || f.countAudit(t) != 0 {
		t.Fatalf("old replica stale %d %s", res.Code, res.Body.String())
	}
}
