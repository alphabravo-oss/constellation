package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	findinghandler "github.com/alphabravocompany/constellation/internal/handler/findings"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestFindingInstanceAuditScopeSurvivesRetention(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, actor, c1, c2, asset, id := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.Pool().Exec(t.Context(), q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name)VALUES($1::uuid,$1::text,'audit instances')`, org)
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM findings WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
	})
	exec(`INSERT INTO users(id,org_id,email,display_name)VALUES($1::uuid,$2,$1::text,'actor')`, actor, org)
	exec(`INSERT INTO clusters(id,org_id,name)VALUES($1,$3,'one'),($2,$3,'two')`, c1, c2, org)
	exec(`INSERT INTO assets(id,org_id,kind,name)VALUES($1,$2,'host','node')`, asset, org)
	a := time.Date(2026, 10, 12, 0, 0, 0, 123456000, time.UTC)
	b := a.Add(time.Microsecond)
	exec(`INSERT INTO findings(id,first_seen_at,org_id,cluster_id,asset_id,kind,title,severity)VALUES($1,$2,$4,$5,$7,'vulnerability','one','high'),($1,$3,$4,$6,$7,'vulnerability','two','high')`, id, a, b, org, c1, c2, asset)
	h := findinghandler.NewFindings(d, audit.New(d.Pool()), nil)
	for _, at := range []time.Time{a, b} {
		body := bytes.NewBufferString(`{"reason":"exact scope","reviewed_revision":"1"}`)
		r := httptest.NewRequest("POST", "/finding-instances/"+id.String()+"/suppress?first_seen_at="+url.QueryEscape(at.Format(time.RFC3339Nano)), body)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", id.String())
		ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
		r = r.WithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org, UserID: actor}))
		w := httptest.NewRecorder()
		h.Suppress(w, r)
		if w.Code != 200 {
			t.Fatalf("mutation%d %s", w.Code, w.Body)
		}
	}
	// Ambiguous old UUID events stay out of both exact cluster histories.
	_, _, err := audit.New(d.Pool()).Log(t.Context(), audit.Event{OrgID: &org, ActorID: &actor, Action: "finding.suppress", TargetKind: "finding", TargetID: id.String(), After: map[string]any{"reason": "legacy"}})
	if err != nil {
		t.Fatal(err)
	}
	read := func(cluster uuid.UUID) []auditDTO {
		t.Helper()
		r := httptest.NewRequest("GET", "/audit?cluster_id="+cluster.String(), nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org}))
		w := httptest.NewRecorder()
		NewAudit(d).List(w, r)
		if w.Code != 200 {
			t.Fatalf("audit%d %s", w.Code, w.Body)
		}
		var got struct {
			Events []auditDTO `json:"events"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		return got.Events
	}
	one, two := read(c1), read(c2)
	if len(one) != 1 || len(two) != 1 || one[0].ID == two[0].ID {
		t.Fatalf("borrowed occurrence audit%+v %+v", one, two)
	}
	exec(`DELETE FROM findings WHERE org_id=$1`, org)
	afterOne, afterTwo := read(c1), read(c2)
	if len(afterOne) != 1 || len(afterTwo) != 1 || afterOne[0].ID != one[0].ID || afterTwo[0].ID != two[0].ID {
		t.Fatal("retention lost recorded audit scope")
	}
}
