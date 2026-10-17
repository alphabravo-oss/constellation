package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

type backupScopeFixture struct {
	handler *Backups
	orgs    []uuid.UUID
	ids     []uuid.UUID
}

func TestBackupsLegacyReadsRequireExactOwner(t *testing.T) {
	f := newBackupScopeFixture(t)
	for i, org := range f.orgs {
		t.Run(org.String(), func(t *testing.T) {
			assertBackupScopeList(t, f, org, f.ids[i])
			for j, id := range f.ids {
				for _, method := range []string{"get", "download"} {
					assertBackupScopeItem(t, f.request(t.Context(), method, id, org, true), method, id, j == i)
				}
			}
			for _, method := range []string{"get", "download"} {
				absent := f.request(t.Context(), method, uuid.New(), org, true)
				unowned := f.request(t.Context(), method, f.ids[2], org, true)
				if absent.Code != unowned.Code || absent.Body.String() != unowned.Body.String() {
					t.Fatalf("%s enumerates inaccessible backup", method)
				}
			}
		})
	}
	for _, method := range []string{"list", "get", "download"} {
		if w := f.request(t.Context(), method, f.ids[0], f.orgs[0], false); w.Code != 401 {
			t.Fatalf("unauthenticated %s status=%d", method, w.Code)
		}
	}
}

func newBackupScopeFixture(t *testing.T) *backupScopeFixture {
	t.Helper()
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	owner, other, deleted := uuid.New(), uuid.New(), uuid.New()
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'owner'),($2::uuid,$2::text,'other'),($3::uuid,$3::text,'deleted')`, owner, other, deleted)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM backups WHERE id=ANY($1)`, ids)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=ANY($1)`, []uuid.UUID{owner, other, deleted})
	})
	root := t.TempDir()
	owners := []any{owner, other, nil, deleted}
	for i, id := range ids {
		path := filepath.Join(root, id.String()+".tar.gz")
		if err := os.WriteFile(path, []byte("private backup "+id.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO backups(id,org_id,mode,status,local_path,error) VALUES($1,$2,'org-backup','succeeded',$3,$4)`, id, owners[i], path, "private metadata "+id.String())
	}
	// The schema preserves the artifact while clearing its owner on org deletion.
	exec(`DELETE FROM orgs WHERE id=$1`, deleted)
	var orphanOwner *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT org_id FROM backups WHERE id=$1`, ids[3]).Scan(&orphanOwner); err != nil || orphanOwner != nil {
		t.Fatalf("deleted org fixture owner=%v err=%v", orphanOwner, err)
	}
	return &backupScopeFixture{handler: &Backups{db: d, audit: audit.New(pool)}, orgs: []uuid.UUID{owner, other}, ids: ids}
}

func (f *backupScopeFixture) request(ctx context.Context, method string, id, org uuid.UUID, authenticated bool) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/backups/"+id.String(), nil)
	if authenticated {
		ctx = WithSubject(ctx, Subject{OrgID: org})
	}
	route := chi.NewRouteContext()
	route.URLParams.Add("id", id.String())
	r = r.WithContext(context.WithValue(ctx, chi.RouteCtxKey, route))
	w := httptest.NewRecorder()
	switch method {
	case "list":
		f.handler.List(w, r)
	case "get":
		f.handler.Get(w, r)
	case "download":
		f.handler.Download(w, r)
	}
	return w
}

func assertBackupScopeList(t *testing.T, f *backupScopeFixture, org, want uuid.UUID) {
	t.Helper()
	w := f.request(t.Context(), "list", uuid.Nil, org, true)
	var page struct {
		Backups []backupSummary `json:"backups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Backups) != 1 || page.Backups[0].ID != want.String() {
		t.Fatalf("list status=%d data=%s err=%v", w.Code, w.Body.String(), err)
	}
}

func assertBackupScopeItem(t *testing.T, w *httptest.ResponseRecorder, method string, id uuid.UUID, owned bool) {
	t.Helper()
	if !owned {
		if w.Code != 404 || strings.Contains(w.Body.String(), id.String()) || w.Header().Get("Content-Disposition") != "" {
			t.Fatalf("%s disclosed unowned backup: status=%d headers=%v body=%s", method, w.Code, w.Header(), w.Body.String())
		}
		return
	}
	if w.Code != 200 {
		t.Fatalf("owned %s status=%d body=%s", method, w.Code, w.Body.String())
	}
	if method == "download" && w.Body.String() != "private backup "+id.String() {
		t.Fatalf("wrong owned artifact: %q", w.Body.String())
	}
}
