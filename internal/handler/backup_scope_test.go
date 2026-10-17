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

func TestBackupsLegacyReadsRequireExactOwner(t *testing.T) {
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
		if err := os.WriteFile(path, []byte("private backup "+id.String()), 0600); err != nil {
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
	h := &Backups{db: d, audit: audit.New(pool)}
	request := func(method string, id uuid.UUID, org uuid.UUID, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/backups/"+id.String(), nil)
		if authenticated {
			r = r.WithContext(WithSubject(r.Context(), Subject{OrgID: org}))
		}
		route := chi.NewRouteContext()
		route.URLParams.Add("id", id.String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		switch method {
		case "list":
			h.List(w, r)
		case "get":
			h.Get(w, r)
		case "download":
			h.Download(w, r)
		}
		return w
	}
	for i, org := range []uuid.UUID{owner, other} {
		t.Run(org.String(), func(t *testing.T) {
			w := request("list", uuid.Nil, org, true)
			var page struct {
				Backups []backupSummary `json:"backups"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Backups) != 1 || page.Backups[0].ID != ids[i].String() {
				t.Fatalf("list status=%d data=%s err=%v", w.Code, w.Body.String(), err)
			}
			for j, id := range ids {
				for _, method := range []string{"get", "download"} {
					w = request(method, id, org, true)
					if j == i {
						if w.Code != 200 {
							t.Fatalf("owned %s status=%d body=%s", method, w.Code, w.Body.String())
						}
						if method == "download" && w.Body.String() != "private backup "+id.String() {
							t.Fatalf("wrong owned artifact: %q", w.Body.String())
						}
					} else {
						if w.Code != 404 || strings.Contains(w.Body.String(), id.String()) || w.Header().Get("Content-Disposition") != "" {
							t.Fatalf("%s disclosed unowned backup: status=%d headers=%v body=%s", method, w.Code, w.Header(), w.Body.String())
						}
					}
				}
			}
			for _, method := range []string{"get", "download"} {
				absent := request(method, uuid.New(), org, true)
				unowned := request(method, ids[2], org, true)
				if absent.Code != unowned.Code || absent.Body.String() != unowned.Body.String() {
					t.Fatalf("%s enumerates inaccessible backup", method)
				}
			}
		})
	}
	for _, method := range []string{"list", "get", "download"} {
		if w := request(method, ids[0], owner, false); w.Code != 401 {
			t.Fatalf("unauthenticated %s status=%d", method, w.Code)
		}
	}
}
