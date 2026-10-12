package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestRoutingRevisionPreconditions(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	orgID, userID := uuid.New(), uuid.New()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs (id,name,display_name) VALUES ($1,$2,'Routing test')`, orgID, orgID.String()); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.Pool().Exec(ctx, `DELETE FROM orgs WHERE id=$1`, orgID) }()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO users (id,org_id,email,display_name) VALUES ($1,$2,$3,'Routing admin')`, userID, orgID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	h := NewReceivers(d, nil, nil)
	subject := Subject{OrgID: orgID, UserID: userID}
	put := func(subj Subject, yaml, match string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"yaml": yaml})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/routing.yaml", strings.NewReader(string(body)))
		req = req.WithContext(WithSubject(req.Context(), subj))
		if match != "" {
			req.Header.Set("If-Match", match)
		}
		w := httptest.NewRecorder()
		h.PutRoutingYAML(w, req)
		return w
	}
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/routing.yaml", nil)
		req = req.WithContext(WithSubject(req.Context(), subject))
		w := httptest.NewRecorder()
		h.GetRoutingYAML(w, req)
		return w
	}
	assertStatus := func(w *httptest.ResponseRecorder, want int) {
		t.Helper()
		if w.Code != want {
			t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
		}
	}
	assertStored := func(want string, revision int) {
		t.Helper()
		w := get()
		assertStatus(w, http.StatusOK)
		var got struct {
			YAML     string `json:"yaml"`
			Revision int    `json:"revision"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.YAML != want || got.Revision != revision || w.Header().Get("ETag") != fmt.Sprintf(`"%d"`, revision) {
			t.Fatalf("stored=%+v etag=%s", got, w.Header().Get("ETag"))
		}
	}
	assertStored("", 0)
	for _, match := range []string{`0`, `*`, `W/"0"`, `"-1"`, `"1", "2"`, `"9223372036854775808"`} {
		assertStatus(put(subject, "invalid", match), http.StatusBadRequest)
	}
	assertStatus(put(subject, "absent", `"1"`), http.StatusPreconditionFailed)
	assertStored("", 0)
	// Two writers loading the same revision must never both succeed, including
	// the first save where no routing_configs row exists yet.
	for revision := 0; revision < 2; revision++ {
		var results [2]*httptest.ResponseRecorder
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i] = put(subject, fmt.Sprintf("document-%d-%d", revision, i), fmt.Sprintf(`"%d"`, revision))
			}(i)
		}
		close(start)
		wg.Wait()
		winner := -1
		for i, w := range results {
			if w.Code == http.StatusOK {
				if winner != -1 {
					t.Fatal("concurrent stale writers both succeeded")
				}
				winner = i
				if w.Header().Get("ETag") != fmt.Sprintf(`"%d"`, revision+1) {
					t.Fatal("missing revision ETag")
				}
			} else {
				assertStatus(w, http.StatusPreconditionFailed)
			}
		}
		if winner < 0 {
			t.Fatal("neither writer succeeded")
		}
		assertStored(fmt.Sprintf("document-%d-%d", revision, winner), revision+1)
	}
	// Another organization cannot update this document even with its revision.
	assertStatus(put(Subject{OrgID: uuid.New(), UserID: userID}, "cross-tenant", `"2"`), http.StatusPreconditionFailed)
	assertStatus(put(subject, "stale", `"1"`), http.StatusPreconditionFailed)
	assertStatus(put(subject, "overflow", `"9223372036854775807"`), http.StatusPreconditionFailed)
	// Existing non-conditional clients retain their API behavior.
	assertStatus(put(subject, "legacy", ""), http.StatusOK)
	assertStored("legacy", 3)
	assertStatus(put(subject, "updated", `"3"`), http.StatusOK)
	assertStored("updated", 4)
}
