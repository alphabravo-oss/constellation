//go:build integration

package handler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Exact instance selectors and reviewed revisions must survive the master/joint
// boundary unchanged, including microseconds and conflicts from an older receipt.
func TestFedProxyFindingInstanceIdentityAndPreconditions(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool, ctx := d.Pool(), t.Context()
	var org, user uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Fatalf("seed organization required: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, org).Scan(&user); err != nil {
		t.Fatalf("seed user required: %v", err)
	}
	id := uuid.NewString()
	rawQuery := "first_seen_at=2026-10-10T00%3A00%3A00.123456%2B00%3A00&cluster_id=" + uuid.NewString()
	receipt := fmt.Sprintf(`{"id":%q,"first_seen_at":"2026-10-10T00:00:00.123456Z","revision":"9007199254740994"}`, id)
	type observed struct{ method, path, query, body, auth, cookie string }
	received := make(chan observed, 8)
	joint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- observed{r.Method, r.URL.Path, r.URL.RawQuery, string(body), r.Header.Get("Authorization"), r.Header.Get("Cookie")}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), `"reviewed_revision":"1"`) {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"finding changed; review the current instance"}`)
			return
		}
		_, _ = io.WriteString(w, receipt)
	}))
	t.Cleanup(joint.Close)
	cluster := insertMember(t, ctx, d, org, joint.URL)
	h := NewFedProxy(d, audit.New(pool))
	for _, test := range []struct {
		name, method, suffix, body string
		status                     int
	}{
		{"read", http.MethodGet, "", "", http.StatusOK},
		{"action", http.MethodPost, "/triage", `{"reviewed_revision":"9007199254740993"}`, http.StatusOK},
		{"comment", http.MethodPost, "/comments", `{"reviewed_revision":"9007199254740993","body":"Review this occurrence only"}`, http.StatusOK},
		{"conflict", http.MethodPost, "/triage", `{"reviewed_revision":"1"}`, http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := "finding-instances/" + id + test.suffix
			w := forwardReq(t, h, adminSubject(org, user), test.method, cluster, path, rawQuery, test.body)
			if w.Code != test.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			got := <-received
			if got.method != test.method || got.path != "/api/v1/"+path || got.query != rawQuery || got.body != test.body {
				t.Fatalf("exact request changed: %+v", got)
			}
			if got.auth != "" || got.cookie != "" {
				t.Fatal("caller credentials reached joint")
			}
			if test.status == http.StatusOK && w.Body.String() != receipt {
				t.Fatalf("exact receipt changed: %s", w.Body.String())
			}
			if test.status == http.StatusConflict && !strings.Contains(w.Body.String(), "finding changed") {
				t.Fatalf("conflict lost: %s", w.Body.String())
			}
		})
	}
	reader := readerSubject(org, user)
	path := "finding-instances/" + id
	if w := forwardReq(t, h, reader, http.MethodGet, cluster, path, rawQuery, ""); w.Code != http.StatusOK {
		t.Fatalf("reader exact GET: %d %s", w.Code, w.Body.String())
	}
	<-received
	if w := forwardReq(t, h, reader, http.MethodPost, cluster, path+"/triage", rawQuery, `{"reviewed_revision":"1"}`); w.Code != http.StatusForbidden {
		t.Fatalf("reader mutation: %d", w.Code)
	}
	custom := NewFedProxy(d, audit.New(pool)).WithReadAllowlist([]string{"findings"})
	if w := forwardReq(t, custom, reader, http.MethodGet, cluster, path, rawQuery, ""); w.Code != http.StatusForbidden {
		t.Fatalf("custom allowlist was widened: %d", w.Code)
	}
	select {
	case got := <-received:
		t.Fatalf("blocked request reached joint: %+v", got)
	default:
	}
}
