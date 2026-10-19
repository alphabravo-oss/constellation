package scanning

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/scanlease"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Ordinary endpoint tests emulate a worker echoing its current claim. Fencing
// tests deliberately do not use this helper: they carry specific old/new IDs.
func currentScanLeaseRequest(t *testing.T, pool *pgxpool.Pool, req *http.Request) *http.Request {
	t.Helper()
	id := chi.URLParam(req, "id")
	if id == "" {
		return req
	}
	var lease *uuid.UUID
	if err := pool.QueryRow(req.Context(), `SELECT lease_id FROM scan_jobs WHERE id=$1`, id).Scan(&lease); err == nil && lease != nil {
		req.Header.Set(scanlease.Header, lease.String())
	}
	return req
}

func TestScanLeaseFencesExpiredAndSupersededClaims(t *testing.T) {
	for _, mode := range []string{"expired", "legacy-expired", "lock-expiry", "reclaimed", "manual-retry", "missing"} {
		for _, action := range []string{"renew", "fail", "complete"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				d := openTestDB(t)
				defer d.Close()
				pool := d.Pool()
				ctx := t.Context()
				org, target, job := uuid.New(), uuid.New(), uuid.New()
				exec := func(q string, args ...any) {
					t.Helper()
					if _, err := pool.Exec(ctx, q, args...); err != nil {
						t.Fatal(err)
					}
				}
				exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "lease-fence-"+org.String())
				defer pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
				ref := "example.test/fence@sha256:" + strings.Repeat("a", 64)
				exec(`INSERT INTO scan_targets(id,org_id,type,ref,source_type,image_ref) VALUES($1,$2,'image',$3,'manual',$3)`, target, org, ref)
				exec(`INSERT INTO scan_jobs(id,org_id,target_id,status) VALUES($1,$2,$3,'pending')`, job, org, target)
				token, _, err := handler.IssueScannerToken(ctx, pool, org, "fence", time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				h := NewScanJobs(d, audit.New(pool))
				call := func(fn http.HandlerFunc, lease, body string) *httptest.ResponseRecorder {
					req := httptest.NewRequestWithContext(ctx, "POST", "/scan", strings.NewReader(body))
					req.Header.Set("Authorization", "Bearer "+token)
					req.Header.Set("X-Constellation-Scanner-Instance", "same-worker")
					if lease != "" {
						req.Header.Set(scanlease.Header, lease)
					}
					req = withRouteParam(req, "id", job.String())
					rec := httptest.NewRecorder()
					handler.ScannerTokenMiddleware(pool)(fn).ServeHTTP(rec, req)
					return rec
				}
				claim := func() string {
					t.Helper()
					rec := call(h.Claim, "", "")
					if rec.Code != 200 {
						t.Fatalf("claim %d %s", rec.Code, rec.Body.String())
					}
					var response struct {
						LeaseID string `json:"lease_id"`
					}
					if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					if _, err := uuid.Parse(response.LeaseID); err != nil {
						t.Fatalf("missing claim identity: %s", rec.Body.String())
					}
					return response.LeaseID
				}
				original := claim()
				current := original
				if mode == "expired" || mode == "legacy-expired" || mode == "reclaimed" {
					exec(`UPDATE scan_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, job)
				}
				if mode == "legacy-expired" {
					exec(`UPDATE scan_jobs SET lease_id=NULL WHERE id=$1`, job)
				}
				if mode == "reclaimed" {
					current = claim()
				}
				if mode == "manual-retry" {
					rec := call(h.Fail, original, `{"error":"test","retryable":false}`)
					if rec.Code != 200 {
						t.Fatalf("fail %d %s", rec.Code, rec.Body.String())
					}
					req := httptest.NewRequestWithContext(ctx, "POST", "/retry", nil)
					req = withRouteParam(req, "id", job.String())
					req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org}))
					rec = httptest.NewRecorder()
					h.Retry(rec, req)
					if rec.Code != 200 {
						t.Fatalf("retry %d %s", rec.Code, rec.Body.String())
					}
					current = claim()
					var attempt int
					if err := pool.QueryRow(ctx, `SELECT attempt_count FROM scan_jobs WHERE id=$1`, job).Scan(&attempt); err != nil || attempt != 1 {
						t.Fatalf("retry counter %d %v", attempt, err)
					}
				}
				if (mode == "reclaimed" || mode == "manual-retry") && current == original {
					t.Fatal("claim identity reused")
				}
				sent := original
				if mode == "missing" || mode == "legacy-expired" {
					sent = ""
				}
				body := `{"image_ref":"` + ref + `","package_count":1,"findings":[{"vulnerability_id":"CVE-2026-12345","severity":"high","package":{"name":"example","version":"1","ecosystem":"deb"}}]}`
				fn := h.Complete
				if action == "renew" {
					fn = h.RenewLease
				}
				if action == "fail" {
					fn = h.Fail
					body = `{"error":"late failure","retryable":false}`
				}
				if mode == "lock-expiry" {
					exec(`UPDATE scan_jobs SET lease_expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, job)
				}
				var before string
				if err := pool.QueryRow(ctx, `SELECT row_to_json(sj)::text FROM scan_jobs sj WHERE id=$1`, job).Scan(&before); err != nil {
					t.Fatal(err)
				}
				var rec *httptest.ResponseRecorder
				if mode == "lock-expiry" {
					tx, err := pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(context.Background())
					if _, err = tx.Exec(ctx, `SELECT id FROM scan_jobs WHERE id=$1 FOR UPDATE`, job); err != nil {
						t.Fatal(err)
					}
					done := make(chan *httptest.ResponseRecorder, 1)
					go func() { done <- call(fn, sent, body) }()
					select {
					case <-done:
						t.Fatal("lease mutation bypassed job lock")
					case <-time.After(1200 * time.Millisecond):
					}
					if err = tx.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case rec = <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("blocked request did not finish")
					}
				} else {
					rec = call(fn, sent, body)
				}
				if rec.Code != 409 {
					t.Fatalf("late %s %d %s", action, rec.Code, rec.Body.String())
				}
				var after string
				if err := pool.QueryRow(ctx, `SELECT row_to_json(sj)::text FROM scan_jobs sj WHERE id=$1`, job).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if before != after {
					t.Fatal("rejected request mutated job")
				}
				var results int
				if err := pool.QueryRow(ctx, `SELECT count(*) FROM image_scan_results WHERE org_id=$1`, org).Scan(&results); err != nil || results != 0 {
					t.Fatalf("rejected request wrote results: %d %v", results, err)
				}
				if mode != "expired" && mode != "legacy-expired" && mode != "lock-expiry" {
					rec = call(h.RenewLease, current, "")
					if rec.Code != 200 {
						t.Fatalf("current renewal %d %s", rec.Code, rec.Body.String())
					}
					rec = call(h.Complete, current, `{"image_ref":"`+ref+`","findings":[]}`)
					if rec.Code != 200 {
						t.Fatalf("current completion %d %s", rec.Code, rec.Body.String())
					}

				}
			})
		}
	}
}
