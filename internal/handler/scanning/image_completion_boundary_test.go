package scanning

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestImageCompletionRejectsConflictingIdentityBeforeWrites(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := t.Context()
	org, target, job := uuid.New(), uuid.New(), uuid.New()
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	ref := "example.test/app@" + a
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "image-boundary-"+org.String())
	defer pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
	exec(`INSERT INTO scan_targets(id,org_id,type,ref,source_type,image_ref,image_digest) VALUES($1,$2,'image',$3,'manual',$3,$4)`, target, org, ref, a)
	exec(`INSERT INTO scan_jobs(id,org_id,target_id,status) VALUES($1,$2,$3,'pending')`, job, org, target)
	token, _, err := handler.IssueScannerToken(ctx, pool, org, "image-boundary", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := NewScanJobs(d, audit.New(pool))
	request := func(body []byte, fn http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/scan", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req = withRouteParam(req, "id", job.String())
		rec := httptest.NewRecorder()
		handler.ScannerTokenMiddleware(pool)(fn).ServeHTTP(rec, currentScanLeaseRequest(t, pool, req))
		return rec
	}
	if rec := request(nil, h.Claim); rec.Code != 200 {
		t.Fatalf("claim %d %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []map[string]any{{"image_ref": ref, "image_digest": b}, {"image_ref": "example.test/other@" + a, "image_digest": a}, {"image_ref": ref, "image_digest": "sha256:abc"}} {
		raw, _ := json.Marshal(bad)
		rec := request(raw, h.Complete)
		if rec.Code != 400 {
			t.Fatalf("bad identity accepted %d %s", rec.Code, rec.Body.String())
		}
		var state, digest string
		if err := pool.QueryRow(ctx, `SELECT sj.status,st.image_digest FROM scan_jobs sj JOIN scan_targets st ON st.id=sj.target_id WHERE sj.id=$1`, job).Scan(&state, &digest); err != nil {
			t.Fatal(err)
		}
		if state != "running" || digest != a {
			t.Fatalf("invalid completion mutated job/target: %s %s", state, digest)
		}
		for _, table := range []string{"findings", "assets", "image_scan_results", "audit_events"} {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE org_id=$1`, org).Scan(&n); err != nil || n != 0 {
				t.Fatalf("invalid completion wrote %s: count=%d err=%v", table, n, err)
			}
		}
	}
	raw, _ := json.Marshal(map[string]any{"image_ref": ref, "image_digest": a, "findings": []any{}})
	if rec := request(raw, h.Complete); rec.Code != 200 {
		t.Fatalf("valid completion failed %d %s", rec.Code, rec.Body.String())
	}
}
