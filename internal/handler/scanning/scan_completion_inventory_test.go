package scanning

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/responserule"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestScanCompletionPreservesClaimProvenanceAcrossTargetUpdates(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "outdated"}[changed], func(t *testing.T) {
			d := openTestDB(t)
			defer d.Close()
			pool := d.Pool()
			ctx := t.Context()
			org, cluster, target, job := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "completion-identity-"+org.String())
			defer pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
			exec(`INSERT INTO clusters(id,org_id,name,state) VALUES($1,$2,$3,'connected')`, cluster, org, "cluster-"+cluster.String())
			exec(`INSERT INTO scan_targets(id,org_id,cluster_id,type,ref,source_type,inventory_hash,platform) VALUES($1,$2,$3,'platform',$4,'platform','first','original')`, target, org, cluster, "cluster:"+cluster.String())
			exec(`INSERT INTO scan_jobs(id,org_id,target_id,status) VALUES($1,$2,$3,'pending')`, job, org, target)
			token, _, err := handler.IssueScannerToken(ctx, pool, org, "completion", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			h := NewScanJobs(d, audit.New(pool))
			evaluations := 0
			h.evalResponseRules = func(context.Context, uuid.UUID, *responserule.Event) ([]responserule.Action, error) {
				evaluations++
				return nil, nil
			}
			request := func(path string, body []byte, fn http.HandlerFunc) *httptest.ResponseRecorder {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+token)
				req = withRouteParam(req, "id", job.String())
				rec := httptest.NewRecorder()
				handler.ScannerTokenMiddleware(pool)(fn).ServeHTTP(rec, currentScanLeaseRequest(t, pool, req))
				return rec
			}
			rec := request("/claim", nil, h.Claim)
			if rec.Code != 200 {
				t.Fatalf("claim %d %s", rec.Code, rec.Body.String())
			}
			if changed {
				exec(`UPDATE scan_targets SET inventory_hash='second',platform='newer' WHERE id=$1`, target)
			}
			body, _ := json.Marshal(map[string]any{"platform": "scanned-platform", "package_count": 1, "findings": []scanner.Finding{{VulnerabilityID: "CVE-2026-12345", Severity: "high", Package: scanner.Package{Name: "example", Version: "1.0", Ecosystem: "generic"}}}})
			rec = request("/complete", body, h.Complete)
			if rec.Code != 200 {
				t.Fatalf("complete %d %s", rec.Code, rec.Body.String())
			}
			want := "current"
			hash, platform := "first", "scanned-platform"
			wantEvaluations := 1
			if changed {
				want = "outdated"
				hash, platform = "second", "newer"
				wantEvaluations = 0
			}
			if evaluations != wantEvaluations {
				t.Fatalf("response evaluations %d want %d", evaluations, wantEvaluations)
			}
			var actualHash, actualPlatform, status string
			if err := pool.QueryRow(ctx, `SELECT inventory_hash,platform FROM scan_targets WHERE id=$1`, target).Scan(&actualHash, &actualPlatform); err != nil {
				t.Fatal(err)
			}
			if actualHash != hash || actualPlatform != platform {
				t.Fatalf("target overwritten: %s %s", actualHash, actualPlatform)
			}
			var detail []byte
			if err := pool.QueryRow(ctx, `SELECT detail_json FROM findings WHERE org_id=$1 AND detail_json->>'target_id'=$2`, org, target.String()).Scan(&detail); err != nil {
				t.Fatal(err)
			}
			var provenance map[string]any
			json.Unmarshal(detail, &provenance)
			if provenance["scan_job_id"] != job.String() || provenance["claimed_inventory_hash"] != "first" || provenance["inventory_status_at_completion"] != want {
				t.Fatalf("finding provenance: %s", detail)
			}
			var after []byte
			if err := pool.QueryRow(ctx, `SELECT after FROM audit_events WHERE org_id=$1 AND action='scan-job.complete' AND target_id=$2`, org, job.String()).Scan(&after); err != nil {
				t.Fatal(err)
			}
			json.Unmarshal(after, &provenance)
			if provenance["claimed_inventory_hash"] != "first" || provenance["inventory_status_at_completion"] != want {
				t.Fatalf("audit provenance: %s", after)
			}
			if changed && provenance["response_rules_skipped"] != "inventory_changed_since_claim" {
				t.Fatalf("missing refusal audit %s", after)
			}
			if err := pool.QueryRow(ctx, `SELECT status FROM scan_jobs WHERE id=$1`, job).Scan(&status); err != nil || status != "completed" {
				t.Fatalf("historical completion lost %s %v", status, err)
			}
			rec = request("/complete", body, h.Complete)
			if rec.Code != 200 || evaluations != wantEvaluations {
				t.Fatal("repeated completion replayed responses")
			}
		})
	}
}
