package scanning

import (
	"encoding/json"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestScanJobClaimPersistsInventoryAndRefreshesOnRetry(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := t.Context()
	org, target, job := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "claim-identity-"+org.String()); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
	if _, err := pool.Exec(ctx, `INSERT INTO scan_targets(id,org_id,type,ref,source_type,inventory_hash) VALUES($1,$2,'platform',$3,'platform','first')`, target, org, "cluster:"+target.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs(id,org_id,target_id,status) VALUES($1,$2,$3,'pending')`, job, org, target); err != nil {
		t.Fatal(err)
	}
	token, _, err := handler.IssueScannerToken(ctx, pool, org, "claim-identity", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(want string) {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/scan-jobs/claim", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(NewScanJobs(d, nil).Claim)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("claim %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			InventoryHash string `json:"inventory_hash"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		var saved string
		if err := pool.QueryRow(ctx, `SELECT claimed_inventory_hash FROM scan_jobs WHERE id=$1`, job).Scan(&saved); err != nil {
			t.Fatal(err)
		}
		if body.InventoryHash != want || saved != want {
			t.Fatalf("returned=%q saved=%q want=%q", body.InventoryHash, saved, want)
		}
	}
	claim("first")
	if _, err := pool.Exec(ctx, `UPDATE scan_targets SET inventory_hash='second' WHERE id=$1`, target); err != nil {
		t.Fatal(err)
	}
	var saved string
	if err := pool.QueryRow(ctx, `SELECT claimed_inventory_hash FROM scan_jobs WHERE id=$1`, job).Scan(&saved); err != nil || saved != "first" {
		t.Fatalf("mutable claim: %q %v", saved, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scan_jobs SET lease_expires_at=now()-interval '1 minute' WHERE id=$1`, job); err != nil {
		t.Fatal(err)
	}
	claim("second")
}
