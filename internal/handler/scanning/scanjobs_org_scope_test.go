package scanning

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestScanJobs_RejectsJobWithForeignOrgTarget(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := context.Background()
	pool := database.Pool()
	jobOrgID, targetOrgID := uuid.New(), uuid.New()
	targetID, jobID := uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{jobOrgID, targetOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "scan-org-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, jobOrgID, targetOrgID)
	}()
	rawToken, tokenID, err := handler.IssueScannerToken(ctx, pool, jobOrgID, "org-scope", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref, last_seen_at)
		VALUES ($1, $2, 'image', $3, 'manual', $3, NOW() - INTERVAL '1 hour')`, targetID, targetOrgID, "registry.example.test/foreign-"+targetID.String()+":latest"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs (id, org_id, target_id, status) VALUES ($1, $2, $3, 'pending')`, jobID, jobOrgID, targetID); err != nil {
		t.Fatal(err)
	}
	h := NewScanJobs(database, nil)
	request := func(method, path string, body []byte, endpoint http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rawToken)
		route := chi.NewRouteContext()
		route.URLParams.Add("id", jobID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		rec := httptest.NewRecorder()
		handler.ScannerTokenMiddleware(pool)(endpoint).ServeHTTP(rec, req)
		return rec
	}
	if rec := request(http.MethodPost, "/api/v1/scan-jobs/claim", nil, h.Claim); rec.Code != http.StatusNoContent {
		t.Fatalf("foreign target claim: status=%d body=%s", rec.Code, rec.Body.String())
	}
	workerID := "scanner:org-scope:" + tokenID.String()
	if _, err := pool.Exec(ctx, `UPDATE scan_jobs SET status = 'running', worker_id = $2, claimed_at = NOW(), attempt_count = 1 WHERE id = $1`, jobID, workerID); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []struct {
		name       string
		body       []byte
		hand       http.HandlerFunc
		wantStatus int
	}{
		{"renew", nil, h.RenewLease, http.StatusConflict},
		{"complete", []byte(`{"package_count":1,"findings":[]}`), h.Complete, http.StatusNotFound},
		{"fail", []byte(`{"error":"failed"}`), h.Fail, http.StatusConflict},
	} {
		rec := request(http.MethodPost, "/api/v1/scan-jobs/"+jobID.String()+"/"+endpoint.name, endpoint.body, endpoint.hand)
		if rec.Code != endpoint.wantStatus {
			t.Fatalf("foreign target %s: status=%d body=%s", endpoint.name, rec.Code, rec.Body.String())
		}
	}
	var status, storedWorkerID string
	var leaseExpiresAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, worker_id, lease_expires_at FROM scan_jobs WHERE id = $1`, jobID).Scan(&status, &storedWorkerID, &leaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	if status != "running" || storedWorkerID != workerID || leaseExpiresAt != nil {
		t.Fatalf("foreign target job changed: status=%s worker=%s lease=%v", status, storedWorkerID, leaseExpiresAt)
	}
	var attemptCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM scan_job_attempts WHERE job_id = $1`, jobID).Scan(&attemptCount); err != nil {
		t.Fatal(err)
	}
	if attemptCount != 0 {
		t.Fatalf("foreign target job wrote %d attempts", attemptCount)
	}
	var targetLastSeenAt time.Time
	if err := pool.QueryRow(ctx, `SELECT last_seen_at FROM scan_targets WHERE id = $1`, targetID).Scan(&targetLastSeenAt); err != nil {
		t.Fatal(err)
	}
	if targetLastSeenAt.After(time.Now().Add(-30 * time.Minute)) {
		t.Fatalf("foreign target was updated at %v", targetLastSeenAt)
	}
}

func TestScanJobs_ClaimIgnoresEvidenceLinkedToForeignOrgTarget(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := context.Background()
	pool := database.Pool()
	jobOrgID, foreignOrgID := uuid.New(), uuid.New()
	targetID, foreignTargetID, jobID, evidenceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{jobOrgID, foreignOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "scan-evidence-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, jobOrgID, foreignOrgID)
	}()
	rawToken, _, err := handler.IssueScannerToken(ctx, pool, jobOrgID, "evidence-scope", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	imageRef := "registry.example.test/evidence-" + targetID.String() + ":latest"
	if _, err := pool.Exec(ctx, `INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref)
		VALUES ($1, $2, 'image', $5, 'manual', $5), ($3, $4, 'image', $5, 'manual', $5)`, targetID, jobOrgID, foreignTargetID, foreignOrgID, imageRef); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_evidence
		(id, org_id, scan_target_id, target_type, target_ref, source_type, evidence_type, inventory_hash, payload, observed_at)
		VALUES ($1, $2, $3, 'image', $4, 'manual', 'package-inventory', 'foreign-link', '{}'::jsonb, NOW())`,
		evidenceID, jobOrgID, foreignTargetID, imageRef); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs (id, org_id, target_id, status) VALUES ($1, $2, $3, 'pending')`, jobID, jobOrgID, targetID); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(NewScanJobs(database, nil).Claim)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("claim: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var claim struct {
		ID         uuid.UUID  `json:"id"`
		EvidenceID *uuid.UUID `json:"evidence_id"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&claim); err != nil {
		t.Fatal(err)
	}
	if claim.ID != jobID || claim.EvidenceID != nil {
		t.Fatalf("claim = %+v; foreign-linked evidence %s must be ignored", claim, evidenceID)
	}
}
