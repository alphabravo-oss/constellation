package scanning

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/responserule"
	"github.com/alphabravocompany/constellation/pkg/vulnprofile"
)

func TestScannerFindingDetailIncludesVulnDBBundle(t *testing.T) {
	exportedAt := time.Date(2026, 6, 12, 1, 2, 3, 0, time.UTC)
	metadata := &scanner.BundleMetadata{
		SchemaVersion: "v2",
		BundleVersion: "fixture-20260612",
		Producer:      "constellation-vulndb",
		MediaType:     "application/vnd.constellation.vulndb.bundle.v2+json",
		ExportedAt:    exportedAt,
		PayloadHash:   "sha256:fixture",
		RecordCount:   42,
	}
	targetID := uuid.New()
	detail := scannerFindingDetail(scanner.Finding{
		VulnerabilityID: "CVE-2026-0001",
		Package: scanner.Package{
			Ecosystem:        "deb",
			Name:             "openssl",
			Version:          "3.0.0",
			NamespaceKind:    "os",
			NamespaceName:    "ubuntu",
			NamespaceVersion: "24.04",
		},
		CVSSBase:        7.5,
		KEVListed:       true,
		CanonicalEngine: "vulndb",
		Reconciliation: []scanner.ReconciliationSignal{{
			Engine:    "trivy",
			Field:     "severity",
			Canonical: "high",
			Evidence:  "critical",
		}},
	}, scanFindingContext{
		ImageRef:           "example.test/app@sha256:abc",
		ImageDigest:        "sha256:abc",
		Platform:           "linux/amd64",
		ScannerProfile:     "default",
		ImageScanResultID:  uuid.New(),
		ImageScanFindingID: uuid.New(),
		TargetID:           targetID,
		TargetType:         "image",
		TargetRef:          "example.test/app@sha256:abc",
		SourceType:         "manual",
		BundleMetadata:     metadata,
	})

	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ImageRef        string                         `json:"image_ref"`
		ImageDigest     string                         `json:"image_digest"`
		Platform        string                         `json:"platform"`
		CanonicalEngine string                         `json:"canonical_engine"`
		Package         scanner.Package                `json:"package"`
		Reconciliation  []scanner.ReconciliationSignal `json:"reconciliation"`
		VulnDBBundle    scanner.BundleMetadata         `json:"vulndb_bundle"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.ImageRef != "example.test/app@sha256:abc" {
		t.Fatalf("image_ref = %q", got.ImageRef)
	}
	if got.ImageDigest != "sha256:abc" || got.Platform != "linux/amd64" {
		t.Fatalf("image identity = %q/%q", got.ImageDigest, got.Platform)
	}
	if got.CanonicalEngine != "vulndb" {
		t.Fatalf("canonical_engine = %q, want vulndb", got.CanonicalEngine)
	}
	if got.Package.Name != "openssl" || got.Package.Version != "3.0.0" || got.Package.Ecosystem != "deb" {
		t.Fatalf("package = %+v", got.Package)
	}
	if bytes.Contains(raw, []byte(`"Name"`)) || bytes.Contains(raw, []byte(`"Version"`)) || bytes.Contains(raw, []byte(`"Ecosystem"`)) {
		t.Fatalf("package JSON used Go field names: %s", raw)
	}
	if len(got.Reconciliation) != 1 || got.Reconciliation[0].Engine != "trivy" || got.Reconciliation[0].Field != "severity" {
		t.Fatalf("reconciliation = %+v", got.Reconciliation)
	}
	if got.VulnDBBundle.BundleVersion != metadata.BundleVersion ||
		got.VulnDBBundle.PayloadHash != metadata.PayloadHash ||
		got.VulnDBBundle.RecordCount != metadata.RecordCount ||
		!got.VulnDBBundle.ExportedAt.Equal(exportedAt) {
		t.Fatalf("bundle metadata = %+v, want %+v", got.VulnDBBundle, metadata)
	}

	withoutBundle := scannerFindingDetail(scanner.Finding{}, scanFindingContext{
		ImageRef:   "example.test/app:latest",
		TargetID:   uuid.New(),
		TargetType: "image",
		TargetRef:  "example.test/app:latest",
		SourceType: "manual",
	})
	if _, ok := withoutBundle["vulndb_bundle"]; ok {
		t.Fatalf("unexpected vulndb_bundle in detail without metadata: %+v", withoutBundle)
	}

	repositoryMetadata := json.RawMessage(`{"provider":"github-actions","run_id":"123","commit":"abcdef"}`)
	withRepository := scannerFindingDetail(scanner.Finding{}, scanFindingContext{
		ImageRef:       "ghcr.io/acme/app@sha256:abc",
		TargetID:       uuid.New(),
		TargetType:     "image",
		TargetRef:      "ghcr.io/acme/app@sha256:abc",
		SourceType:     "repository",
		SourceRef:      "github.com/acme/app@abcdef",
		TargetMetadata: repositoryMetadata,
	})
	raw, err = json.Marshal(withRepository)
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		SourceRef string `json:"source_ref"`
		Metadata  struct {
			Provider string `json:"provider"`
			RunID    string `json:"run_id"`
			Commit   string `json:"commit"`
		} `json:"scan_target_metadata"`
	}
	if err := json.Unmarshal(raw, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.SourceRef != "github.com/acme/app@abcdef" || provenance.Metadata.Provider != "github-actions" || provenance.Metadata.Commit != "abcdef" {
		t.Fatalf("repository provenance = %+v", provenance)
	}
}

func TestScannerFindingDetailIncludesVulnerabilityProfileDecision(t *testing.T) {
	decision := map[string]any{
		"profile_id":   "profile-1",
		"profile_name": "Production criticals",
		"decision":     vulnprofile.DecisionEscalate,
		"entry_name":   "recent-critical",
		"reason":       "recent-critical",
	}
	detail := scannerFindingDetail(scanner.Finding{VulnerabilityID: "CVE-2026-0002"}, scanFindingContext{
		TargetID:            uuid.New(),
		TargetType:          "image",
		TargetRef:           "registry.example.test/api@sha256:abc",
		VulnProfileDecision: decision,
	})
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Profile map[string]any `json:"vulnerability_profile"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Profile["profile_id"] != "profile-1" || got.Profile["decision"] != string(vulnprofile.DecisionEscalate) {
		t.Fatalf("profile decision = %+v", got.Profile)
	}
}

func TestVulnerabilityProfileDecisionForFinding(t *testing.T) {
	clusterID := uuid.New()
	target := handler.ScanTarget{
		ClusterID: &clusterID,
		Type:      "workload",
		Ref:       "Deployment/prod/api",
		ImageRef:  "registry.example.test/prod/api:1.0",
		Metadata:  json.RawMessage(`{"namespace":"prod"}`),
	}
	identity := scanImageIdentity{Ref: "registry.example.test/prod/api@sha256:abc"}
	profiles := []vulnprofile.Profile{
		{
			ID:          "profile-low",
			Name:        "No match",
			Active:      true,
			DomainScope: vulnprofile.DomainScope{Namespaces: []string{"dev"}},
			Entries:     []vulnprofile.Entry{{Name: "dev-only", SeverityFloor: "high", Action: vulnprofile.ActionEscalate}},
		},
		{
			ID:          "profile-prod",
			Name:        "Production highs",
			Active:      true,
			DomainScope: vulnprofile.DomainScope{Clusters: []string{clusterID.String()}, Namespaces: []string{"prod"}},
			Entries: []vulnprofile.Entry{{
				Name:          "prod-high-api",
				Images:        []string{"registry.example.test/prod/*"},
				SeverityFloor: "high",
				Action:        vulnprofile.ActionEscalate,
			}},
		},
	}
	decision := vulnerabilityProfileDecisionForFinding(profiles, target, identity, scanner.Finding{
		VulnerabilityID: "CVE-2026-0003",
		CVSSBase:        8.5,
	}, "high")
	if decision["profile_id"] != "profile-prod" || decision["decision"] != vulnprofile.DecisionEscalate {
		t.Fatalf("decision = %+v", decision)
	}

	none := vulnerabilityProfileDecisionForFinding(profiles, target, identity, scanner.Finding{
		VulnerabilityID: "CVE-2026-0004",
		CVSSBase:        5.0,
	}, "medium")
	if none != nil {
		t.Fatalf("medium finding should not match: %+v", none)
	}
}

func TestScanJobs_RejectsExecutableRepositoryTarget(t *testing.T) {
	h := NewScanJobs(nil, nil)
	body, _ := json.Marshal(EnqueueRequest{TargetType: "repository", TargetRef: "github.com/acme/app"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs", bytes.NewReader(body))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: uuid.New(), OrgID: uuid.New()}))
	rec := httptest.NewRecorder()
	h.Enqueue(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); !bytes.Contains([]byte(got), []byte("repository package evidence")) {
		t.Fatalf("error body = %s", got)
	}
}

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	url := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
	}
	d, err := db.Connect(context.Background(), url)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	return d
}

// clearScanQueue removes every claimable (pending/running/paused) scan job for
// an org from the persistent shared test DB. ScanJobs.Claim pulls the oldest
// claimable job for the token's org regardless of which test enqueued it, so
// leftover jobs from prior (including crashed) runs against the shared DB would
// otherwise be claimed ahead of the job a test just enqueued. Tests in this
// package run sequentially (no t.Parallel), so clearing the org's queue at
// setup is safe and makes claim deterministic. This changes test isolation
// only; it touches no assertion or production code.
func clearScanQueue(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM scan_jobs WHERE org_id = $1 AND status IN ('pending','running','paused')`, orgID); err != nil {
		t.Fatalf("clear scan queue: %v", err)
	}
}

func TestScanJobs_QueueLifecycle(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	// Clean slate.
	_, _ = pool.Exec(ctx, `DELETE FROM scanner_tokens WHERE name = 'queue-test'`)

	// Use the first org from seed.
	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	queueImageRef := "registry.example.test/constellation/test-queue-image@sha256:0000000000000000000000000000000000000000000000000000000000000001"
	queueImageDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	_, _ = pool.Exec(ctx, `DELETE FROM findings WHERE org_id = $1 AND detail_json->>'image_digest' = $2`, orgID, queueImageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM image_scan_results WHERE org_id = $1 AND image_digest = $2`, orgID, queueImageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM assets WHERE org_id = $1 AND digest = $2`, orgID, queueImageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM scan_targets WHERE org_id = $1 AND ref = $2`, orgID, queueImageRef)
	clearScanQueue(t, pool, orgID)
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id = $1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}

	// Mint a scanner token.
	rawToken, _, err := handler.IssueScannerToken(ctx, pool, orgID, "queue-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	h := NewScanJobs(d, audit.New(pool))

	// 1) Enqueue a job as a user.
	enqueueReq := EnqueueRequest{TargetType: "image", TargetRef: queueImageRef}
	body, _ := json.Marshal(enqueueReq)
	r := httptest.NewRequest("POST", "/api/v1/scan-jobs", bytes.NewReader(body))
	r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h.Enqueue(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("enqueue status: %d body: %s", w.Code, w.Body.String())
	}
	var enqRes struct {
		ID uuid.UUID `json:"id"`
	}
	_ = json.NewDecoder(w.Body).Decode(&enqRes)

	// 2) Claim as scanner.
	r = httptest.NewRequest("POST", "/api/v1/scan-jobs/claim", nil)
	r.Header.Set("Authorization", "Bearer "+rawToken)
	// Wrap with the scanner-token middleware to populate context.
	w = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("claim status: %d body: %s", w.Code, w.Body.String())
	}
	var claimRes map[string]any
	_ = json.NewDecoder(w.Body).Decode(&claimRes)
	if claimRes["id"] != enqRes.ID.String() {
		t.Fatalf("claim returned different id: %v vs %v", claimRes["id"], enqRes.ID)
	}
	if claimRes["target_type"] != "image" || claimRes["target_ref"] != queueImageRef {
		t.Fatalf("claim target = %v/%v", claimRes["target_type"], claimRes["target_ref"])
	}
	if leaseRaw, ok := claimRes["lease_expires_at"].(string); !ok || leaseRaw == "" {
		t.Fatalf("claim missing lease expiry: %+v", claimRes)
	}
	var leaseExpiresAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT lease_expires_at FROM scan_jobs WHERE id = $1`, enqRes.ID).Scan(&leaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	if leaseExpiresAt == nil || !leaseExpiresAt.After(time.Now().UTC().Add(20*time.Minute)) {
		t.Fatalf("lease expiry = %v, want future lease", leaseExpiresAt)
	}

	// 3) Complete as scanner.
	exportedAt := time.Date(2026, 6, 12, 2, 3, 4, 0, time.UTC)
	metadata := scanner.BundleMetadata{
		SchemaVersion: "v2",
		BundleVersion: "fixture-20260612",
		Producer:      "constellation-vulndb",
		MediaType:     "application/vnd.constellation.vulndb.bundle.v2+json",
		ExportedAt:    exportedAt,
		PayloadHash:   "sha256:scan-job-fixture",
		RecordCount:   42,
	}
	completeBody, _ := json.Marshal(map[string]any{
		"image_ref":       queueImageRef,
		"image_digest":    queueImageDigest,
		"platform":        "linux/amd64",
		"package_count":   5,
		"findings":        []any{},
		"bundle_metadata": metadata,
	})
	r = httptest.NewRequest("POST", "/api/v1/scan-jobs/"+enqRes.ID.String()+"/complete", bytes.NewReader(completeBody))
	r.Header.Set("Authorization", "Bearer "+rawToken)
	// chi URL params are normally injected by the router; set them manually for the test.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", enqRes.ID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Complete)).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("complete status: %d body: %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("POST", "/api/v1/scan-jobs/"+enqRes.ID.String()+"/complete", bytes.NewReader(completeBody))
	r.Header.Set("Authorization", "Bearer "+rawToken)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", enqRes.ID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	replay := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Complete)).ServeHTTP(replay, r)
	if replay.Code != 200 {
		t.Fatalf("replay complete status: %d body: %s", replay.Code, replay.Body.String())
	}

	// 4) Verify DB row reflects completion.
	var status string
	var pkgs, findings int
	var bundleRaw []byte
	leaseExpiresAt = nil
	if err := pool.QueryRow(ctx, `SELECT status, package_count, finding_count, bundle_metadata, lease_expires_at FROM scan_jobs WHERE id = $1`, enqRes.ID).
		Scan(&status, &pkgs, &findings, &bundleRaw, &leaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	if status != "completed" || pkgs != 5 || findings != 0 {
		t.Fatalf("unexpected final state: status=%s pkgs=%d findings=%d", status, pkgs, findings)
	}
	if leaseExpiresAt != nil {
		t.Fatalf("completed job retained lease expiry: %v", leaseExpiresAt)
	}
	var stored scanner.BundleMetadata
	if err := json.Unmarshal(bundleRaw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.BundleVersion != metadata.BundleVersion || stored.PayloadHash != metadata.PayloadHash || stored.RecordCount != metadata.RecordCount {
		t.Fatalf("stored bundle metadata = %+v, want %+v", stored, metadata)
	}

	// 5) Verify list API exposes first-class scan-job bundle provenance.
	r = httptest.NewRequest("GET", "/api/v1/scan-jobs", nil)
	r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w = httptest.NewRecorder()
	h.List(w, r)
	if w.Code != 200 {
		t.Fatalf("list status: %d body: %s", w.Code, w.Body.String())
	}
	var listRes struct {
		Jobs []JobView `json:"jobs"`
	}
	if err := json.NewDecoder(w.Body).Decode(&listRes); err != nil {
		t.Fatal(err)
	}
	var listed *JobView
	for i := range listRes.Jobs {
		if listRes.Jobs[i].ID == enqRes.ID {
			listed = &listRes.Jobs[i]
			break
		}
	}
	if listed == nil {
		t.Fatalf("completed job not returned: %+v", listRes.Jobs)
	}
	if listed.BundleMetadata == nil || listed.BundleMetadata.BundleVersion != metadata.BundleVersion || listed.BundleMetadata.PayloadHash != metadata.PayloadHash {
		t.Fatalf("listed bundle metadata = %+v, want %+v", listed.BundleMetadata, metadata)
	}
}

func TestScanJobs_ClaimReclaimsExpiredLeaseAndFailureRequiresWorker(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	targetID := uuid.New()
	pendingTargetID := uuid.New()
	jobID := uuid.New()
	if _, err := pool.Exec(ctx, `
	INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scan Lease Test')`, orgID, "scan-lease-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	oldRawToken, oldTokenID, err := handler.IssueScannerToken(ctx, pool, orgID, "lease-old", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newRawToken, newTokenID, err := handler.IssueScannerToken(ctx, pool, orgID, "lease-new", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref)
	VALUES ($1, $2, 'image', 'registry.example.test/reclaim:latest', 'manual', 'registry.example.test/reclaim:latest'),
	       ($3, $2, 'image', 'registry.example.test/pending:latest', 'manual', 'registry.example.test/pending:latest')`,
		targetID, orgID, pendingTargetID); err != nil {
		t.Fatalf("scan target: %v", err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_jobs (id, org_id, target_id, status, worker_id, requested_at, claimed_at, lease_expires_at, error, finished_at)
	VALUES ($1, $2, $3, 'running', $4, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '45 minutes', NOW() - INTERVAL '5 minutes', 'previous failure', NOW() - INTERVAL '5 minutes')`,
		jobID, orgID, targetID, "scanner:lease-old:"+oldTokenID.String()); err != nil {
		t.Fatalf("scan job: %v", err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_jobs (id, org_id, target_id, status, requested_at)
	VALUES (gen_random_uuid(), $1, $2, 'pending', NOW() - INTERVAL '5 minutes')`,
		orgID, pendingTargetID); err != nil {
		t.Fatalf("pending scan job: %v", err)
	}

	h := NewScanJobs(d, audit.New(pool))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim", nil)
	req.Header.Set("Authorization", "Bearer "+newRawToken)
	rec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("claim status: %d body: %s", rec.Code, rec.Body.String())
	}
	var claimRes struct {
		ID             uuid.UUID `json:"id"`
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&claimRes); err != nil {
		t.Fatal(err)
	}
	if claimRes.ID != jobID {
		t.Fatalf("claim id = %s, want %s", claimRes.ID, jobID)
	}
	if !claimRes.LeaseExpiresAt.After(time.Now().UTC().Add(20 * time.Minute)) {
		t.Fatalf("lease expiry = %v, want renewed future lease", claimRes.LeaseExpiresAt)
	}

	var status, workerID string
	var leaseExpiresAt, finishedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, worker_id, lease_expires_at, finished_at FROM scan_jobs WHERE id = $1`, jobID).
		Scan(&status, &workerID, &leaseExpiresAt, &finishedAt); err != nil {
		t.Fatal(err)
	}
	if status != "running" || workerID != "scanner:lease-new:"+newTokenID.String() || leaseExpiresAt == nil || finishedAt != nil {
		t.Fatalf("reclaimed job = status=%s worker=%s lease=%v finished=%v", status, workerID, leaseExpiresAt, finishedAt)
	}

	failReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+jobID.String()+"/fail", bytes.NewBufferString(`{"error":"old worker failed late"}`))
	failReq.Header.Set("Authorization", "Bearer "+oldRawToken)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID.String())
	failReq = failReq.WithContext(context.WithValue(failReq.Context(), chi.RouteCtxKey, rctx))
	failRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Fail)).ServeHTTP(failRec, failReq)
	if failRec.Code != http.StatusConflict {
		t.Fatalf("old worker fail status: %d body: %s", failRec.Code, failRec.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM scan_jobs WHERE id = $1`, jobID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("old worker changed status to %s", status)
	}

	failReq = httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+jobID.String()+"/fail", bytes.NewBufferString(`{"error":"scanner failed"}`))
	failReq.Header.Set("Authorization", "Bearer "+newRawToken)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID.String())
	failReq = failReq.WithContext(context.WithValue(failReq.Context(), chi.RouteCtxKey, rctx))
	failRec = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Fail)).ServeHTTP(failRec, failReq)
	if failRec.Code != http.StatusOK {
		t.Fatalf("new worker fail status: %d body: %s", failRec.Code, failRec.Body.String())
	}
	leaseExpiresAt = nil
	if err := pool.QueryRow(ctx, `SELECT status, lease_expires_at FROM scan_jobs WHERE id = $1`, jobID).Scan(&status, &leaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || leaseExpiresAt != nil {
		t.Fatalf("failed job = status=%s lease=%v", status, leaseExpiresAt)
	}
}

func TestScanJobs_RenewRequiresSameScannerInstance(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	targetID := uuid.New()
	jobID := uuid.New()
	if _, err := pool.Exec(ctx, `
	INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scan Renew Test')`, orgID, "scan-renew-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	rawToken, _, err := handler.IssueScannerToken(ctx, pool, orgID, "renew-shared-token", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref)
	VALUES ($1, $2, 'image', 'registry.example.test/renew:latest', 'manual', 'registry.example.test/renew:latest')`,
		targetID, orgID); err != nil {
		t.Fatalf("scan target: %v", err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_jobs (id, org_id, target_id, status, requested_at)
	VALUES ($1, $2, $3, 'pending', NOW() - INTERVAL '5 minutes')`,
		jobID, orgID, targetID); err != nil {
		t.Fatalf("scan job: %v", err)
	}

	h := NewScanJobs(d, audit.New(pool))
	claimReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim?target_type=image", nil)
	claimReq.Header.Set("Authorization", "Bearer "+rawToken)
	claimReq.Header.Set("X-Constellation-Scanner-Instance", "scanner-a")
	claimRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(claimRec, claimReq)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("claim status: %d body: %s", claimRec.Code, claimRec.Body.String())
	}

	renewReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+jobID.String()+"/renew", nil)
	renewReq.Header.Set("Authorization", "Bearer "+rawToken)
	renewReq.Header.Set("X-Constellation-Scanner-Instance", "scanner-b")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID.String())
	renewReq = renewReq.WithContext(context.WithValue(renewReq.Context(), chi.RouteCtxKey, rctx))
	renewRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.RenewLease)).ServeHTTP(renewRec, renewReq)
	if renewRec.Code != http.StatusConflict {
		t.Fatalf("different instance renew status: %d body: %s", renewRec.Code, renewRec.Body.String())
	}

	// Simulate the lease being close to expiry before the owning instance
	// renews it, then capture the (short) pre-renew lease so the assertion
	// below verifies the renew actually extends it far into the future.
	_, _ = pool.Exec(ctx, `UPDATE scan_jobs SET lease_expires_at = NOW() + INTERVAL '1 minute' WHERE id = $1`, jobID)
	var before time.Time
	if err := pool.QueryRow(ctx, `SELECT lease_expires_at FROM scan_jobs WHERE id = $1`, jobID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	renewReq = httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+jobID.String()+"/renew", nil)
	renewReq.Header.Set("Authorization", "Bearer "+rawToken)
	renewReq.Header.Set("X-Constellation-Scanner-Instance", "scanner-a")
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID.String())
	renewReq = renewReq.WithContext(context.WithValue(renewReq.Context(), chi.RouteCtxKey, rctx))
	renewRec = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.RenewLease)).ServeHTTP(renewRec, renewReq)
	if renewRec.Code != http.StatusOK {
		t.Fatalf("same instance renew status: %d body: %s", renewRec.Code, renewRec.Body.String())
	}
	var after time.Time
	if err := pool.QueryRow(ctx, `SELECT lease_expires_at FROM scan_jobs WHERE id = $1`, jobID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.After(before.Add(20 * time.Minute)) {
		t.Fatalf("lease did not renew far enough: before=%v after=%v", before, after)
	}

	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+jobID.String()+"/complete", bytes.NewBufferString(`{"image_ref":"registry.example.test/renew:latest","image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","findings":[]}`))
	completeReq.Header.Set("Authorization", "Bearer "+rawToken)
	completeReq.Header.Set("X-Constellation-Scanner-Instance", "scanner-b")
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID.String())
	completeReq = completeReq.WithContext(context.WithValue(completeReq.Context(), chi.RouteCtxKey, rctx))
	completeRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Complete)).ServeHTTP(completeRec, completeReq)
	if completeRec.Code != http.StatusConflict {
		t.Fatalf("different instance complete status: %d body: %s", completeRec.Code, completeRec.Body.String())
	}
}

func TestScanJobs_RetryBackoffAndMaxAttempts(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	targetID := uuid.New()
	jobID := uuid.New()
	terminalJobID := uuid.New()
	if _, err := pool.Exec(ctx, `
	INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scan Retry Test')`, orgID, "scan-retry-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Scan Retry User')`, userID, orgID, "scan-retry-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	rawToken, tokenID, err := handler.IssueScannerToken(ctx, pool, orgID, "retry-token", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref)
	VALUES ($1, $2, 'image', 'registry.example.test/retry:latest', 'manual', 'registry.example.test/retry:latest')`,
		targetID, orgID); err != nil {
		t.Fatalf("scan target: %v", err)
	}
	workerID := "scanner:retry-token:" + tokenID.String() + ":retry-a"
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_jobs (id, org_id, target_id, status, worker_id, requested_by, requested_at, claimed_at, lease_expires_at, attempt_count, max_attempts)
	VALUES ($1, $2, $3, 'running', $4, $5, NOW() - INTERVAL '5 minutes', NOW() - INTERVAL '1 minute', NOW() + INTERVAL '20 minutes', 1, 3),
	       ($6, $2, $3, 'running', $4, $5, NOW() - INTERVAL '4 minutes', NOW() - INTERVAL '1 minute', NOW() + INTERVAL '20 minutes', 3, 3)`,
		jobID, orgID, targetID, workerID, userID, terminalJobID); err != nil {
		t.Fatalf("scan jobs: %v", err)
	}

	h := NewScanJobs(d, audit.New(pool))
	failReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+jobID.String()+"/fail", bytes.NewBufferString(`{"error":"registry timeout","retryable":true}`))
	failReq.Header.Set("Authorization", "Bearer "+rawToken)
	failReq.Header.Set("X-Constellation-Scanner-Instance", "retry-a")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID.String())
	failReq = failReq.WithContext(context.WithValue(failReq.Context(), chi.RouteCtxKey, rctx))
	failRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Fail)).ServeHTTP(failRec, failReq)
	if failRec.Code != http.StatusOK {
		t.Fatalf("retryable fail status: %d body: %s", failRec.Code, failRec.Body.String())
	}
	var status string
	var nextAttemptAt *time.Time
	var storedWorker *string
	if err := pool.QueryRow(ctx, `SELECT status, worker_id, next_attempt_at FROM scan_jobs WHERE id = $1`, jobID).Scan(&status, &storedWorker, &nextAttemptAt); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || storedWorker != nil || nextAttemptAt == nil || !nextAttemptAt.After(time.Now().UTC()) {
		t.Fatalf("retry scheduled row = status=%s worker=%v next=%v", status, storedWorker, nextAttemptAt)
	}

	claimReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim", nil)
	claimReq.Header.Set("Authorization", "Bearer "+rawToken)
	claimReq.Header.Set("X-Constellation-Scanner-Instance", "retry-a")
	claimRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(claimRec, claimReq)
	if claimRec.Code != http.StatusNoContent {
		t.Fatalf("delayed retry claim status: %d body: %s", claimRec.Code, claimRec.Body.String())
	}

	if _, err := pool.Exec(ctx, `UPDATE scan_jobs SET next_attempt_at = NOW() - INTERVAL '1 second' WHERE id = $1`, jobID); err != nil {
		t.Fatal(err)
	}
	claimReq = httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim", nil)
	claimReq.Header.Set("Authorization", "Bearer "+rawToken)
	claimReq.Header.Set("X-Constellation-Scanner-Instance", "retry-a")
	claimRec = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(claimRec, claimReq)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("eligible retry claim status: %d body: %s", claimRec.Code, claimRec.Body.String())
	}
	var claimRes struct {
		ID           uuid.UUID `json:"id"`
		AttemptCount int       `json:"attempt_count"`
	}
	if err := json.NewDecoder(claimRec.Body).Decode(&claimRes); err != nil {
		t.Fatal(err)
	}
	if claimRes.ID != jobID || claimRes.AttemptCount != 2 {
		t.Fatalf("retry claim = %+v, want job=%s attempt=2", claimRes, jobID)
	}

	failReq = httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+terminalJobID.String()+"/fail", bytes.NewBufferString(`{"error":"registry timeout","retryable":true}`))
	failReq.Header.Set("Authorization", "Bearer "+rawToken)
	failReq.Header.Set("X-Constellation-Scanner-Instance", "retry-a")
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", terminalJobID.String())
	failReq = failReq.WithContext(context.WithValue(failReq.Context(), chi.RouteCtxKey, rctx))
	failRec = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Fail)).ServeHTTP(failRec, failReq)
	if failRec.Code != http.StatusOK {
		t.Fatalf("terminal fail status: %d body: %s", failRec.Code, failRec.Body.String())
	}
	nextAttemptAt = nil
	if err := pool.QueryRow(ctx, `SELECT status, next_attempt_at FROM scan_jobs WHERE id = $1`, terminalJobID).Scan(&status, &nextAttemptAt); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || nextAttemptAt != nil {
		t.Fatalf("max attempts row = status=%s next=%v", status, nextAttemptAt)
	}

	retryReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+terminalJobID.String()+"/retry", nil)
	retryReq = retryReq.WithContext(authctx.WithSubject(retryReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", terminalJobID.String())
	retryReq = retryReq.WithContext(context.WithValue(retryReq.Context(), chi.RouteCtxKey, rctx))
	retryRec := httptest.NewRecorder()
	h.Retry(retryRec, retryReq)
	if retryRec.Code != http.StatusOK {
		t.Fatalf("manual retry status: %d body: %s", retryRec.Code, retryRec.Body.String())
	}
	var attempts int
	if err := pool.QueryRow(ctx, `SELECT status, attempt_count, next_attempt_at FROM scan_jobs WHERE id = $1`, terminalJobID).Scan(&status, &attempts, &nextAttemptAt); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || attempts != 0 || nextAttemptAt != nil {
		t.Fatalf("manual retry row = status=%s attempts=%d next=%v", status, attempts, nextAttemptAt)
	}
}

func TestScanJobs_ClaimFiltersTargetTypes(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	imageTargetID := uuid.New()
	hostTargetID := uuid.New()
	if _, err := pool.Exec(ctx, `
	INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scan Claim Filter Test')`, orgID, "scan-claim-filter-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	rawToken, _, err := handler.IssueScannerToken(ctx, pool, orgID, "claim-filter-token", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref)
	VALUES ($1, $2, 'image', 'registry.example.test/filter:latest', 'manual', 'registry.example.test/filter:latest'),
	       ($3, $2, 'host', 'node/filter', 'host', NULL)`,
		imageTargetID, orgID, hostTargetID); err != nil {
		t.Fatalf("scan targets: %v", err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_jobs (id, org_id, target_id, status, requested_at)
	VALUES (gen_random_uuid(), $1, $2, 'pending', NOW() - INTERVAL '10 minutes'),
	       (gen_random_uuid(), $1, $3, 'pending', NOW() - INTERVAL '5 minutes')`,
		orgID, imageTargetID, hostTargetID); err != nil {
		t.Fatalf("scan jobs: %v", err)
	}

	h := NewScanJobs(d, audit.New(pool))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim?target_type=host", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("host claim status: %d body: %s", rec.Code, rec.Body.String())
	}
	var claimed struct {
		TargetType string `json:"target_type"`
		TargetRef  string `json:"target_ref"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&claimed); err != nil {
		t.Fatal(err)
	}
	if claimed.TargetType != "host" || claimed.TargetRef != "node/filter" {
		t.Fatalf("claimed = %+v, want host", claimed)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim?target_type=repository", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("repository claim status: %d body: %s", rec.Code, rec.Body.String())
	}
}

// Previously this test asserted that completing an image scan wrote NOTHING to the unified
// `findings` table (projected == 0) — which was the under-reporting bug: image vulnerabilities
// on running workloads never surfaced on the dashboard or Findings page. The fixture sets up
// a LINKED, running image (image_workload_links for the cluster), so the correct behavior is
// now that the high-severity image finding IS promoted into `findings`, attributed to the
// running cluster, while the canonical image_scan_findings row is still preserved. The
// assertions below were flipped to match the unified per-asset model.
func TestScanJobs_CompleteWritesCanonicalImageResultWithoutFindingProjection(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id = $1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}

	imageDigest := "sha256:0000000000000000000000000000000000000000000000000000000000004242"
	imageRef := "registry.example.test/constellation/test-queue-image@" + imageDigest
	vulnID := "CVE-2026-4242"
	clusterID := uuid.New()
	clusterName := "scan-cluster-" + clusterID.String()
	deploymentID := uuid.New()

	_, _ = pool.Exec(ctx, `DELETE FROM findings WHERE org_id = $1 AND external_id = $2`, orgID, vulnID)
	_, _ = pool.Exec(ctx, `DELETE FROM image_workload_links WHERE org_id = $1 AND image_digest = $2`, orgID, imageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM image_scan_results WHERE org_id = $1 AND image_digest = $2`, orgID, imageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM assets WHERE org_id = $1 AND digest = $2`, orgID, imageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM scan_targets WHERE org_id = $1 AND ref = $2`, orgID, imageRef)
	clearScanQueue(t, pool, orgID)
	_, _ = pool.Exec(ctx, `DELETE FROM scanner_tokens WHERE name = 'cluster-scope-test'`)
	_, _ = pool.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, clusterID)

	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state)
VALUES ($1, $2, $3, 'kubernetes', 'connected')`, clusterID, orgID, clusterName); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (id, org_id, cluster_id, namespace, name, kind, image_refs)
VALUES ($1, $2, $3, 'default', 'cluster-scope-app', 'Deployment', $4)`,
		deploymentID, orgID, clusterID, []string{imageRef}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest
) VALUES ($1, $2, $3, 'default/cluster-scope-app', 'default', 'cluster-scope-app', 'Deployment',
          $4, $4, 'registry.example.test/constellation/test-queue-image', '', $5)`,
		orgID, clusterID, deploymentID, imageRef, imageDigest); err != nil {
		t.Fatal(err)
	}

	rawToken, _, err := handler.IssueScannerToken(ctx, pool, orgID, "cluster-scope-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	h := NewScanJobs(d, audit.New(pool))
	body, _ := json.Marshal(EnqueueRequest{TargetType: "image", TargetRef: imageRef})
	r := httptest.NewRequest("POST", "/api/v1/scan-jobs", bytes.NewReader(body))
	r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h.Enqueue(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("enqueue status: %d body: %s", w.Code, w.Body.String())
	}
	var enqRes struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&enqRes); err != nil {
		t.Fatal(err)
	}

	r = httptest.NewRequest("POST", "/api/v1/scan-jobs/claim", nil)
	r.Header.Set("Authorization", "Bearer "+rawToken)
	w = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("claim status: %d body: %s", w.Code, w.Body.String())
	}

	completeBody, _ := json.Marshal(map[string]any{
		"image_ref":     imageRef,
		"image_digest":  imageDigest,
		"package_count": 1,
		"findings": []scanner.Finding{{
			VulnerabilityID: vulnID,
			Severity:        "high",
			Title:           "cluster scoped fixture",
			Package: scanner.Package{
				Ecosystem: "apk",
				Name:      "openssl",
				Version:   "3.0.0-r0",
			},
			CanonicalEngine: "vulndb",
		}},
	})
	r = httptest.NewRequest("POST", "/api/v1/scan-jobs/"+enqRes.ID.String()+"/complete", bytes.NewReader(completeBody))
	r.Header.Set("Authorization", "Bearer "+rawToken)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", enqRes.ID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Complete)).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("complete status: %d body: %s", w.Code, w.Body.String())
	}

	// The image is running on exactly one cluster (one image_workload_link), so the high
	// finding is promoted into the unified findings table once, attributed to that cluster.
	var projected int
	var promotedSeverity, promotedTargetType string
	var promotedCluster uuid.UUID
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int,
       COALESCE(MIN(severity), ''),
       COALESCE(MIN(target_type), ''),
       COALESCE(MIN(cluster_id::text), '00000000-0000-0000-0000-000000000000')::uuid
  FROM findings
 WHERE org_id = $1 AND external_id = $2`, orgID, vulnID).
		Scan(&projected, &promotedSeverity, &promotedTargetType, &promotedCluster); err != nil {
		t.Fatal(err)
	}
	if projected != 1 {
		t.Fatalf("promoted image findings = %d, want 1 (one running cluster)", projected)
	}
	if promotedSeverity != "high" || promotedTargetType != "image-workload" || promotedCluster != clusterID {
		t.Fatalf("promoted finding = severity:%s target_type:%s cluster:%s, want high/image-workload/%s",
			promotedSeverity, promotedTargetType, promotedCluster, clusterID)
	}

	var resultCount, canonicalCount int
	var resultIDStr string
	if err := pool.QueryRow(ctx, `
SELECT COUNT(DISTINCT r.id)::int, COUNT(f.id)::int, MIN(r.id::text)
  FROM image_scan_results r
  LEFT JOIN image_scan_findings f ON f.image_scan_result_id = r.id
 WHERE r.org_id = $1 AND r.image_digest = $2`, orgID, imageDigest).Scan(&resultCount, &canonicalCount, &resultIDStr); err != nil {
		t.Fatal(err)
	}
	if resultCount != 1 || canonicalCount != 1 {
		t.Fatalf("canonical result/finding counts = %d/%d, want 1/1", resultCount, canonicalCount)
	}
	resultID, err := uuid.Parse(resultIDStr)
	if err != nil {
		t.Fatal(err)
	}

	imageResults := handler.NewImageScanResults(d)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/image-scan-results/"+resultID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	resultCtx := chi.NewRouteContext()
	resultCtx.URLParams.Add("id", resultID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, resultCtx))
	rec := httptest.NewRecorder()
	imageResults.Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("image result status: %d body: %s", rec.Code, rec.Body.String())
	}
	var resultDetail struct {
		ImageScanResult   handler.ImageScanResultDTO    `json:"image_scan_result"`
		Findings          []handler.ImageScanFindingDTO `json:"findings"`
		ImpactedWorkloads []handler.ImpactedWorkload    `json:"impacted_workloads"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resultDetail); err != nil {
		t.Fatal(err)
	}
	if resultDetail.ImageScanResult.ImageDigest != imageDigest || resultDetail.ImageScanResult.CriticalCount != 0 || resultDetail.ImageScanResult.HighCount != 1 {
		t.Fatalf("image result summary = %+v", resultDetail.ImageScanResult)
	}
	if len(resultDetail.Findings) != 1 || resultDetail.Findings[0].ExternalID != vulnID || resultDetail.Findings[0].PackageName != "openssl" {
		t.Fatalf("image findings = %+v", resultDetail.Findings)
	}
	if len(resultDetail.ImpactedWorkloads) != 1 || resultDetail.ImpactedWorkloads[0].ClusterID != clusterID {
		t.Fatalf("impacted workloads = %+v", resultDetail.ImpactedWorkloads)
	}
}

func TestScanJobs_CompleteWritesImageScanArtifacts(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.image_scan_artifacts')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: image_scan_artifacts migration not applied (%v)", err)
	}
	var secretArtifactsEnabled bool
	if err := pool.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conrelid = 'image_scan_artifacts'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%constellation-image-secrets-v1%'
)`).Scan(&secretArtifactsEnabled); err != nil {
		t.Fatal(err)
	}
	var signatureArtifactsEnabled bool
	if err := pool.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conrelid = 'image_scan_artifacts'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%constellation-image-signature-v1%'
)`).Scan(&signatureArtifactsEnabled); err != nil {
		t.Fatal(err)
	}
	var layerArtifactsEnabled bool
	if err := pool.QueryRow(ctx, `
	SELECT EXISTS (
	    SELECT 1
	      FROM pg_constraint
	     WHERE conrelid = 'image_scan_artifacts'::regclass
	       AND contype = 'c'
	       AND pg_get_constraintdef(oid) LIKE '%constellation-image-layers-v1%'
	)`).Scan(&layerArtifactsEnabled); err != nil {
		t.Fatal(err)
	}
	var fileRiskArtifactsEnabled bool
	if err := pool.QueryRow(ctx, `
	SELECT EXISTS (
	    SELECT 1
	      FROM pg_constraint
	     WHERE conrelid = 'image_scan_artifacts'::regclass
	       AND contype = 'c'
	       AND pg_get_constraintdef(oid) LIKE '%constellation-image-file-risk-v1%'
	)`).Scan(&fileRiskArtifactsEnabled); err != nil {
		t.Fatal(err)
	}

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id = $1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}

	imageDigest := "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	imageRef := "registry.example.test/constellation/artifact-image@" + imageDigest
	_, _ = pool.Exec(ctx, `DELETE FROM image_scan_results WHERE org_id = $1 AND image_digest = $2`, orgID, imageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM assets WHERE org_id = $1 AND digest = $2`, orgID, imageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM scan_targets WHERE org_id = $1 AND ref = $2`, orgID, imageRef)
	_, _ = pool.Exec(ctx, `DELETE FROM scanner_tokens WHERE name = 'artifact-test'`)
	clearScanQueue(t, pool, orgID)

	rawToken, _, err := handler.IssueScannerToken(ctx, pool, orgID, "artifact-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	h := NewScanJobs(d, audit.New(pool))
	body, _ := json.Marshal(EnqueueRequest{TargetType: "image", TargetRef: imageRef, Platform: "linux/amd64"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs", bytes.NewReader(body))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	h.Enqueue(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enqueue status: %d body: %s", rec.Code, rec.Body.String())
	}
	var enqRes struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&enqRes); err != nil {
		t.Fatal(err)
	}

	claimReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim", nil)
	claimReq.Header.Set("Authorization", "Bearer "+rawToken)
	claimRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(claimRec, claimReq)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("claim status: %d body: %s", claimRec.Code, claimRec.Body.String())
	}

	packages := []scanner.Package{{
		Ecosystem:        "apk",
		Name:             "openssl",
		Version:          "3.0.0-r0",
		Purl:             "pkg:apk/openssl@3.0.0-r0",
		NamespaceKind:    "os",
		NamespaceName:    "alpine",
		NamespaceVersion: "3.20",
		Locations: []scanner.PackageLocation{{
			Path:        "/lib/apk/db/installed",
			LayerDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		}},
	}}
	completePayload := map[string]any{
		"image_ref":    imageRef,
		"image_digest": imageDigest,
		"platform":     "linux/amd64",
		"packages":     packages,
		"findings":     []scanner.Finding{},
	}
	if secretArtifactsEnabled {
		completePayload["secrets"] = []scanner.SecretFinding{{
			Engine:        "trivy",
			RuleID:        "aws-access-key-id",
			Category:      "AWS",
			Severity:      "HIGH",
			Title:         "AWS Access Key ID",
			Target:        "app/config.py",
			Path:          "app/config.py",
			StartLine:     12,
			EndLine:       12,
			MatchSHA256:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			MatchRedacted: "AKIA1234567890TEST",
		}}
	}
	if signatureArtifactsEnabled {
		completePayload["signature"] = &scanner.SignatureResult{
			ImageRef: imageRef,
			Status:   "trusted",
			Signed:   true,
			Trusted:  true,
			Identity: "https://github.com/alphabravocompany/constellation/.github/workflows/release.yml@refs/heads/main",
			Issuer:   "https://token.actions.githubusercontent.com",
			Reason:   "signature trusted",
		}
	}
	if layerArtifactsEnabled {
		completePayload["layers"] = &scanner.ImageLayerMetadata{
			ImageRef:        imageRef,
			ManifestDigest:  imageDigest,
			MediaType:       "application/vnd.oci.image.manifest.v1+json",
			ConfigDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			ConfigMediaType: "application/vnd.oci.image.config.v1+json",
			ConfigSizeBytes: 7023,
			Layers: []scanner.ImageLayer{
				{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", SizeBytes: 100},
				{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", SizeBytes: 250},
			},
			Architectures:    []string{"linux/amd64"},
			SelectedPlatform: "linux/amd64",
			TotalSizeBytes:   350,
			Status:           "observed",
		}
	}
	if fileRiskArtifactsEnabled {
		completePayload["file_risks"] = &scanner.ImageFileRiskReport{
			ImageRef:       imageRef,
			ManifestDigest: imageDigest,
			Platform:       "linux/amd64",
			Status:         "observed",
			FindingCount:   2,
			EntryCount:     42,
			MaxFindings:    500,
			Findings: []scanner.ImageFileRiskFinding{
				{Path: "/usr/bin/suid-helper", Type: "regular", Mode: "4755", UID: 0, GID: 0, LayerIndex: 1, LayerDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", RiskTypes: []string{"setuid"}, Severity: "high", Reason: "high filesystem risk: setuid"},
				{Path: "/var/lib/open", Type: "directory", Mode: "0777", UID: 0, GID: 0, LayerIndex: 1, LayerDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", RiskTypes: []string{"world-writable-directory"}, Severity: "medium", Reason: "medium filesystem risk: world-writable-directory"},
			},
		}
	}
	completeBody, _ := json.Marshal(completePayload)
	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+enqRes.ID.String()+"/complete", bytes.NewReader(completeBody))
	completeReq.Header.Set("Authorization", "Bearer "+rawToken)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", enqRes.ID.String())
	completeReq = completeReq.WithContext(context.WithValue(completeReq.Context(), chi.RouteCtxKey, rctx))
	completeRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Complete)).ServeHTTP(completeRec, completeReq)
	if completeRec.Code != http.StatusOK {
		t.Fatalf("complete status: %d body: %s", completeRec.Code, completeRec.Body.String())
	}
	var completeRes struct {
		ImageScanResultID uuid.UUID `json:"image_scan_result_id"`
	}
	if err := json.NewDecoder(completeRec.Body).Decode(&completeRes); err != nil {
		t.Fatal(err)
	}

	var artifactCount int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int
  FROM image_scan_artifacts
 WHERE org_id = $1 AND image_scan_result_id = $2`, orgID, completeRes.ImageScanResultID).Scan(&artifactCount); err != nil {
		t.Fatal(err)
	}
	expectedArtifacts := 3
	if secretArtifactsEnabled {
		expectedArtifacts = 4
	}
	if signatureArtifactsEnabled {
		expectedArtifacts++
	}
	if layerArtifactsEnabled {
		expectedArtifacts++
	}
	if fileRiskArtifactsEnabled {
		expectedArtifacts++
	}
	if artifactCount != expectedArtifacts {
		t.Fatalf("artifact count = %d, want %d", artifactCount, expectedArtifacts)
	}
	var packageCount int
	var inventoryRaw []byte
	if err := pool.QueryRow(ctx, `
SELECT package_count, payload
  FROM image_scan_artifacts
 WHERE org_id = $1
   AND image_scan_result_id = $2
   AND artifact_type = 'package-inventory'
   AND format = 'constellation-package-inventory-v1'`, orgID, completeRes.ImageScanResultID).Scan(&packageCount, &inventoryRaw); err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		ImageDigest  string            `json:"image_digest"`
		PackageCount int               `json:"package_count"`
		Packages     []scanner.Package `json:"packages"`
	}
	if err := json.Unmarshal(inventoryRaw, &inventory); err != nil {
		t.Fatal(err)
	}
	if packageCount != 1 || inventory.PackageCount != 1 || inventory.ImageDigest != imageDigest || len(inventory.Packages) != 1 || inventory.Packages[0].Name != "openssl" {
		t.Fatalf("inventory = %+v packageCount=%d", inventory, packageCount)
	}
	if len(inventory.Packages[0].Locations) != 1 || inventory.Packages[0].Locations[0].LayerDigest != "sha256:1111111111111111111111111111111111111111111111111111111111111111" {
		t.Fatalf("inventory package locations = %+v", inventory.Packages[0].Locations)
	}
	packagesReq := httptest.NewRequest(http.MethodGet, "/api/v1/image-scan-results/"+completeRes.ImageScanResultID.String()+"/packages", nil)
	packagesReq = packagesReq.WithContext(authctx.WithSubject(packagesReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	packagesCtx := chi.NewRouteContext()
	packagesCtx.URLParams.Add("id", completeRes.ImageScanResultID.String())
	packagesReq = packagesReq.WithContext(context.WithValue(packagesReq.Context(), chi.RouteCtxKey, packagesCtx))
	packagesRec := httptest.NewRecorder()
	handler.NewImageScanResults(d).Packages(packagesRec, packagesReq)
	if packagesRec.Code != http.StatusOK {
		t.Fatalf("packages status: %d body: %s", packagesRec.Code, packagesRec.Body.String())
	}
	var packagesResp struct {
		PackageCount             int `json:"package_count"`
		LayerPackageCount        int `json:"layer_package_count"`
		UnattributedPackageCount int `json:"unattributed_package_count"`
		PackageInventory         struct {
			Packages []scanner.Package `json:"packages"`
		} `json:"package_inventory"`
		PackageLayers []struct {
			LayerIndex   *int              `json:"layer_index"`
			LayerDigest  string            `json:"layer_digest"`
			PackageCount int               `json:"package_count"`
			Packages     []scanner.Package `json:"packages"`
		} `json:"package_layers"`
	}
	if err := json.NewDecoder(packagesRec.Body).Decode(&packagesResp); err != nil {
		t.Fatal(err)
	}
	if packagesResp.PackageCount != 1 || len(packagesResp.PackageInventory.Packages) != 1 {
		t.Fatalf("packages response = %+v", packagesResp)
	}
	if layerArtifactsEnabled {
		if packagesResp.LayerPackageCount != 1 || packagesResp.UnattributedPackageCount != 0 || len(packagesResp.PackageLayers) != 1 {
			t.Fatalf("package layers response = %+v", packagesResp)
		}
		if packagesResp.PackageLayers[0].LayerIndex == nil || *packagesResp.PackageLayers[0].LayerIndex != 0 ||
			packagesResp.PackageLayers[0].LayerDigest != "sha256:1111111111111111111111111111111111111111111111111111111111111111" ||
			packagesResp.PackageLayers[0].Packages[0].Name != "openssl" {
			t.Fatalf("package layer = %+v", packagesResp.PackageLayers[0])
		}
	}
	if secretArtifactsEnabled {
		var secretCount int
		var secretRaw []byte
		if err := pool.QueryRow(ctx, `
SELECT package_count, payload
  FROM image_scan_artifacts
 WHERE org_id = $1
   AND image_scan_result_id = $2
   AND artifact_type = 'secret-scan'
   AND format = 'constellation-image-secrets-v1'`, orgID, completeRes.ImageScanResultID).Scan(&secretCount, &secretRaw); err != nil {
			t.Fatal(err)
		}
		var secretReport struct {
			ImageDigest string                  `json:"image_digest"`
			SecretCount int                     `json:"secret_count"`
			Secrets     []scanner.SecretFinding `json:"secrets"`
		}
		if err := json.Unmarshal(secretRaw, &secretReport); err != nil {
			t.Fatal(err)
		}
		if secretCount != 1 || secretReport.SecretCount != 1 || secretReport.ImageDigest != imageDigest || len(secretReport.Secrets) != 1 {
			t.Fatalf("secret report = %+v secretCount=%d", secretReport, secretCount)
		}
		if secretReport.Secrets[0].MatchRedacted != "[redacted]" {
			t.Fatalf("secret redaction was not sanitized: %+v", secretReport.Secrets[0])
		}
		if strings.Contains(string(secretRaw), "AKIA1234567890TEST") {
			t.Fatalf("secret artifact contains raw match: %s", secretRaw)
		}
	}
	if signatureArtifactsEnabled {
		var signatureRaw []byte
		if err := pool.QueryRow(ctx, `
SELECT payload
  FROM image_scan_artifacts
 WHERE org_id = $1
   AND image_scan_result_id = $2
   AND artifact_type = 'signature-scan'
   AND format = 'constellation-image-signature-v1'`, orgID, completeRes.ImageScanResultID).Scan(&signatureRaw); err != nil {
			t.Fatal(err)
		}
		var signatureReport struct {
			ImageDigest string                  `json:"image_digest"`
			Status      string                  `json:"status"`
			Signed      bool                    `json:"signed"`
			Trusted     bool                    `json:"trusted"`
			Signature   scanner.SignatureResult `json:"signature"`
		}
		if err := json.Unmarshal(signatureRaw, &signatureReport); err != nil {
			t.Fatal(err)
		}
		if signatureReport.ImageDigest != imageDigest || signatureReport.Status != "trusted" || !signatureReport.Signed || !signatureReport.Trusted || !signatureReport.Signature.Trusted {
			t.Fatalf("signature report = %+v", signatureReport)
		}
		var imageSigned bool
		var signatureInfo []byte
		if err := pool.QueryRow(ctx, `
SELECT signed, signature_info
  FROM images
 WHERE digest = $1`, imageDigest).Scan(&imageSigned, &signatureInfo); err != nil {
			t.Fatal(err)
		}
		if !imageSigned || !strings.Contains(string(signatureInfo), "signature trusted") {
			t.Fatalf("image signature metadata signed=%v info=%s", imageSigned, signatureInfo)
		}
	}
	if layerArtifactsEnabled {
		var layerCount int
		var layerRaw []byte
		if err := pool.QueryRow(ctx, `
SELECT package_count, payload
  FROM image_scan_artifacts
 WHERE org_id = $1
   AND image_scan_result_id = $2
   AND artifact_type = 'layer-metadata'
   AND format = 'constellation-image-layers-v1'`, orgID, completeRes.ImageScanResultID).Scan(&layerCount, &layerRaw); err != nil {
			t.Fatal(err)
		}
		var layerReport struct {
			ImageDigest    string               `json:"image_digest"`
			LayerCount     int                  `json:"layer_count"`
			ManifestDigest string               `json:"manifest_digest"`
			Status         string               `json:"status"`
			Layers         []scanner.ImageLayer `json:"layers"`
		}
		if err := json.Unmarshal(layerRaw, &layerReport); err != nil {
			t.Fatal(err)
		}
		if layerCount != 2 || layerReport.LayerCount != 2 || layerReport.ImageDigest != imageDigest || layerReport.ManifestDigest != imageDigest || layerReport.Status != "observed" || len(layerReport.Layers) != 2 {
			t.Fatalf("layer report = %+v layerCount=%d", layerReport, layerCount)
		}
		var layersInfo, architecturesInfo []byte
		var sizeBytes int64
		if err := pool.QueryRow(ctx, `
SELECT layers, architectures, COALESCE(size_bytes, 0)
  FROM images
 WHERE digest = $1`, imageDigest).Scan(&layersInfo, &architecturesInfo, &sizeBytes); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(layersInfo), "sha256:1111111111111111111111111111111111111111111111111111111111111111") || !strings.Contains(string(architecturesInfo), "linux/amd64") || sizeBytes != 350 {
			t.Fatalf("image layer metadata layers=%s architectures=%s size=%d", layersInfo, architecturesInfo, sizeBytes)
		}
	}
	if fileRiskArtifactsEnabled {
		var fileRiskCount int
		var fileRiskRaw []byte
		if err := pool.QueryRow(ctx, `
SELECT package_count, payload
  FROM image_scan_artifacts
 WHERE org_id = $1
   AND image_scan_result_id = $2
   AND artifact_type = 'file-risk'
   AND format = 'constellation-image-file-risk-v1'`, orgID, completeRes.ImageScanResultID).Scan(&fileRiskCount, &fileRiskRaw); err != nil {
			t.Fatal(err)
		}
		var fileRiskReport struct {
			ImageDigest   string                         `json:"image_digest"`
			FileRiskCount int                            `json:"file_risk_count"`
			Status        string                         `json:"status"`
			Findings      []scanner.ImageFileRiskFinding `json:"findings"`
		}
		if err := json.Unmarshal(fileRiskRaw, &fileRiskReport); err != nil {
			t.Fatal(err)
		}
		if fileRiskCount != 2 || fileRiskReport.FileRiskCount != 2 || fileRiskReport.ImageDigest != imageDigest || fileRiskReport.Status != "observed" || len(fileRiskReport.Findings) != 2 {
			t.Fatalf("file risk report = %+v fileRiskCount=%d", fileRiskReport, fileRiskCount)
		}
	}

	imageResults := handler.NewImageScanResults(d)
	pkgReq := httptest.NewRequest(http.MethodGet, "/api/v1/image-scan-results/"+completeRes.ImageScanResultID.String()+"/packages", nil)
	pkgReq = pkgReq.WithContext(authctx.WithSubject(pkgReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	pkgCtx := chi.NewRouteContext()
	pkgCtx.URLParams.Add("id", completeRes.ImageScanResultID.String())
	pkgReq = pkgReq.WithContext(context.WithValue(pkgReq.Context(), chi.RouteCtxKey, pkgCtx))
	pkgRec := httptest.NewRecorder()
	imageResults.Packages(pkgRec, pkgReq)
	if pkgRec.Code != http.StatusOK {
		t.Fatalf("packages status: %d body: %s", pkgRec.Code, pkgRec.Body.String())
	}
	var pkgRes struct {
		PackageInventory struct {
			Packages []scanner.Package `json:"packages"`
		} `json:"package_inventory"`
	}
	if err := json.NewDecoder(pkgRec.Body).Decode(&pkgRes); err != nil {
		t.Fatal(err)
	}
	if len(pkgRes.PackageInventory.Packages) != 1 || pkgRes.PackageInventory.Packages[0].Purl != "pkg:apk/openssl@3.0.0-r0" {
		t.Fatalf("packages endpoint = %+v", pkgRes.PackageInventory.Packages)
	}
	if secretArtifactsEnabled {
		secretReq := httptest.NewRequest(http.MethodGet, "/api/v1/image-scan-results/"+completeRes.ImageScanResultID.String()+"/secrets", nil)
		secretReq = secretReq.WithContext(authctx.WithSubject(secretReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		secretCtx := chi.NewRouteContext()
		secretCtx.URLParams.Add("id", completeRes.ImageScanResultID.String())
		secretReq = secretReq.WithContext(context.WithValue(secretReq.Context(), chi.RouteCtxKey, secretCtx))
		secretRec := httptest.NewRecorder()
		imageResults.Secrets(secretRec, secretReq)
		if secretRec.Code != http.StatusOK {
			t.Fatalf("secrets status: %d body: %s", secretRec.Code, secretRec.Body.String())
		}
		if strings.Contains(secretRec.Body.String(), "AKIA1234567890TEST") {
			t.Fatalf("secrets endpoint contains raw match: %s", secretRec.Body.String())
		}
	}
	if layerArtifactsEnabled {
		layersReq := httptest.NewRequest(http.MethodGet, "/api/v1/image-scan-results/"+completeRes.ImageScanResultID.String()+"/layers", nil)
		layersReq = layersReq.WithContext(authctx.WithSubject(layersReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		layersCtx := chi.NewRouteContext()
		layersCtx.URLParams.Add("id", completeRes.ImageScanResultID.String())
		layersReq = layersReq.WithContext(context.WithValue(layersReq.Context(), chi.RouteCtxKey, layersCtx))
		layersRec := httptest.NewRecorder()
		imageResults.Layers(layersRec, layersReq)
		if layersRec.Code != http.StatusOK {
			t.Fatalf("layers status: %d body: %s", layersRec.Code, layersRec.Body.String())
		}
		if !strings.Contains(layersRec.Body.String(), "sha256:2222222222222222222222222222222222222222222222222222222222222222") {
			t.Fatalf("layers endpoint body = %s", layersRec.Body.String())
		}
	}
	if fileRiskArtifactsEnabled {
		fileRiskReq := httptest.NewRequest(http.MethodGet, "/api/v1/image-scan-results/"+completeRes.ImageScanResultID.String()+"/file-risks", nil)
		fileRiskReq = fileRiskReq.WithContext(authctx.WithSubject(fileRiskReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		fileRiskCtx := chi.NewRouteContext()
		fileRiskCtx.URLParams.Add("id", completeRes.ImageScanResultID.String())
		fileRiskReq = fileRiskReq.WithContext(context.WithValue(fileRiskReq.Context(), chi.RouteCtxKey, fileRiskCtx))
		fileRiskRec := httptest.NewRecorder()
		imageResults.FileRisks(fileRiskRec, fileRiskReq)
		if fileRiskRec.Code != http.StatusOK {
			t.Fatalf("file risks status: %d body: %s", fileRiskRec.Code, fileRiskRec.Body.String())
		}
		if !strings.Contains(fileRiskRec.Body.String(), "/usr/bin/suid-helper") {
			t.Fatalf("file risks endpoint body = %s", fileRiskRec.Body.String())
		}
	}
	if signatureArtifactsEnabled {
		signatureReq := httptest.NewRequest(http.MethodGet, "/api/v1/image-scan-results/"+completeRes.ImageScanResultID.String()+"/signature", nil)
		signatureReq = signatureReq.WithContext(authctx.WithSubject(signatureReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		signatureCtx := chi.NewRouteContext()
		signatureCtx.URLParams.Add("id", completeRes.ImageScanResultID.String())
		signatureReq = signatureReq.WithContext(context.WithValue(signatureReq.Context(), chi.RouteCtxKey, signatureCtx))
		signatureRec := httptest.NewRecorder()
		imageResults.Signature(signatureRec, signatureReq)
		if signatureRec.Code != http.StatusOK {
			t.Fatalf("signature status: %d body: %s", signatureRec.Code, signatureRec.Body.String())
		}
		if !strings.Contains(signatureRec.Body.String(), "signature trusted") {
			t.Fatalf("signature endpoint body = %s", signatureRec.Body.String())
		}
	}

	for _, tc := range []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
		field   string
		want    string
	}{
		{name: "spdx", path: "/api/v1/image-scan-results/" + completeRes.ImageScanResultID.String() + "/sbom/spdx", handler: imageResults.SPDX, field: "spdxVersion", want: "SPDX-2.3"},
		{name: "cyclonedx", path: "/api/v1/image-scan-results/" + completeRes.ImageScanResultID.String() + "/sbom/cyclonedx", handler: imageResults.CycloneDX, field: "bomFormat", want: "CycloneDX"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", completeRes.ImageScanResultID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		tc.handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status: %d body: %s", tc.name, rec.Code, rec.Body.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s decode: %v", tc.name, err)
		}
		if doc[tc.field] != tc.want {
			t.Fatalf("%s doc[%s] = %v, want %s", tc.name, tc.field, doc[tc.field], tc.want)
		}
	}
}

func TestCompleteScanEnginesToResultsTracksSuccessfulEngines(t *testing.T) {
	engines := completeScanEnginesToResults([]completeScanEngine{
		{Engine: " Trivy "},
		{Engine: "grype", Error: "grype failed"},
		{Engine: " "},
	})
	if len(engines) != 2 {
		t.Fatalf("engines = %+v, want two normalized entries", engines)
	}
	if !successfulEngineRan(engines, "trivy") {
		t.Fatalf("expected trivy to be successful: %+v", engines)
	}
	if successfulEngineRan(engines, "grype") {
		t.Fatalf("expected failed grype to be unsuccessful: %+v", engines)
	}
	if successfulEngineRan(engines, "syft") {
		t.Fatalf("expected missing syft to be unsuccessful: %+v", engines)
	}
}

func TestImageScanArtifacts_RecordsCleanSecretScanOnlyForSuccessfulTrivy(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.image_scan_artifacts')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: image_scan_artifacts migration not applied (%v)", err)
	}

	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Clean Secret Artifact Test')`, orgID, "clean-secret-artifact-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	insertResult := func(id uuid.UUID, digest string) {
		t.Helper()
		imageRef := "registry.example.test/constellation/clean@" + digest
		if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
    id, org_id, image_ref, image_ref_normalized, image_repository, image_tag,
    image_digest, platform, scanner_profile, package_count, finding_count
) VALUES ($1, $2, $3, $3, 'registry.example.test/constellation/clean', '',
          $4, 'linux/amd64', 'default', 0, 0)`,
			id, orgID, imageRef, digest); err != nil {
			t.Fatalf("insert image scan result: %v", err)
		}
	}

	cleanResultID := uuid.New()
	cleanDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	insertResult(cleanResultID, cleanDigest)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertImageScanArtifacts(ctx, tx, orgID, cleanResultID, scanImageIdentity{
		Ref:            "registry.example.test/constellation/clean@" + cleanDigest,
		NormalizedRef:  "registry.example.test/constellation/clean@" + cleanDigest,
		Repository:     "registry.example.test/constellation/clean",
		Digest:         cleanDigest,
		Platform:       "linux/amd64",
		ScannerProfile: "default",
	}, scanner.ScanResult{
		Engines: []scanner.EngineResult{{Engine: "trivy"}},
	}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("upsert clean artifact: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var secretCount int
	var secretRaw []byte
	if err := pool.QueryRow(ctx, `
SELECT package_count, payload
  FROM image_scan_artifacts
 WHERE org_id = $1
   AND image_scan_result_id = $2
   AND artifact_type = 'secret-scan'
   AND format = 'constellation-image-secrets-v1'`, orgID, cleanResultID).Scan(&secretCount, &secretRaw); err != nil {
		t.Fatalf("query clean secret artifact: %v", err)
	}
	var cleanReport struct {
		Status      string                  `json:"status"`
		Engine      string                  `json:"engine"`
		SecretCount int                     `json:"secret_count"`
		Secrets     []scanner.SecretFinding `json:"secrets"`
	}
	if err := json.Unmarshal(secretRaw, &cleanReport); err != nil {
		t.Fatal(err)
	}
	if secretCount != 0 || cleanReport.SecretCount != 0 || cleanReport.Status != "observed" || cleanReport.Engine != "trivy" || len(cleanReport.Secrets) != 0 {
		t.Fatalf("clean secret artifact = %+v package_count=%d", cleanReport, secretCount)
	}

	failedResultID := uuid.New()
	failedDigest := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	insertResult(failedResultID, failedDigest)
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertImageScanArtifacts(ctx, tx, orgID, failedResultID, scanImageIdentity{
		Ref:            "registry.example.test/constellation/clean@" + failedDigest,
		NormalizedRef:  "registry.example.test/constellation/clean@" + failedDigest,
		Repository:     "registry.example.test/constellation/clean",
		Digest:         failedDigest,
		Platform:       "linux/amd64",
		ScannerProfile: "default",
	}, scanner.ScanResult{
		Engines: []scanner.EngineResult{{Engine: "trivy", Error: "trivy failed"}},
	}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("upsert failed artifact: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var failedArtifactCount int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int
  FROM image_scan_artifacts
 WHERE org_id = $1
   AND image_scan_result_id = $2
   AND artifact_type = 'secret-scan'
   AND format = 'constellation-image-secrets-v1'`, orgID, failedResultID).Scan(&failedArtifactCount); err != nil {
		t.Fatal(err)
	}
	if failedArtifactCount != 0 {
		t.Fatalf("failed trivy wrote %d clean secret artifacts, want 0", failedArtifactCount)
	}
}

func TestScanFindingStableKeyIgnoresPackageLocations(t *testing.T) {
	base := scanner.Finding{
		VulnerabilityID: "CVE-2026-0001",
		Package: scanner.Package{
			Ecosystem:        "deb",
			Name:             "openssl",
			Version:          "3.0.13-0ubuntu3",
			Purl:             "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3?arch=amd64",
			NamespaceKind:    "os",
			NamespaceName:    "ubuntu",
			NamespaceVersion: "24.04",
		},
		FixedVersion: "3.0.13-0ubuntu4",
		AffectedRange: &scanner.AffectedRange{
			NamespaceKind: "os",
			NamespaceName: "ubuntu",
			PackageName:   "openssl",
			FixedVersion:  "3.0.13-0ubuntu4",
		},
	}
	withLocation := base
	withLocation.Package.Locations = []scanner.PackageLocation{{
		Path:        "/var/lib/dpkg/status",
		LayerDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}
	withDifferentLocation := base
	withDifferentLocation.Package.Locations = []scanner.PackageLocation{{
		Path:        "/usr/share/doc/openssl/copyright",
		LayerDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}}

	if scanFindingStableKey(withLocation) != scanFindingStableKey(withDifferentLocation) {
		t.Fatalf("package locations changed vulnerability finding key")
	}
}

func TestScanJobs_RepositorySourceImageScanPreservesProvenance(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id = $1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}

	imageDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	imageRef := "ghcr.io/acme/payments@" + imageDigest
	sourceRef := "github.com/acme/payments@abcdef1234567890"
	vulnID := "CVE-2026-7222"

	_, _ = pool.Exec(ctx, `DELETE FROM image_scan_results WHERE org_id = $1 AND image_digest = $2`, orgID, imageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM findings WHERE org_id = $1 AND external_id = $2`, orgID, vulnID)
	_, _ = pool.Exec(ctx, `DELETE FROM assets WHERE org_id = $1 AND digest = $2`, orgID, imageDigest)
	_, _ = pool.Exec(ctx, `DELETE FROM scan_targets WHERE org_id = $1 AND (ref = $2 OR source_ref = $3)`, orgID, imageRef, sourceRef)
	_, _ = pool.Exec(ctx, `DELETE FROM scanner_tokens WHERE name = 'repository-source-test'`)
	clearScanQueue(t, pool, orgID)

	rawToken, _, err := handler.IssueScannerToken(ctx, pool, orgID, "repository-source-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	h := NewScanJobs(d, audit.New(pool))
	metadata := json.RawMessage(`{"provider":"github-actions","workflow":"release","run_id":"12345","commit":"abcdef1234567890"}`)
	body, _ := json.Marshal(EnqueueRequest{
		TargetType: "image",
		TargetRef:  imageRef,
		SourceType: "repository",
		SourceRef:  sourceRef,
		Platform:   "linux/amd64",
		Metadata:   metadata,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs", bytes.NewReader(body))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	h.Enqueue(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enqueue status: %d body: %s", rec.Code, rec.Body.String())
	}
	var enqRes struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&enqRes); err != nil {
		t.Fatal(err)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs", nil)
	listReq = listReq.WithContext(authctx.WithSubject(listReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	listRec := httptest.NewRecorder()
	h.List(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status: %d body: %s", listRec.Code, listRec.Body.String())
	}
	var listRes struct {
		Jobs []JobView `json:"jobs"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&listRes); err != nil {
		t.Fatal(err)
	}
	var listed *JobView
	for i := range listRes.Jobs {
		if listRes.Jobs[i].ID == enqRes.ID {
			listed = &listRes.Jobs[i]
			break
		}
	}
	if listed == nil || listed.SourceType != "repository" || listed.SourceRef != sourceRef || len(listed.Metadata) == 0 {
		t.Fatalf("listed repository job = %+v", listed)
	}

	claimReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim", nil)
	claimReq.Header.Set("Authorization", "Bearer "+rawToken)
	claimRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(claimRec, claimReq)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("claim status: %d body: %s", claimRec.Code, claimRec.Body.String())
	}
	var claim struct {
		ID         uuid.UUID `json:"id"`
		TargetID   uuid.UUID `json:"target_id"`
		TargetType string    `json:"target_type"`
		TargetRef  string    `json:"target_ref"`
		SourceType string    `json:"source_type"`
		SourceRef  string    `json:"source_ref"`
	}
	if err := json.NewDecoder(claimRec.Body).Decode(&claim); err != nil {
		t.Fatal(err)
	}
	if claim.ID != enqRes.ID || claim.TargetType != "image" || claim.TargetRef != imageRef || claim.SourceType != "repository" || claim.SourceRef != sourceRef {
		t.Fatalf("claim = %+v", claim)
	}

	completeBody, _ := json.Marshal(map[string]any{
		"image_ref":     imageRef,
		"image_digest":  imageDigest,
		"platform":      "linux/amd64",
		"package_count": 1,
		"findings": []scanner.Finding{{
			VulnerabilityID: vulnID,
			Severity:        "critical",
			Title:           "repository source fixture",
			Package: scanner.Package{
				Ecosystem: "deb",
				Name:      "openssl",
				Version:   "3.0.0-1",
			},
			CanonicalEngine: "vulndb",
		}},
	})
	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+enqRes.ID.String()+"/complete", bytes.NewReader(completeBody))
	completeReq.Header.Set("Authorization", "Bearer "+rawToken)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", enqRes.ID.String())
	completeReq = completeReq.WithContext(context.WithValue(completeReq.Context(), chi.RouteCtxKey, rctx))
	completeRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Complete)).ServeHTTP(completeRec, completeReq)
	if completeRec.Code != http.StatusOK {
		t.Fatalf("complete status: %d body: %s", completeRec.Code, completeRec.Body.String())
	}

	var resultID uuid.UUID
	var resultSourceType, resultSourceRef string
	if err := pool.QueryRow(ctx, `
SELECT id, COALESCE(source_type, ''), COALESCE(source_ref, '')
  FROM image_scan_results
 WHERE org_id = $1 AND image_digest = $2
 ORDER BY last_scanned_at DESC
 LIMIT 1`, orgID, imageDigest).Scan(&resultID, &resultSourceType, &resultSourceRef); err != nil {
		t.Fatal(err)
	}
	if resultSourceType != "repository" || resultSourceRef != sourceRef {
		t.Fatalf("persisted result provenance source=%s/%s", resultSourceType, resultSourceRef)
	}

	imageResults := handler.NewImageScanResults(d)
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/image-scan-results/"+resultID.String(), nil)
	getReq = getReq.WithContext(authctx.WithSubject(getReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	resultCtx := chi.NewRouteContext()
	resultCtx.URLParams.Add("id", resultID.String())
	getReq = getReq.WithContext(context.WithValue(getReq.Context(), chi.RouteCtxKey, resultCtx))
	getRec := httptest.NewRecorder()
	imageResults.Get(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("image result status: %d body: %s", getRec.Code, getRec.Body.String())
	}
	var resultDetail struct {
		ImageScanResult handler.ImageScanResultDTO    `json:"image_scan_result"`
		Findings        []handler.ImageScanFindingDTO `json:"findings"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&resultDetail); err != nil {
		t.Fatal(err)
	}
	if resultDetail.ImageScanResult.SourceType != "repository" || resultDetail.ImageScanResult.SourceRef != sourceRef {
		t.Fatalf("result provenance = %+v", resultDetail.ImageScanResult)
	}
	var resultMetadata struct {
		Provider string `json:"provider"`
		Workflow string `json:"workflow"`
		RunID    string `json:"run_id"`
		Commit   string `json:"commit"`
	}
	if err := json.Unmarshal(resultDetail.ImageScanResult.ScanTargetMetadata, &resultMetadata); err != nil {
		t.Fatal(err)
	}
	if resultMetadata.Provider != "github-actions" || resultMetadata.Workflow != "release" || resultMetadata.Commit != "abcdef1234567890" {
		t.Fatalf("result metadata = %+v", resultMetadata)
	}
	if len(resultDetail.Findings) != 1 || resultDetail.Findings[0].ExternalID != vulnID {
		t.Fatalf("findings = %+v", resultDetail.Findings)
	}
	var findingDetail struct {
		SourceRef string `json:"source_ref"`
	}
	if err := json.Unmarshal(resultDetail.Findings[0].Detail, &findingDetail); err != nil {
		t.Fatal(err)
	}
	if findingDetail.SourceRef != sourceRef {
		t.Fatalf("finding detail provenance = %+v", findingDetail)
	}
}

func TestScanJobs_ImpactedWorkloadsMatchesDigestAndCluster(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.image_workload_links')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: image_workload_links migration not applied (%v)", err)
	}

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id = $1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}

	clusterID := uuid.New()
	clusterName := "impact-cluster-" + clusterID.String()
	digest := "sha256:abc123impact"
	targetRef := "registry.example.test/payments/api:prod"
	runningRef := "registry.example.test/payments/api@" + digest
	deploymentID := uuid.New()
	_, _ = pool.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, clusterID)
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state)
VALUES ($1, $2, $3, 'kubernetes', 'connected')`, clusterID, orgID, clusterName); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (
    id, org_id, cluster_id, namespace, name, kind, image_refs,
    risk_score, finding_count, critical_count, high_count
) VALUES ($1, $2, $3, 'payments', 'api', 'Deployment', $4, 91, 7, 2, 3)`,
		deploymentID, orgID, clusterID, []string{runningRef}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest
) VALUES ($1, $2, $3, 'payments/api', 'payments', 'api', 'Deployment', $4, $4, 'registry.example.test/payments/api', '', $5)`,
		orgID, clusterID, deploymentID, runningRef, digest); err != nil {
		t.Fatal(err)
	}

	h := NewScanJobs(d, audit.New(pool))
	target, err := h.upsertScanTarget(ctx, nil, orgID, handler.ScanTargetUpsert{
		TargetType:      "image",
		TargetRef:       targetRef,
		TargetClusterID: &clusterID,
		SourceType:      "manual",
		ImageRef:        targetRef,
		ImageDigest:     digest,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-targets/"+target.ID.String()+"/impacted-workloads", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", target.ID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.ImpactedWorkloads(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		TargetID          uuid.UUID                  `json:"target_id"`
		ImageDigest       string                     `json:"image_digest"`
		ImpactedCount     int                        `json:"impacted_count"`
		ImpactedWorkloads []handler.ImpactedWorkload `json:"impacted_workloads"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.TargetID != target.ID || got.ImageDigest != digest {
		t.Fatalf("target response = %+v, want target=%s digest=%s", got, target.ID, digest)
	}
	if got.ImpactedCount != 1 || len(got.ImpactedWorkloads) != 1 {
		t.Fatalf("impacts = %+v", got)
	}
	impact := got.ImpactedWorkloads[0]
	if impact.WorkloadID != "payments/api" || impact.ImageRef != runningRef || impact.ImageDigest != digest {
		t.Fatalf("impact identity = %+v", impact)
	}
	if impact.RiskScore != 91 || impact.CriticalCount != 2 || impact.HighCount != 3 || impact.FindingCount != 7 {
		t.Fatalf("impact rollup = %+v", impact)
	}
}

func TestScanJobs_ListIncludesQueueMetricsByTargetType(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	imageTargetID := uuid.New()
	hostTargetID := uuid.New()

	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scan Queue Metrics Test')`, orgID, "scan-queue-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref)
VALUES ($1, $2, 'image', 'registry.example.test/app:latest', 'manual', 'registry.example.test/app:latest'),
       ($3, $2, 'host', 'node/local', 'host', NULL)`,
		imageTargetID, orgID, hostTargetID); err != nil {
		t.Fatalf("scan targets: %v", err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_jobs (id, org_id, target_id, status, requested_at, claimed_at, lease_expires_at)
	VALUES (gen_random_uuid(), $1, $2, 'pending', NOW() - INTERVAL '2 minutes', NULL, NULL),
	       (gen_random_uuid(), $1, $2, 'running', NOW() - INTERVAL '1 minute', NOW() - INTERVAL '1 minute', NOW() + INTERVAL '10 minutes'),
	       (gen_random_uuid(), $1, $2, 'paused', NOW() - INTERVAL '3 minutes', NULL, NULL),
	       (gen_random_uuid(), $1, $2, 'canceled', NOW() - INTERVAL '4 minutes', NULL, NULL),
	       (gen_random_uuid(), $1, $3, 'pending', NOW() - INTERVAL '5 minutes', NULL, NULL),
	       (gen_random_uuid(), $1, $3, 'failed', NOW() - INTERVAL '10 minutes', NULL, NULL),
	       (gen_random_uuid(), $1, $3, 'running', NOW() - INTERVAL '15 minutes', NOW() - INTERVAL '15 minutes', NOW() - INTERVAL '1 minute')`,
		orgID, imageTargetID, hostTargetID); err != nil {
		t.Fatalf("scan jobs: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewScanJobs(d, audit.New(pool)).List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Jobs         []JobView                    `json:"jobs"`
		QueueMetrics []handler.ScanQueueMetricDTO `json:"queue_metrics"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Jobs) != 7 {
		t.Fatalf("jobs = %d, want 7", len(got.Jobs))
	}
	byType := map[string]handler.ScanQueueMetricDTO{}
	for _, item := range got.QueueMetrics {
		byType[item.TargetType] = item
	}
	if byType["image"].Pending != 1 || byType["image"].Running != 1 || byType["image"].StaleRunning != 0 || byType["image"].Paused != 1 || byType["image"].Canceled != 1 || byType["image"].Failed != 0 {
		t.Fatalf("image queue metric = %+v", byType["image"])
	}
	if byType["host"].Pending != 1 || byType["host"].Running != 1 || byType["host"].StaleRunning != 1 || byType["host"].Paused != 0 || byType["host"].Canceled != 0 || byType["host"].Failed != 1 || byType["host"].OldestPendingSeconds < 240 {
		t.Fatalf("host queue metric = %+v", byType["host"])
	}
}

// TestScanJobs_ImageFindingsPromotedToDashboardAndFindingsList proves the under-reporting
// fix: vulnerabilities recorded in image_scan_findings for an image that is RUNNING on a
// workload (via image_workload_links) are promoted into the unified `findings` table, so
// they surface in both the cluster dashboard severity rollup and the Findings list — which
// previously read only workload/host findings and showed 0 image vulns. Also covers
// idempotency (re-promotion replaces, no dupes) and running-only scoping (an unlinked image
// produces nothing).
func TestScanJobs_ImageFindingsPromotedToDashboardAndFindingsList(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.image_workload_links')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: image_workload_links migration not applied (%v)", err)
	}

	// Isolated org so dashboard/findings counts are deterministic.
	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Promote Test')`,
		orgID, "promote-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })

	clusterID := uuid.New()
	digest := "sha256:promote00000000000000000000000000000000000000000000000000000001"
	imageRef := "registry.example.test/team/api@" + digest
	repo := "registry.example.test/team/api"
	deploymentID := uuid.New()
	imageAssetID := uuid.New()
	imageTargetID := uuid.New()
	resultID := uuid.New()

	mustExec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup (%s): %v", strings.SplitN(sql, "\n", 3)[0], err)
		}
	}
	mustExec(`INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, $3, 'kubernetes', 'connected')`,
		clusterID, orgID, "promote-cluster-"+clusterID.String())
	mustExec(`INSERT INTO deployments (id, org_id, cluster_id, namespace, name, kind, image_refs)
VALUES ($1, $2, $3, 'team', 'api', 'Deployment', $4)`, deploymentID, orgID, clusterID, []string{imageRef})
	mustExec(`INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest)
VALUES ($1, $2, $3, 'team/api', 'team', 'api', 'Deployment', $4, $4, $5, '', $6)`,
		orgID, clusterID, deploymentID, imageRef, repo, digest)
	mustExec(`INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', $3, $4, '{}'::jsonb, 'high')`, imageAssetID, orgID, repo, digest)
	mustExec(`INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref, image_digest)
VALUES ($1, $2, 'image', $3, 'manual', $3, $4)`, imageTargetID, orgID, imageRef, digest)
	mustExec(`INSERT INTO image_scan_results (
    id, org_id, scan_target_id, asset_id, image_ref, image_ref_normalized, image_repository,
    image_tag, image_digest, finding_count)
VALUES ($1, $2, $3, $4, $5, $5, $6, '', $7, 3)`,
		resultID, orgID, imageTargetID, imageAssetID, imageRef, repo, digest)

	// Two criticals and one high in the canonical image scan store.
	for i, sev := range []string{"critical", "critical", "high"} {
		mustExec(`INSERT INTO image_scan_findings (
    org_id, image_scan_result_id, finding_key, external_id, title, severity, risk_score)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			orgID, resultID, "key-"+sev+"-"+handler.Itoa(i), "CVE-2099-"+sev+handler.Itoa(i), "img "+sev, sev, 90)
	}

	promote := func() int {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		n, err := promoteImageFindingsToWorkloads(ctx, tx, orgID, resultID, imageTargetID, imageAssetID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// First promotion: 3 image findings on one running cluster -> 3 unified findings.
	if n := promote(); n != 3 {
		t.Fatalf("first promotion inserted %d rows, want 3", n)
	}
	// Idempotency: re-running replaces, does not duplicate.
	if n := promote(); n != 3 {
		t.Fatalf("second promotion inserted %d rows, want 3", n)
	}
	var total int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*)::int FROM findings WHERE org_id = $1 AND target_type = 'image-workload'`, orgID).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("promoted findings after re-scan = %d, want 3 (no dupes)", total)
	}

	// Dashboard summary now counts the image vulns under the running cluster.
	dashReq := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary?cluster_id="+clusterID.String(), nil)
	dashReq = dashReq.WithContext(authctx.WithSubject(dashReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	dashRec := httptest.NewRecorder()
	handler.NewDashboard(d).Summary(dashRec, dashReq)
	if dashRec.Code != http.StatusOK {
		t.Fatalf("dashboard status %d: %s", dashRec.Code, dashRec.Body.String())
	}
	var dash handler.DashboardSummaryDTO
	if err := json.NewDecoder(dashRec.Body).Decode(&dash); err != nil {
		t.Fatal(err)
	}
	if dash.FindingsByLevel["critical"] != 2 || dash.FindingsByLevel["high"] != 1 {
		t.Fatalf("dashboard severity rollup = %v, want critical=2 high=1", dash.FindingsByLevel)
	}
	if dash.OpenFindings != 3 {
		t.Fatalf("dashboard open findings = %d, want 3", dash.OpenFindings)
	}

	// Findings list (vulnerability kind) now surfaces the promoted image vulns.
	// The findings List handler lives in internal/handler/findings, which imports
	// this package — so a handler-package test cannot call it without an import
	// cycle. We assert the same outcome by querying the findings table exactly the
	// way List does for ?kind=vulnerability&cluster_id=<cluster>.
	listRows, err := pool.Query(ctx, `
SELECT severity, cluster_id
  FROM findings
 WHERE org_id = $1
   AND ($2::text = '' OR kind = $2)
   AND ($3::uuid IS NULL OR cluster_id = $3)`, orgID, "vulnerability", clusterID)
	if err != nil {
		t.Fatalf("findings list query: %v", err)
	}
	crit, high, listN := 0, 0, 0
	for listRows.Next() {
		var sev string
		var cid *uuid.UUID
		if err := listRows.Scan(&sev, &cid); err != nil {
			listRows.Close()
			t.Fatal(err)
		}
		listN++
		if cid == nil || *cid != clusterID {
			continue
		}
		switch sev {
		case "critical":
			crit++
		case "high":
			high++
		}
	}
	listRows.Close()
	if err := listRows.Err(); err != nil {
		t.Fatal(err)
	}
	if crit != 2 || high != 1 {
		t.Fatalf("findings list severities = critical:%d high:%d, want 2/1 (n=%d)", crit, high, listN)
	}

	// Running-only scoping: an image with NO workload link promotes nothing.
	otherResultID := uuid.New()
	otherDigest := "sha256:unlinked0000000000000000000000000000000000000000000000000000002"
	mustExec(`INSERT INTO image_scan_results (
    id, org_id, image_ref, image_ref_normalized, image_repository, image_tag, image_digest)
VALUES ($1, $2, $3, $3, 'registry.example.test/team/unused', '', $4)`,
		otherResultID, orgID, "registry.example.test/team/unused@"+otherDigest, otherDigest)
	mustExec(`INSERT INTO image_scan_findings (
    org_id, image_scan_result_id, finding_key, external_id, title, severity, risk_score)
VALUES ($1, $2, 'k', 'CVE-2099-unused', 'unused', 'critical', 90)`, orgID, otherResultID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, err := promoteImageFindingsToWorkloads(ctx, tx, orgID, otherResultID, uuid.New(), imageAssetID)
	if err != nil {
		t.Fatalf("unlinked promote: %v", err)
	}
	_ = tx.Commit(ctx)
	if n != 0 {
		t.Fatalf("unlinked image promoted %d findings, want 0 (running-only scoping)", n)
	}
}

func TestScanJobs_StatusReportsNeuVectorAggregate(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	orgID := uuid.New()
	userID := uuid.New()
	targetID := uuid.New()
	exportedAt := "2026-06-14T07:30:00Z"

	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scan Status Test')`, orgID, "scan-status-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Scan Status User')`,
		userID, orgID, "scan-status-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref)
VALUES ($1, $2, 'image', 'registry.example.test/status:latest', 'manual', 'registry.example.test/status:latest')`,
		targetID, orgID); err != nil {
		t.Fatalf("scan target: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (org_id, target_id, status, requested_at, finished_at, bundle_metadata)
VALUES ($1, $2, 'completed', NOW() - INTERVAL '7 minutes', NOW() - INTERVAL '6 minutes', $3::jsonb),
       ($1, $2, 'pending', NOW() - INTERVAL '5 minutes', NULL, NULL),
       ($1, $2, 'running', NOW() - INTERVAL '4 minutes', NULL, NULL),
       ($1, $2, 'failed', NOW() - INTERVAL '3 minutes', NOW() - INTERVAL '2 minutes', NULL),
       ($1, $2, 'paused', NOW() - INTERVAL '2 minutes', NULL, NULL),
       ($1, $2, 'canceled', NOW() - INTERVAL '1 minute', NOW() - INTERVAL '1 minute', NULL)`,
		orgID, targetID, `{"bundle_version":"fixture-20260614","exported_at":"`+exportedAt+`","payload_hash":"sha256:status"}`); err != nil {
		t.Fatalf("scan jobs: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/status", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewScanJobs(d, audit.New(pool)).Status(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var got scanStatusDTO
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Scanned != 1 || got.Scheduled != 1 || got.Scanning != 1 || got.Failed != 1 || got.Paused != 1 || got.Canceled != 1 {
		t.Fatalf("scan status counts = %+v", got)
	}
	if got.CVEDBVersion != "fixture-20260614" || got.CVEDBCreateTime != exportedAt {
		t.Fatalf("scan status bundle = %+v", got)
	}
}

func TestScanJobs_CanceledRunningWorkerReportsAreDropped(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	orgID := uuid.New()
	targetID := uuid.New()
	completeJobID := uuid.New()
	failJobID := uuid.New()

	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Canceled Worker Test')`, orgID, "scan-canceled-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	rawToken, tokenID, err := handler.IssueScannerToken(ctx, pool, orgID, "cancel-token", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	workerID := "scanner:cancel-token:" + tokenID.String() + ":pod-a"
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref)
VALUES ($1, $2, 'image', 'registry.example.test/cancel:latest', 'manual', 'registry.example.test/cancel:latest')`,
		targetID, orgID); err != nil {
		t.Fatalf("scan target: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status, worker_id, requested_at, claimed_at, canceled_at, finished_at)
VALUES ($1, $2, $3, 'canceled', $4, NOW() - INTERVAL '5 minutes', NOW() - INTERVAL '4 minutes', NOW() - INTERVAL '1 minute', NOW() - INTERVAL '1 minute'),
       ($5, $2, $3, 'canceled', $4, NOW() - INTERVAL '5 minutes', NOW() - INTERVAL '4 minutes', NOW() - INTERVAL '1 minute', NOW() - INTERVAL '1 minute')`,
		completeJobID, orgID, targetID, workerID, failJobID); err != nil {
		t.Fatalf("scan jobs: %v", err)
	}
	h := NewScanJobs(d, audit.New(pool))

	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+completeJobID.String()+"/complete", bytes.NewBufferString(`{}`))
	completeReq.Header.Set("Authorization", "Bearer "+rawToken)
	completeReq.Header.Set("X-Constellation-Scanner-Instance", "pod-a")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", completeJobID.String())
	completeReq = completeReq.WithContext(context.WithValue(completeReq.Context(), chi.RouteCtxKey, rctx))
	completeRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Complete)).ServeHTTP(completeRec, completeReq)
	if completeRec.Code != http.StatusOK {
		t.Fatalf("complete canceled status: %d body: %s", completeRec.Code, completeRec.Body.String())
	}
	if !strings.Contains(completeRec.Body.String(), `"dropped":true`) {
		t.Fatalf("complete canceled body = %s", completeRec.Body.String())
	}

	failReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+failJobID.String()+"/fail", bytes.NewBufferString(`{"error":"late scanner error"}`))
	failReq.Header.Set("Authorization", "Bearer "+rawToken)
	failReq.Header.Set("X-Constellation-Scanner-Instance", "pod-a")
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", failJobID.String())
	failReq = failReq.WithContext(context.WithValue(failReq.Context(), chi.RouteCtxKey, rctx))
	failRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Fail)).ServeHTTP(failRec, failReq)
	if failRec.Code != http.StatusOK {
		t.Fatalf("fail canceled status: %d body: %s", failRec.Code, failRec.Body.String())
	}
	if !strings.Contains(failRec.Body.String(), `"dropped":true`) {
		t.Fatalf("fail canceled body = %s", failRec.Body.String())
	}

	var completedWrites int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM image_scan_results WHERE org_id = $1`, orgID).Scan(&completedWrites); err != nil {
		t.Fatal(err)
	}
	if completedWrites != 0 {
		t.Fatalf("canceled completion wrote %d image results", completedWrites)
	}
}

func TestScannerTokenMiddleware_Rejects(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	r := httptest.NewRequest("POST", "/api/v1/scan-jobs/claim", nil)
	r.Header.Set("Authorization", "Bearer not-a-real-token")
	w := httptest.NewRecorder()
	called := false
	handler.ScannerTokenMiddleware(d.Pool())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	})).ServeHTTP(w, r)
	if called {
		t.Fatal("middleware passed through invalid token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: %d", w.Code)
	}
}

// TestVulnProfileDecisionApplication covers the pure mapping from a vuln-profile verdict to the
// finding mutations: escalate raises severity/risk to critical; suppress maps to the lifecycle
// that drops the CVE out of the open critical/high rollups; none/escalate leave lifecycle to the
// caller. Decision values are exercised both as the in-memory vulnprofile.Decision type and as
// the JSON string they decode to from detail_json.
func TestVulnProfileDecisionApplication(t *testing.T) {
	t.Run("escalate bumps severity and risk floor", func(t *testing.T) {
		dec := map[string]any{"decision": vulnprofile.DecisionEscalate}
		sev, risk := applyVulnProfileEscalation(dec, "low", 10)
		if sev != "critical" || risk != handler.SeverityToScore("critical", 0, false) {
			t.Fatalf("escalate = (%s,%d), want (critical,%d)", sev, risk, handler.SeverityToScore("critical", 0, false))
		}
		if got := vulnProfileLifecycleOverride(dec); got != "" {
			t.Fatalf("escalate lifecycle override = %q, want \"\"", got)
		}
		// A higher pre-existing risk is not lowered.
		if _, risk := applyVulnProfileEscalation(dec, "critical", 100); risk != 100 {
			t.Fatalf("escalate lowered risk to %d", risk)
		}
	})
	t.Run("suppress maps to non-open lifecycle", func(t *testing.T) {
		if got := vulnProfileLifecycleOverride(map[string]any{"decision": "suppress_accept"}); got != "accepted" {
			t.Fatalf("suppress_accept lifecycle = %q, want accepted", got)
		}
		if got := vulnProfileLifecycleOverride(map[string]any{"decision": vulnprofile.DecisionSuppressDefer}); got != "suppressed" {
			t.Fatalf("suppress_defer lifecycle = %q, want suppressed", got)
		}
		// Suppress does not bump severity.
		if sev, risk := applyVulnProfileEscalation(map[string]any{"decision": "suppress_accept"}, "high", 70); sev != "high" || risk != 70 {
			t.Fatalf("suppress mutated severity/risk = (%s,%d)", sev, risk)
		}
	})
	t.Run("none leaves everything untouched", func(t *testing.T) {
		if got := vulnProfileLifecycleOverride(nil); got != "" {
			t.Fatalf("nil lifecycle = %q", got)
		}
		if sev, risk := applyVulnProfileEscalation(nil, "medium", 50); sev != "medium" || risk != 50 {
			t.Fatalf("nil mutated severity/risk = (%s,%d)", sev, risk)
		}
	})
}

// TestPromoteImageFindingsAppliesSuppressAndCarriesForwardTriage proves two fixes at once on the
// promotion path: (1) a vuln-profile suppress verdict recorded in detail_json maps the promoted
// finding to a non-open lifecycle so it drops out of the open critical/high rollups; (2) a
// rescan (re-promotion) preserves the user's manual triage — lifecycle, assignee, accepted_until,
// priority, and the original first_seen_at — instead of resetting the CVE to a fresh open finding.
func TestPromoteImageFindingsAppliesSuppressAndCarriesForwardTriage(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.image_workload_links')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: image_workload_links migration not applied (%v)", err)
	}

	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Suppress Promote Test')`,
		orgID, "suppress-promote-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })

	clusterID := uuid.New()
	digest := "sha256:suppress0000000000000000000000000000000000000000000000000000001"
	imageRef := "registry.example.test/team/svc@" + digest
	repo := "registry.example.test/team/svc"
	deploymentID := uuid.New()
	imageAssetID := uuid.New()
	imageTargetID := uuid.New()
	resultID := uuid.New()

	mustExec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup (%s): %v", strings.SplitN(sql, "\n", 3)[0], err)
		}
	}
	mustExec(`INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, $3, 'kubernetes', 'connected')`,
		clusterID, orgID, "suppress-cluster-"+clusterID.String())
	mustExec(`INSERT INTO deployments (id, org_id, cluster_id, namespace, name, kind, image_refs)
VALUES ($1, $2, $3, 'team', 'svc', 'Deployment', $4)`, deploymentID, orgID, clusterID, []string{imageRef})
	mustExec(`INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest)
VALUES ($1, $2, $3, 'team/svc', 'team', 'svc', 'Deployment', $4, $4, $5, '', $6)`,
		orgID, clusterID, deploymentID, imageRef, repo, digest)
	mustExec(`INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', $3, $4, '{}'::jsonb, 'high')`, imageAssetID, orgID, repo, digest)
	mustExec(`INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref, image_digest)
VALUES ($1, $2, 'image', $3, 'manual', $3, $4)`, imageTargetID, orgID, imageRef, digest)
	mustExec(`INSERT INTO image_scan_results (
    id, org_id, scan_target_id, asset_id, image_ref, image_ref_normalized, image_repository,
    image_tag, image_digest, finding_count)
VALUES ($1, $2, $3, $4, $5, $5, $6, '', $7, 3)`,
		resultID, orgID, imageTargetID, imageAssetID, imageRef, repo, digest)

	// Three image-scan findings: a plain critical (open), a suppress_accept critical, and a
	// suppress_defer high. The suppress verdicts are recorded in detail_json exactly as the
	// scan-completion path writes them.
	mustExec(`INSERT INTO image_scan_findings (org_id, image_scan_result_id, finding_key, external_id, title, severity, risk_score, detail_json)
VALUES ($1, $2, 'key-open', 'CVE-2099-OPEN', 'open crit', 'critical', 90, '{}'::jsonb)`, orgID, resultID)
	mustExec(`INSERT INTO image_scan_findings (org_id, image_scan_result_id, finding_key, external_id, title, severity, risk_score, detail_json)
VALUES ($1, $2, 'key-accept', 'CVE-2099-ACCEPT', 'accepted crit', 'critical', 90, '{"vulnerability_profile":{"decision":"suppress_accept"}}'::jsonb)`, orgID, resultID)
	mustExec(`INSERT INTO image_scan_findings (org_id, image_scan_result_id, finding_key, external_id, title, severity, risk_score, detail_json)
VALUES ($1, $2, 'key-defer', 'CVE-2099-DEFER', 'deferred high', 'high', 70, '{"vulnerability_profile":{"decision":"suppress_defer"}}'::jsonb)`, orgID, resultID)

	promote := func() int {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		n, err := promoteImageFindingsToWorkloads(ctx, tx, orgID, resultID, imageTargetID, imageAssetID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if n := promote(); n != 3 {
		t.Fatalf("first promotion inserted %d rows, want 3", n)
	}

	lifecycleOf := func(key string) string {
		t.Helper()
		var lc string
		if err := pool.QueryRow(ctx, `
SELECT lifecycle FROM findings
 WHERE org_id = $1 AND target_type = 'image-workload' AND detail_json->>'scan_finding_key' = $2`,
			orgID, key).Scan(&lc); err != nil {
			t.Fatalf("lifecycle of %s: %v", key, err)
		}
		return lc
	}

	// Suppress verdict applied: accepted/suppressed, not open.
	if got := lifecycleOf("key-accept"); got != "accepted" {
		t.Fatalf("suppress_accept promoted lifecycle = %q, want accepted", got)
	}
	if got := lifecycleOf("key-defer"); got != "suppressed" {
		t.Fatalf("suppress_defer promoted lifecycle = %q, want suppressed", got)
	}
	if got := lifecycleOf("key-open"); got != "open" {
		t.Fatalf("plain promoted lifecycle = %q, want open", got)
	}

	// Only the un-suppressed critical inflates the open critical rollup.
	var openCrit int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int FROM findings
 WHERE org_id = $1 AND target_type = 'image-workload' AND lifecycle = 'open' AND severity = 'critical'`,
		orgID).Scan(&openCrit); err != nil {
		t.Fatal(err)
	}
	if openCrit != 1 {
		t.Fatalf("open critical promoted findings = %d, want 1 (suppressed CVE excluded)", openCrit)
	}

	// Simulate a user triaging the open finding: accept it, assign it, set a grace window and
	// priority. Capture first_seen_at so we can prove it survives the rescan.
	assignee := uuid.New()
	mustExec(`UPDATE findings
   SET lifecycle = 'accepted', assignee_id = $2, accepted_until = NOW() + INTERVAL '30 days', priority = 'p2'
 WHERE org_id = $1 AND target_type = 'image-workload' AND detail_json->>'scan_finding_key' = 'key-open'`,
		orgID, assignee)
	var firstSeen time.Time
	var acceptedUntil time.Time
	if err := pool.QueryRow(ctx, `
SELECT first_seen_at, accepted_until FROM findings
 WHERE org_id = $1 AND target_type = 'image-workload' AND detail_json->>'scan_finding_key' = 'key-open'`,
		orgID).Scan(&firstSeen, &acceptedUntil); err != nil {
		t.Fatal(err)
	}

	// Rescan: re-promote. Triage must carry forward, not reset to open.
	if n := promote(); n != 3 {
		t.Fatalf("re-promotion inserted %d rows, want 3", n)
	}
	var total int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*)::int FROM findings WHERE org_id = $1 AND target_type = 'image-workload'`, orgID).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("promoted findings after rescan = %d, want 3 (no dupes)", total)
	}

	var gotLifecycle, gotPriority string
	var gotAssignee uuid.UUID
	var gotFirstSeen, gotAcceptedUntil time.Time
	if err := pool.QueryRow(ctx, `
SELECT lifecycle, assignee_id, priority, first_seen_at, accepted_until FROM findings
 WHERE org_id = $1 AND target_type = 'image-workload' AND detail_json->>'scan_finding_key' = 'key-open'`,
		orgID).Scan(&gotLifecycle, &gotAssignee, &gotPriority, &gotFirstSeen, &gotAcceptedUntil); err != nil {
		t.Fatal(err)
	}
	if gotLifecycle != "accepted" || gotAssignee != assignee || gotPriority != "p2" {
		t.Fatalf("rescan lost triage: lifecycle=%q assignee=%s priority=%q", gotLifecycle, gotAssignee, gotPriority)
	}
	if !gotFirstSeen.Equal(firstSeen) {
		t.Fatalf("rescan reset first_seen_at: got %s, want %s", gotFirstSeen, firstSeen)
	}
	if !gotAcceptedUntil.Equal(acceptedUntil) {
		t.Fatalf("rescan reset accepted_until: got %s, want %s", gotAcceptedUntil, acceptedUntil)
	}
	// The suppress verdicts still hold after rescan.
	if got := lifecycleOf("key-accept"); got != "accepted" {
		t.Fatalf("suppress_accept lifecycle after rescan = %q, want accepted", got)
	}
}

// TestScanResponseRuleQuarantineEnforcesForRegistryScan proves the registry/repository scan
// quarantine fix: when the scan target has no cluster_id (the canonical "scan in the registry,
// block at admission" case), the quarantine action now resolves every cluster running the image
// via image_workload_links and writes a scope='image' quarantine_entries row per cluster, instead
// of audit-logging enforced=skipped and blocking nothing.
func TestScanResponseRuleQuarantineEnforcesForRegistryScan(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.image_workload_links')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: image_workload_links migration not applied (%v)", err)
	}

	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Registry Quarantine Test')`,
		orgID, "registry-quarantine-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })

	digest := "sha256:regquarantine000000000000000000000000000000000000000000000001"
	repo := "registry.example.test/payments/api"
	imageRef := repo + "@" + digest
	clusterA := uuid.New()
	clusterB := uuid.New()
	mustExec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup (%s): %v", strings.SplitN(sql, "\n", 3)[0], err)
		}
	}
	for i, cid := range []uuid.UUID{clusterA, clusterB} {
		deploymentID := uuid.New()
		mustExec(`INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, $3, 'kubernetes', 'connected')`,
			cid, orgID, "reg-q-cluster-"+handler.Itoa(i)+"-"+cid.String())
		mustExec(`INSERT INTO deployments (id, org_id, cluster_id, namespace, name, kind, image_refs)
VALUES ($1, $2, $3, 'payments', 'api', 'Deployment', $4)`, deploymentID, orgID, cid, []string{imageRef})
		mustExec(`INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest)
VALUES ($1, $2, $3, 'payments/api', 'payments', 'api', 'Deployment', $4, $4, $5, '', $6)`,
			orgID, cid, deploymentID, imageRef, repo, digest)
	}

	// Registry scan target: type image, cluster_id NULL.
	target := handler.ScanTarget{
		ID:        uuid.New(),
		Type:      "image",
		Ref:       imageRef,
		ImageRef:  imageRef,
		ClusterID: nil,
	}
	identity := scanImageIdentity{Ref: imageRef, Repository: repo, Digest: digest}
	ev := scanResponseRuleEvent(target, identity, []scanner.Finding{{VulnerabilityID: "CVE-2099-9999", Severity: "critical"}})

	h := NewScanJobs(d, audit.New(pool))
	h.applyScanResponseRuleActions(ctx, orgID, target, identity, ev, []responserule.Action{{Type: responserule.ActionQuarantine}})

	rows, err := pool.Query(ctx, `
SELECT cluster_id, match_key, scope, origin, source_kind
  FROM quarantine_entries
 WHERE org_id = $1 AND lifted_at IS NULL
 ORDER BY cluster_id`, orgID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[uuid.UUID]bool{}
	for rows.Next() {
		var cid uuid.UUID
		var matchKey, scope, origin, sourceKind string
		if err := rows.Scan(&cid, &matchKey, &scope, &origin, &sourceKind); err != nil {
			t.Fatal(err)
		}
		if matchKey != repo || scope != "image" || origin != "auto" || sourceKind != "scan" {
			t.Fatalf("quarantine entry = match_key=%q scope=%q origin=%q source=%q", matchKey, scope, origin, sourceKind)
		}
		got[cid] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !got[clusterA] || !got[clusterB] || len(got) != 2 {
		t.Fatalf("quarantine clusters = %v, want both %s and %s", got, clusterA, clusterB)
	}
}

// Silence unused-import linter if test DB isn't reachable.
var _ = pgxpool.New

// TestResolveEvidenceImageName verifies a digest-only evidence scan identity gets its
// human repo:tag filled in from the workload map (and that an unmapped digest is left
// untouched rather than guessed).
func TestResolveEvidenceImageName(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no org in test db: %v", err)
	}
	clusterID := uuid.New()
	deploymentID := uuid.New()
	digest := "sha256:" + strings.Repeat("ab12", 16) // 64 hex
	repo := "registry.example.com/team/widget"
	ref := repo + ":v1.2.3"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM image_workload_links WHERE org_id=$1 AND image_digest=$2`, orgID, digest)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO image_workload_links (org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest)
VALUES ($1,$2,$3,'team/widget','team','widget','Deployment',$4,$4,$5,'v1.2.3',$6)`,
		orgID, clusterID, deploymentID, ref, repo, digest); err != nil {
		t.Fatalf("link insert: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	// digest-only identity (as the evidence path produces it)
	id := scanImageIdentity{Ref: digest, Digest: digest}
	resolveEvidenceImageName(ctx, tx, orgID, &id)
	if id.Repository != repo {
		t.Fatalf("repository not resolved: got %q want %q", id.Repository, repo)
	}
	if id.Tag != "v1.2.3" {
		t.Fatalf("tag not resolved: got %q", id.Tag)
	}
	if id.Ref != ref {
		t.Fatalf("ref not upgraded: got %q want %q", id.Ref, ref)
	}

	// unmapped digest → left as-is (no fabricated name)
	un := scanImageIdentity{Ref: "sha256:" + strings.Repeat("ffff", 16), Digest: "sha256:" + strings.Repeat("ffff", 16)}
	resolveEvidenceImageName(ctx, tx, orgID, &un)
	if un.Repository != "" {
		t.Fatalf("unmapped digest must stay nameless, got repository=%q", un.Repository)
	}

	// Deployment fallback: the runtime-agent's content digest differs from the registry
	// manifest digest, so the link is nameless (repository empty, ref=content digest) but
	// its deployment carries the named ref. Resolution must go through the workload.
	contentDigest := "sha256:" + strings.Repeat("cd34", 16)
	manifestRef := "registry.k8s.io/team/gadget:v2.0.0@sha256:" + strings.Repeat("beef", 16)
	dep2 := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM image_workload_links WHERE org_id=$1 AND image_ref=$2`, orgID, contentDigest)
		_, _ = pool.Exec(context.Background(), `DELETE FROM deployments WHERE id=$1`, dep2)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (id, org_id, cluster_id, namespace, name, kind, image_refs)
VALUES ($1,$2,$3,'team','gadget','Deployment',$4)`, dep2, orgID, clusterID, []string{manifestRef, "registry.k8s.io/team/gadget@sha256:" + strings.Repeat("beef", 16)}); err != nil {
		t.Fatalf("dep2 insert: %v", err)
	}
	// nameless link (no repository), image_ref is the content digest
	if _, err := pool.Exec(ctx, `
INSERT INTO image_workload_links (org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest)
VALUES ($1,$2,$3,'team/gadget','team','gadget','Deployment',$4,$4,'','',$4)`,
		orgID, clusterID, dep2, contentDigest); err != nil {
		t.Fatalf("nameless link insert: %v", err)
	}
	viaDep := scanImageIdentity{Ref: contentDigest, Digest: contentDigest}
	resolveEvidenceImageName(ctx, tx, orgID, &viaDep)
	if viaDep.Repository != "registry.k8s.io/team/gadget" {
		t.Fatalf("deployment fallback repository: got %q", viaDep.Repository)
	}
	if viaDep.Tag != "v2.0.0" {
		t.Fatalf("deployment fallback tag: got %q", viaDep.Tag)
	}
	// the scan-keying digest stays the CONTENT digest, not the manifest one
	if viaDep.Digest != contentDigest {
		t.Fatalf("evidence digest must be preserved, got %q", viaDep.Digest)
	}
}
