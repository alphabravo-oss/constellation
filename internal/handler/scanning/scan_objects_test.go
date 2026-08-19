package scanning

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestScanObjects_TriggerQueuesEvidenceBackedTargets(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	ensureScanObjectTables(t, ctx, pool)

	orgID, userID, clusterID := createScanObjectOrg(t, ctx, pool, "trigger")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	hostRef := "node-" + uuid.NewString()
	workloadRef := "payments/pod/api-" + uuid.NewString()
	platformRef := handler.PlatformTargetRef(clusterID)
	hostTargetID, hostEvidenceID := insertScanObjectTarget(t, ctx, pool, orgID, clusterID, "host", hostRef, "host", `{"distro":"ubuntu","base_os":"ubuntu:24.04"}`)
	workloadTargetID, _ := insertScanObjectTarget(t, ctx, pool, orgID, clusterID, "workload", workloadRef, "runtime-agent", `{"base_os":"ubuntu:24.04"}`)
	platformTargetID, _ := insertScanObjectTarget(t, ctx, pool, orgID, clusterID, "platform", platformRef, "platform", `{"distro":"k3s","kubernetes_git_version":"v1.30.1+k3s1"}`)

	h := NewScanJobs(d, nil)
	subj := authctx.Subject{UserID: userID, OrgID: orgID}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/host/"+hostRef+"?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), subj))
	req = withRouteParam(req, "id", hostRef)
	rec := httptest.NewRecorder()
	h.TriggerHost(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("host trigger status: %d body: %s", rec.Code, rec.Body.String())
	}
	var hostOut scanObjectTriggerDTO
	if err := json.NewDecoder(rec.Body).Decode(&hostOut); err != nil {
		t.Fatal(err)
	}
	if hostOut.TargetID != hostTargetID || hostOut.ScanEvidenceID != hostEvidenceID || !hostOut.ScanJobEnqueued || hostOut.JobID == nil {
		t.Fatalf("host trigger = %+v target=%s evidence=%s", hostOut, hostTargetID, hostEvidenceID)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/scan/host/"+hostRef+"?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), subj))
	req = withRouteParam(req, "id", hostRef)
	rec = httptest.NewRecorder()
	h.TriggerHost(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("host retrigger status: %d body: %s", rec.Code, rec.Body.String())
	}
	var hostAgain scanObjectTriggerDTO
	if err := json.NewDecoder(rec.Body).Decode(&hostAgain); err != nil {
		t.Fatal(err)
	}
	if hostAgain.ScanJobEnqueued || hostAgain.JobID != nil {
		t.Fatalf("host retrigger should be idempotent: %+v", hostAgain)
	}
	var pending int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int FROM scan_jobs WHERE org_id = $1 AND target_id = $2 AND status = 'pending'`, orgID, hostTargetID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending host jobs = %d, want 1", pending)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/scan/workload/"+workloadRef+"?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), subj))
	req = withRouteParam(req, "id", workloadRef)
	rec = httptest.NewRecorder()
	h.TriggerWorkload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("workload trigger status: %d body: %s", rec.Code, rec.Body.String())
	}
	var workloadOut scanObjectTriggerDTO
	if err := json.NewDecoder(rec.Body).Decode(&workloadOut); err != nil {
		t.Fatal(err)
	}
	if workloadOut.TargetID != workloadTargetID || !workloadOut.ScanJobEnqueued {
		t.Fatalf("workload trigger = %+v target=%s", workloadOut, workloadTargetID)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/scan/platform/platform", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), subj))
	rec = httptest.NewRecorder()
	h.TriggerPlatform(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("platform trigger status: %d body: %s", rec.Code, rec.Body.String())
	}
	var platformOut scanObjectTriggerDTO
	if err := json.NewDecoder(rec.Body).Decode(&platformOut); err != nil {
		t.Fatal(err)
	}
	if platformOut.TargetID != platformTargetID || !platformOut.ScanJobEnqueued {
		t.Fatalf("platform trigger = %+v target=%s", platformOut, platformTargetID)
	}
}

func TestScanObjects_ReportAndPlatformSummary(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	ensureScanObjectTables(t, ctx, pool)

	orgID, userID, clusterID := createScanObjectOrg(t, ctx, pool, "report")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	hostRef := "node-" + uuid.NewString()
	targetID, _ := insertScanObjectTarget(t, ctx, pool, orgID, clusterID, "host", hostRef, "host", `{"base_os":"ubuntu:24.04"}`)
	assetID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, cluster_id, kind, name, labels, criticality)
VALUES ($1, $2, $3, 'host', $4, '{}'::jsonb, 'medium')`, assetID, orgID, clusterID, hostRef); err != nil {
		t.Fatal(err)
	}
	jobID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (
    id, org_id, target_id, status, requested_by, package_count, finding_count,
    bundle_metadata, requested_at, claimed_at, finished_at
) VALUES (
    $1, $2, $3, 'completed', $4, 1, 1,
    '{"bundle_version":"vulndb-test-1","exported_at":"2026-06-14T00:00:00Z"}'::jsonb,
    $5, $5, $5
)`, jobID, orgID, targetID, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (
    org_id, cluster_id, asset_id, kind, external_id, title, description,
    severity, risk_score, lifecycle, canonical_engine, detail_json,
    scan_target_id, target_type, target_ref, target_cluster_id, source_type,
    first_seen_at, last_seen_at
) VALUES (
    $1, $2, $3, 'vulnerability', 'CVE-2099-1000', 'openssl vuln', 'test vuln',
    'critical', 97, 'open', 'constellation-vulndb',
    '{"package":{"name":"openssl","version":"3.0.13"},"fixed":"3.0.14","cvss_base":"9.8","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","references":["https://example.test/CVE-2099-1000"]}'::jsonb,
    $4, 'host', $5, $2, 'host', $6, $6
)`, orgID, clusterID, assetID, targetID, hostRef, now); err != nil {
		t.Fatal(err)
	}

	h := NewScanJobs(d, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/host/"+hostRef+"?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	req = withRouteParam(req, "id", hostRef)
	rec := httptest.NewRecorder()
	h.HostReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("host report status: %d body: %s", rec.Code, rec.Body.String())
	}
	var report scanObjectReportDTO
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.ScanSummary.Status != "finished" || report.ScanSummary.CriticalVuls != 1 || report.ScanSummary.CVEDBVersion != "vulndb-test-1" {
		t.Fatalf("scan summary = %+v", report.ScanSummary)
	}
	if len(report.Report.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %+v", report.Report.Vulnerabilities)
	}
	vuln := report.Report.Vulnerabilities[0]
	if vuln.Name != "CVE-2099-1000" || vuln.PackageName != "openssl" || vuln.FixedVersion != "3.0.14" || vuln.ScoreV3 != 9.8 {
		t.Fatalf("vulnerability = %+v", vuln)
	}

	missingRef := "payments/pod/missing-" + uuid.NewString()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/scan/workload/"+missingRef, nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	req = withRouteParam(req, "id", missingRef)
	rec = httptest.NewRecorder()
	h.WorkloadReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("missing workload report status: %d body: %s", rec.Code, rec.Body.String())
	}
	var missing scanObjectReportDTO
	if err := json.NewDecoder(rec.Body).Decode(&missing); err != nil {
		t.Fatal(err)
	}
	if missing.ScanSummary.Status != "" || len(missing.Report.Vulnerabilities) != 0 {
		t.Fatalf("missing workload report = %+v", missing)
	}

	platformRef := handler.PlatformTargetRef(clusterID)
	platformTargetID, _ := insertScanObjectTarget(t, ctx, pool, orgID, clusterID, "platform", platformRef, "platform", `{"distro":"k3s","kubernetes_git_version":"v1.30.1+k3s1"}`)
	if _, err := pool.Exec(ctx, `
INSERT INTO cluster_platform_facts (
    org_id, cluster_id, distro, kubernetes_git_version, kubernetes_major, kubernetes_minor,
    platform_provider, platform_version, node_count, kubelet_versions, payload, observed_at
) VALUES (
    $1, $2, 'k3s', 'v1.30.1+k3s1', '1', '30',
    'onprem', 'v1.30.1+k3s1', 1, '{"v1.30.1+k3s1":1}'::jsonb, '{}'::jsonb, $3
)`, orgID, clusterID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status, package_count, finding_count, finished_at)
VALUES ($1, $2, $3, 'completed', 4, 0, $4)`, uuid.New(), orgID, platformTargetID, now); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/scan/platform", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec = httptest.NewRecorder()
	h.PlatformSummary(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("platform summary status: %d body: %s", rec.Code, rec.Body.String())
	}
	var summary scanObjectPlatformSummaryDTO
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Platforms) != 1 || summary.Platforms[0].K8sVersion != "v1.30.1+k3s1" || summary.Platforms[0].Status != "finished" {
		t.Fatalf("platform summary = %+v", summary)
	}
}

func ensureScanObjectTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, table := range []string{"scan_targets", "scan_evidence", "cluster_platform_facts"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}
}

func createScanObjectOrg(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name)
VALUES ($1, $2, $3)`, orgID, "scan-object-"+suffix+"-"+orgID.String(), "Scan Object "+suffix); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash)
VALUES ($1, $2, $3, 'Test User', 'x')`, userID, orgID, "scan-object-"+suffix+"@example.test"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state, last_heartbeat_at)
VALUES ($1, $2, $3, 'k3s', 'connected', NOW())`, clusterID, orgID, "scan-object-"+suffix+"-"+clusterID.String()); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	return orgID, userID, clusterID
}

func insertScanObjectTarget(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, clusterID uuid.UUID, targetType, targetRef, sourceType, metadata string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	targetID := uuid.New()
	evidenceID := uuid.New()
	inventoryHash := "sha256:" + uuid.NewString()
	if err := pool.QueryRow(ctx, `
INSERT INTO scan_targets (
    id, org_id, cluster_id, type, ref, source_type, source_ref, inventory_hash, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $5, $7, $8::jsonb
) RETURNING id`, targetID, orgID, clusterID, targetType, targetRef, sourceType, inventoryHash, metadata).Scan(&targetID); err != nil {
		t.Fatalf("scan target: %v", err)
	}
	if err := pool.QueryRow(ctx, `
INSERT INTO scan_evidence (
    id, org_id, scan_target_id, cluster_id, target_type, target_ref,
    source_type, source_ref, evidence_type, inventory_hash, package_count, payload, observed_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $6, 'package-inventory', $8, 1,
    '{"packages":[{"name":"openssl","version":"3.0.13","ecosystem":"deb","namespace_kind":"os","namespace_name":"ubuntu"}]}'::jsonb,
    NOW()
) RETURNING id`, evidenceID, orgID, targetID, clusterID, targetType, targetRef, sourceType, inventoryHash).Scan(&evidenceID); err != nil {
		t.Fatalf("scan evidence: %v", err)
	}
	return targetID, evidenceID
}
