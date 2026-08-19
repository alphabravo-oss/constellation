package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestConnectorCoverage_OverviewWithoutStorageReturnsEmptyLiveState(t *testing.T) {
	w := httptest.NewRecorder()

	NewConnectorCoverage().Overview(w, httptest.NewRequest(http.MethodGet, "/api/v1/connector-coverage", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got connectorCoverageOverviewDTO
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.RegistryConnectorsTotal != 0 || got.Summary.CloudConnectorsTotal != 0 || got.Summary.ImagesObserved != 0 {
		t.Fatalf("no storage should not return sample connector data: %+v", got.Summary)
	}
	if len(got.RegistryConnectors) != 0 || len(got.CloudConnectors) != 0 || len(got.ScanCoverage) != 0 || len(got.ScannerPools) != 0 || len(got.RecentJobs) != 0 {
		t.Fatalf("no storage should return empty live panels: %+v", got)
	}
	if len(got.Guardrails) == 0 {
		t.Fatalf("guardrails should still describe connector API invariants: %+v", got)
	}
}

func TestConnectorCoverage_SaveConfigPersistsMetadataWithoutRawSecrets(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureConnectorConfigTable(t, pool)

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Connector Config Test')`, orgID, "connector-config-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Connector Admin')`, userID, orgID, "connector-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/connector-coverage/configs", bytes.NewBufferString(`{
		"connector_id":"test-registry",
		"connector_type":"registry",
		"provider":"ghcr",
		"display_name":"Test Registry",
		"endpoint":"registry.test/team",
		"auth_mode":"token",
		"owner":"secops",
		"scan_cadence":"hourly",
		"rotation_due_at":"2026-06-11T00:00:00Z",
		"credential_ref":"vault://kv/test-registry"
	}`))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewConnectorCoverage(d).SaveConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var saved struct {
		Config connectorConfigDTO `json:"config"`
	}
	if err := json.NewDecoder(w.Body).Decode(&saved); err != nil {
		t.Fatal(err)
	}
	if !saved.Config.CredentialPresent || saved.Config.CredentialFingerprint == "" || saved.Config.CredentialRef == "" {
		t.Fatalf("missing credential metadata: %+v", saved.Config)
	}

	testReq := requestWithConnectorConfigID(http.MethodPost, "/api/v1/connector-coverage/configs/"+saved.Config.ID+"/test", saved.Config.ID, nil)
	testReq = testReq.WithContext(authctx.WithSubject(testReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	testResp := httptest.NewRecorder()
	NewConnectorCoverage(d).TestSavedConfig(testResp, testReq)
	if testResp.Code != http.StatusOK {
		t.Fatalf("test saved config status=%d body=%s", testResp.Code, testResp.Body.String())
	}
	var tested connectorConfigTestDTO
	if err := json.NewDecoder(testResp.Body).Decode(&tested); err != nil {
		t.Fatal(err)
	}
	if tested.Status != "healthy" || tested.Config.LastTestStatus != "healthy" || tested.Config.LastTestAt == "" {
		t.Fatalf("missing saved test status: %+v", tested)
	}
	if tested.PersistsSecrets || tested.StartsScan || tested.RotatesCredential {
		t.Fatalf("saved config test must remain read-only: %+v", tested)
	}

	overviewReq := httptest.NewRequest(http.MethodGet, "/api/v1/connector-coverage", nil)
	overviewReq = overviewReq.WithContext(authctx.WithSubject(overviewReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	overviewResp := httptest.NewRecorder()
	NewConnectorCoverage(d).Overview(overviewResp, overviewReq)
	if overviewResp.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", overviewResp.Code, overviewResp.Body.String())
	}
	var overview connectorCoverageOverviewDTO
	if err := json.NewDecoder(overviewResp.Body).Decode(&overview); err != nil {
		t.Fatal(err)
	}
	if len(overview.Configs) != 1 || overview.Configs[0].ConnectorID != "test-registry" {
		t.Fatalf("missing saved config: %+v", overview.Configs)
	}
	if overview.Configs[0].LastTestStatus != "healthy" || overview.Configs[0].LastTestAt == "" {
		t.Fatalf("overview missing saved health: %+v", overview.Configs[0])
	}

	rejectReq := httptest.NewRequest(http.MethodPost, "/api/v1/connector-coverage/configs", bytes.NewBufferString(`{
		"connector_id":"test-registry",
		"connector_type":"registry",
		"display_name":"Test Registry",
		"endpoint":"registry.test/team",
		"auth_mode":"token",
		"owner":"secops",
		"secret":"raw-token"
	}`))
	rejectReq = rejectReq.WithContext(authctx.WithSubject(rejectReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rejectResp := httptest.NewRecorder()
	NewConnectorCoverage(d).SaveConfig(rejectResp, rejectReq)
	if rejectResp.Code != http.StatusBadRequest {
		t.Fatalf("expected raw secret rejection, got %d: %s", rejectResp.Code, rejectResp.Body.String())
	}
}

func TestConnectorCoverage_OverviewUsesDatabaseState(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureConnectorConfigTable(t, pool)
	var evidenceTable string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.scan_evidence')::text, '')`).Scan(&evidenceTable); err != nil || evidenceTable == "" {
		t.Skipf("skipping: scan_evidence migration not applied (%v)", err)
	}

	orgID := uuid.New()
	userID := uuid.New()
	registryID := uuid.New()
	scanTargetID := uuid.New()
	pendingScanTargetID := uuid.New()
	hostTargetID := uuid.New()
	imageAssetID := uuid.New()
	unscannedAssetID := uuid.New()
	cloudAssetID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Connector Coverage Test')`, orgID, "connector-coverage-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Connector Analyst')`, userID, orgID, "coverage-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO registries (
    id, org_id, name, kind, endpoint, auth_kind, auth_secret, scan_cadence,
    last_sync_at, last_sync_status, images_seen, created_by
) VALUES ($1,$2,'GHCR test','ghcr','ghcr.io/test','static',$3,'hourly',$4,'ok',2,$5)`,
		registryID, orgID, []byte{1, 2, 3}, now.Add(-30*time.Minute), userID); err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO registry_images (org_id, registry_id, repository, tags, last_seen_at)
VALUES ($1,$2,'ghcr.io/test/api',$3,$4)`,
		orgID, registryID, []string{"v1", "v2"}, now.Add(-20*time.Minute)); err != nil {
		t.Fatalf("registry image: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO connector_configs (
    org_id, connector_id, connector_type, provider, display_name, endpoint, auth_mode,
    owner, scan_cadence, rotation_due_at, credential_ref, credential_fingerprint, credential_present,
    last_test_status, last_test_at, created_by, updated_by
) VALUES
($1,$2,'registry','ghcr','GHCR test','ghcr.io/test','static','secops','hourly',$3,'vault://kv/ghcr-test','fp',true,'healthy',$4,$5,$5),
($1,'aws-test','cloud','aws','AWS test','acct-test','cross-account role','cloudsec','daily',$3,'vault://kv/cloud-test','fp2',true,'healthy',$4,$5,$5)`,
		orgID, registryID.String(), now.Add(7*24*time.Hour), now.Add(-10*time.Minute), userID); err != nil {
		t.Fatalf("connector configs: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (id, org_id, type, ref, source_type, source_ref, image_ref, registry_id, platform)
VALUES
($1,$3,'image','ghcr.io/test/api:v1','registry',$4,'ghcr.io/test/api:v1',$5,'linux/amd64'),
($2,$3,'image','ghcr.io/test/api:v2','registry',$4,'ghcr.io/test/api:v2',$5,'linux/amd64')`,
		scanTargetID, pendingScanTargetID, orgID, registryID.String(), registryID); err != nil {
		t.Fatalf("scan targets: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (id, org_id, type, ref, source_type, source_ref, inventory_hash)
VALUES ($1,$2,'host','node-a','host','node-a','sha256:host-fixture')`,
		hostTargetID, orgID); err != nil {
		t.Fatalf("host scan target: %v", err)
	}
	if _, err := pool.Exec(ctx, `
	INSERT INTO scan_jobs (org_id, target_id, status, requested_by, finding_count, requested_at, claimed_at, lease_expires_at, finished_at)
	VALUES
	($1,$2,'completed',$4,2,$5,$6,NULL,$7),
	($1,$3,'pending',$4,0,$8,NULL,NULL,NULL),
	($1,$9,'completed',$4,1,$5,$6,NULL,$7),
	($1,$3,'running',$4,0,$10,$11,$12,NULL)`,
		orgID, scanTargetID, pendingScanTargetID, userID, now.Add(-8*time.Minute), now.Add(-7*time.Minute), now.Add(-5*time.Minute), now.Add(-2*time.Minute), hostTargetID, now.Add(-20*time.Minute), now.Add(-19*time.Minute), now.Add(-10*time.Minute)); err != nil {
		t.Fatalf("scan jobs: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_packages (org_id, node, package_count, source, distro, payload, observed_at)
VALUES ($1,'node-a',1,'dpkg','ubuntu',$2::jsonb,$3)`,
		orgID, `{"items":[{"name":"openssl","version":"3.0.13-0ubuntu3.5"}]}`, now.Add(-4*time.Minute)); err != nil {
		t.Fatalf("host packages: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_evidence (
    org_id, scan_target_id, target_type, target_ref, source_type, source_ref,
    evidence_type, inventory_hash, package_count, payload, observed_at
) VALUES ($1,$2,'host','node-a','host','node-a','package-inventory','sha256:host-fixture',1,$3::jsonb,$4)`,
		orgID, hostTargetID, `{"packages":[{"ecosystem":"deb","name":"openssl","version":"3.0.13-0ubuntu3.5","namespace_kind":"os","namespace_name":"ubuntu","namespace_version":"24.04"}]}`, now.Add(-4*time.Minute)); err != nil {
		t.Fatalf("host evidence: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, criticality, last_seen_at)
VALUES
($1,$2,'image','ghcr.io/test/api:v1','sha256:111','medium',$5),
($3,$2,'image','ghcr.io/test/api:v2','sha256:222','critical',$5),
($4,$2,'cloud-resource','arn:aws:s3:::example-public',NULL,'high',$5)`,
		imageAssetID, orgID, unscannedAssetID, cloudAssetID, now.Add(-3*time.Minute)); err != nil {
		t.Fatalf("assets: %v", err)
	}
	// The deployed-images coverage query counts an image asset as "scanned"
	// when a matching image_scan_results row exists for the asset/digest. The
	// v1 image is the one whose scan_target/job above completed, so record its
	// canonical scan result here. Without this fixture the deployed-images
	// "Scanned" count is non-deterministic against the shared test DB (the
	// query is org-scoped, so it depends solely on rows this test creates).
	// v2 (critical) intentionally has no result → it remains the critical gap.
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
    org_id, scan_target_id, asset_id, image_ref, image_ref_normalized,
    image_repository, image_tag, image_digest, package_count, finding_count,
    first_seen_at, last_scanned_at, updated_at
) VALUES ($1,$2,$3,'ghcr.io/test/api:v1','ghcr.io/test/api:v1','ghcr.io/test/api','v1','sha256:111',1,2,$4,$4,$4)`,
		orgID, scanTargetID, imageAssetID, now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("image scan result: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, asset_id, kind, external_id, title, severity, risk_score, lifecycle, first_seen_at, last_seen_at)
VALUES ($1,$2,'cloud-config','AWS-S3-PUBLIC','Public S3 bucket','high',90,'open',$3,$3)`,
		orgID, cloudAssetID, now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("cloud finding: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats (org_id, component, version, hostname, uptime_seconds, metadata, last_seen_at)
VALUES ($1,'scanner','test-version','scanner-0',120,$2::jsonb,$3)`,
		orgID, `{"instance_id":"scanner-test-0","max_concurrent":4,"active_jobs":2,"idle_capacity":2,"target_capacity":{"image":2,"host":4},"active_jobs_by_target_type":{"image":1,"host":1},"cache_health":{"syft":{"configured":true,"present":true,"writable":true,"status":"ready","record_count":1,"record_size_bytes":128}},"vulndb":{"enabled":true,"ready":true,"status":"ready","bundle_version":"fixture-2026"}}`, now); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/connector-coverage", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewConnectorCoverage(d).Overview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got connectorCoverageOverviewDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.RegistryConnectorsTotal != 1 || got.Summary.RegistryConnectorsReady != 1 {
		t.Fatalf("registry summary = %+v", got.Summary)
	}
	if got.Summary.ImagesObserved != 2 || got.Summary.ImagesScanned != 1 || got.Summary.ImagesUnscanned != 1 || got.Summary.QueuedScans != 1 {
		t.Fatalf("image/queue summary = %+v", got.Summary)
	}
	if got.Summary.CloudConnectorsTotal != 1 || got.Summary.CloudConnectorsReady != 1 || got.Summary.CloudResourcesObserved != 1 || got.Summary.CloudResourcesAssessed != 1 {
		t.Fatalf("cloud summary = %+v", got.Summary)
	}
	if len(got.RegistryConnectors) != 1 || got.RegistryConnectors[0].ID != registryID.String() || got.RegistryConnectors[0].Status != "ready" {
		t.Fatalf("registry connectors = %+v", got.RegistryConnectors)
	}
	if got.RegistryConnectors[0].LastScanAt == "" || got.RegistryConnectors[0].NextScanAt == "" || got.RegistryConnectors[0].RotationDueAt == "" {
		t.Fatalf("registry connector missing timestamps/rotation: %+v", got.RegistryConnectors[0])
	}
	if len(got.CloudConnectors) != 1 || got.CloudConnectors[0].Status != "ready" || got.CloudConnectors[0].FindingsOpen != 1 {
		t.Fatalf("cloud connectors = %+v", got.CloudConnectors)
	}
	if len(got.ScannerPools) != 1 || got.ScannerPools[0].ReadyWorkers != 1 || got.ScannerPools[0].QueueDepth != 1 || got.ScannerPools[0].StaleLeases != 1 || got.ScannerPools[0].Status != "degraded" {
		t.Fatalf("scanner pools = %+v", got.ScannerPools)
	}
	if got.ScannerPools[0].ActiveJobs != 2 || got.ScannerPools[0].IdleCapacity != 2 || len(got.ScannerPools[0].Scanners) != 1 {
		t.Fatalf("scanner capacity metadata = %+v", got.ScannerPools[0])
	}
	if got.ScannerPools[0].Scanners[0].VulnDBStatus != "ready" || got.ScannerPools[0].Scanners[0].VulnDBBundleVersion != "fixture-2026" || got.ScannerPools[0].Scanners[0].TargetCapacity["host"] != 4 {
		t.Fatalf("scanner worker metadata = %+v", got.ScannerPools[0].Scanners[0])
	}
	if got.ScannerPools[0].Scanners[0].InstanceID != "scanner-test-0" {
		t.Fatalf("scanner instance id = %+v", got.ScannerPools[0].Scanners[0])
	}
	if cache := handler.MetadataMap(got.ScannerPools[0].Scanners[0].CacheHealth, "syft"); !handler.MetadataBool(cache, "writable") || handler.MetadataInt(cache, "record_count") != 1 || handler.MetadataInt(cache, "record_size_bytes") != 128 {
		t.Fatalf("scanner cache metadata = %+v", got.ScannerPools[0].Scanners[0].CacheHealth)
	}
	if len(got.RecentJobs) != 4 || got.RecentJobs[0].ID == "not-a-real-job-id" {
		t.Fatalf("recent jobs should come from scan_jobs: %+v", got.RecentJobs)
	}
	coverageByScope := map[string]scanCoverageDTO{}
	for _, item := range got.ScanCoverage {
		coverageByScope[item.Scope] = item
	}
	if coverageByScope["Deployed images"].Observed != 2 || coverageByScope["Deployed images"].Scanned != 1 || coverageByScope["Deployed images"].CriticalGaps != 1 {
		t.Fatalf("deployed coverage = %+v", coverageByScope["Deployed images"])
	}
	// The "CI submitted images" scope counts every scan_jobs row for the org
	// (observed) and those in 'completed' state (scanned). This test now seeds
	// four scan jobs for the fixture org — image v1 (completed), image v2
	// (pending), image v2 (running/stale lease) and the node-a host job
	// (completed) — all of which the recent-jobs, queue-depth and stale-lease
	// assertions above depend on. The expected counts here therefore reflect
	// those four jobs (4 observed / 2 completed); the values are derived from
	// the same fixtures the test inserts, so they stay deterministic against
	// the shared DB (the query is strictly org-scoped to this fresh org).
	if coverageByScope["CI submitted images"].Observed != 4 || coverageByScope["CI submitted images"].Scanned != 2 {
		t.Fatalf("CI coverage = %+v", coverageByScope["CI submitted images"])
	}
	if coverageByScope["Host package evidence"].Observed != 1 || coverageByScope["Host package evidence"].Scanned != 1 || coverageByScope["Host package evidence"].CriticalGaps != 0 {
		t.Fatalf("host evidence coverage = %+v", coverageByScope["Host package evidence"])
	}

	testReq := httptest.NewRequest(http.MethodPost, "/api/v1/connector-coverage/test?id="+registryID.String()+"&type=registry", nil)
	testReq = testReq.WithContext(authctx.WithSubject(testReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	testResp := httptest.NewRecorder()
	NewConnectorCoverage(d).Test(testResp, testReq)
	if testResp.Code != http.StatusOK {
		t.Fatalf("preview existing registry status=%d body=%s", testResp.Code, testResp.Body.String())
	}

	missingReq := httptest.NewRequest(http.MethodPost, "/api/v1/connector-coverage/test?id=test-registry&type=registry", nil)
	missingReq = missingReq.WithContext(authctx.WithSubject(missingReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	missingResp := httptest.NewRecorder()
	NewConnectorCoverage(d).Test(missingResp, missingReq)
	if missingResp.Code != http.StatusNotFound {
		t.Fatalf("expected missing registry 404, got %d: %s", missingResp.Code, missingResp.Body.String())
	}
}

func TestConnectorCoverage_TestSavedConfigRequiresStorage(t *testing.T) {
	id := uuid.New().String()
	req := requestWithConnectorConfigID(http.MethodPost, "/api/v1/connector-coverage/configs/"+id+"/test", id, nil)
	w := httptest.NewRecorder()

	NewConnectorCoverage().TestSavedConfig(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected storage unavailable, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConnectorCoverage_TestSavedConfigPersistsUnhealthyWithoutCredentialRefAndRejectsRawSecret(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureConnectorConfigTable(t, pool)

	orgID := uuid.New()
	userID := uuid.New()
	configID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Connector Health Test')`, orgID, "connector-health-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Connector Admin')`, userID, orgID, "connector-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO connector_configs (
    id, org_id, connector_id, connector_type, provider, display_name, endpoint, auth_mode,
    owner, scan_cadence, credential_present, created_by, updated_by
) VALUES ($1,$2,'artifact-registry-ml','registry','artifact-registry','Google Artifact Registry ML','us-docker.pkg.dev/ml-prod/images','workload identity','ml-secops','daily',false,$3,$3)`,
		configID, orgID, userID); err != nil {
		t.Fatalf("config: %v", err)
	}

	rawSecretReq := requestWithConnectorConfigID(http.MethodPost, "/api/v1/connector-coverage/configs/"+configID.String()+"/test", configID.String(), bytes.NewBufferString(`{"secret":"raw-token"}`))
	rawSecretReq = rawSecretReq.WithContext(authctx.WithSubject(rawSecretReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rawSecretResp := httptest.NewRecorder()
	NewConnectorCoverage(d).TestSavedConfig(rawSecretResp, rawSecretReq)
	if rawSecretResp.Code != http.StatusBadRequest {
		t.Fatalf("expected raw secret rejection, got %d: %s", rawSecretResp.Code, rawSecretResp.Body.String())
	}

	req := requestWithConnectorConfigID(http.MethodPost, "/api/v1/connector-coverage/configs/"+configID.String()+"/test", configID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	resp := httptest.NewRecorder()
	NewConnectorCoverage(d).TestSavedConfig(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var tested connectorConfigTestDTO
	if err := json.NewDecoder(resp.Body).Decode(&tested); err != nil {
		t.Fatal(err)
	}
	if tested.Status != "unhealthy" || tested.Config.LastTestStatus != "unhealthy" || tested.Config.LastTestAt == "" {
		t.Fatalf("expected unhealthy persisted diagnostic: %+v", tested)
	}
	if tested.Config.CredentialRef != "" || tested.Config.CredentialPresent {
		t.Fatalf("test should not create credential metadata: %+v", tested.Config)
	}

	var lastTestAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_test_at FROM connector_configs WHERE id = $1`, configID).Scan(&lastTestAt); err != nil {
		t.Fatalf("last_test_at: %v", err)
	}
	if lastTestAt == nil {
		t.Fatal("expected persisted last_test_at")
	}
}

func TestConnectorCoverage_TestSavedConfigIsOrgScoped(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureConnectorConfigTable(t, pool)

	orgA := uuid.New()
	orgB := uuid.New()
	userA := uuid.New()
	userB := uuid.New()
	configID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Org A'), ($3, $4, 'Org B')`, orgA, "connector-org-a-"+orgA.String(), orgB, "connector-org-b-"+orgB.String()); err != nil {
		t.Fatalf("orgs: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Admin A'), ($4, $5, $6, 'Admin B')`, userA, orgA, "a-"+userA.String()+"@example.com", userB, orgB, "b-"+userB.String()+"@example.com"); err != nil {
		t.Fatalf("users: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = ANY($1)`, []uuid.UUID{orgA, orgB})
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO connector_configs (
    id, org_id, connector_id, connector_type, provider, display_name, endpoint, auth_mode,
    owner, scan_cadence, credential_ref, credential_fingerprint, credential_present, created_by, updated_by
) VALUES ($1,$2,'test-registry','registry','ghcr','Test Registry','registry.test/team','token','secops','hourly','vault://kv/test-registry','fingerprint',true,$3,$3)`,
		configID, orgA, userA); err != nil {
		t.Fatalf("config: %v", err)
	}

	req := requestWithConnectorConfigID(http.MethodPost, "/api/v1/connector-coverage/configs/"+configID.String()+"/test", configID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userB, OrgID: orgB}))
	resp := httptest.NewRecorder()
	NewConnectorCoverage(d).TestSavedConfig(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected org-scoped 404, got %d: %s", resp.Code, resp.Body.String())
	}

	var status string
	var lastTestAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_test_status, last_test_at FROM connector_configs WHERE id = $1`, configID).Scan(&status, &lastTestAt); err != nil {
		t.Fatalf("row: %v", err)
	}
	if status != "not_tested" || lastTestAt != nil {
		t.Fatalf("other org should not update config, status=%s last_test_at=%v", status, lastTestAt)
	}
}

func requestWithConnectorConfigID(method, target, id string, body *bytes.Buffer) *http.Request {
	var requestBody *bytes.Buffer
	if body == nil {
		requestBody = bytes.NewBuffer(nil)
	} else {
		requestBody = body
	}
	req := httptest.NewRequest(method, target, requestBody)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))
}

func ensureConnectorConfigTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
CREATE TABLE IF NOT EXISTS connector_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    connector_id TEXT NOT NULL,
    connector_type TEXT NOT NULL CHECK (connector_type IN ('registry', 'cloud')),
    provider TEXT NOT NULL,
    display_name TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    auth_mode TEXT NOT NULL,
    owner TEXT NOT NULL,
    scan_cadence TEXT NOT NULL DEFAULT 'daily',
    rotation_due_at TIMESTAMPTZ,
    credential_ref TEXT,
    credential_fingerprint TEXT,
    credential_present BOOLEAN NOT NULL DEFAULT FALSE,
    last_test_status TEXT NOT NULL DEFAULT 'not_tested',
    last_test_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, connector_type, connector_id)
)`)
	if err != nil {
		t.Fatalf("connector config table: %v", err)
	}
}

func TestConnectorCoverage_TestIsReadOnly(t *testing.T) {
	w := httptest.NewRecorder()

	NewConnectorCoverage().Test(w, httptest.NewRequest(http.MethodPost, "/api/v1/connector-coverage/test?id=test-registry&type=registry", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got connectorCheckPreviewDTO
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.PersistsSecrets || got.StartsScan || got.RotatesCredential {
		t.Fatalf("test preview must be read-only: %+v", got)
	}
	if got.ConnectorID != "test-registry" || len(got.Guardrails) == 0 {
		t.Fatalf("bad preview: %+v", got)
	}
}
