package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPlatformFactsReportQueuesEvidenceBackedScan(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"cluster_platform_facts", "scan_evidence", "scan_targets"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name)
VALUES ($1, $2, 'Platform Facts Test')`, orgID, "platform-facts-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash)
VALUES ($1, $2, $3, 'Test User', 'x')`, userID, orgID, "platform-facts@example.test"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state)
VALUES ($1, $2, 'local-k3s', 'kubernetes', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	runtimeToken, _, err := IssueRuntimeAgentToken(ctx, pool, orgID, "platform-facts-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(PlatformFactsReport{
		ClusterID:            clusterID,
		ClusterName:          "local-k3s",
		ObservedAt:           time.Now().UTC(),
		Distro:               "k3s",
		KubernetesGitVersion: "v1.30.1+k3s1",
		KubernetesMajor:      "1",
		KubernetesMinor:      "30",
		PlatformProvider:     "onprem",
		NodeCount:            1,
		KubeletVersions:      map[string]int{"v1.30.1+k3s1": 1},
		Components: []PlatformComponent{{
			Name:      "coredns",
			Version:   "1.11.1",
			Type:      "deployment",
			Source:    "kube-system/coredns",
			Namespace: "kubernetes",
		}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/platform-facts:report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+runtimeToken)
	rec := httptest.NewRecorder()
	AnyServiceTokenMiddleware(pool)(http.HandlerFunc(NewPlatformFacts(d).Report)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("report status: %d body: %s", rec.Code, rec.Body.String())
	}
	var report struct {
		ScanTargetID    uuid.UUID `json:"scan_target_id"`
		ScanEvidenceID  uuid.UUID `json:"scan_evidence_id"`
		InventoryHash   string    `json:"inventory_hash"`
		PackageCount    int       `json:"package_count"`
		ScanJobEnqueued bool      `json:"scan_job_enqueued"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.ScanTargetID == uuid.Nil || report.ScanEvidenceID == uuid.Nil || report.InventoryHash == "" {
		t.Fatalf("report ids = %+v", report)
	}
	if !report.ScanJobEnqueued || report.PackageCount != 4 {
		t.Fatalf("report queue/package count = %+v", report)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+clusterID.String()+"/platform-facts", nil)
	getReq = getReq.WithContext(WithSubject(getReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	getReq = withRouteParam(getReq, "id", clusterID.String())
	getRec := httptest.NewRecorder()
	NewPlatformFacts(d).Get(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status: %d body: %s", getRec.Code, getRec.Body.String())
	}
	var view PlatformFactsResponse
	if err := json.NewDecoder(getRec.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.Facts == nil || view.Facts.KubernetesGitVersion != "v1.30.1+k3s1" {
		t.Fatalf("facts = %+v", view.Facts)
	}
	if view.Evidence == nil || view.Evidence.ID != report.ScanEvidenceID || view.Evidence.PackageCount != report.PackageCount {
		t.Fatalf("evidence = %+v report = %+v", view.Evidence, report)
	}
	wantPackages := map[string]string{
		"kubernetes|kubernetes|v1.30.1+k3s1": "",
		"k3s|k3s|v1.30.1+k3s1":               "",
		"kubernetes|kubelet|v1.30.1+k3s1":    "",
		"kubernetes|coredns|1.11.1":          "",
	}
	for _, pkg := range view.Evidence.Packages {
		key := pkg.NamespaceName + "|" + pkg.Name + "|" + pkg.Version
		if _, ok := wantPackages[key]; !ok {
			t.Fatalf("unexpected platform package %q: %+v", key, view.Evidence.Packages)
		}
		if pkg.NamespaceKind != "generic" || pkg.Ecosystem != "generic" || pkg.Purl != "pkg:generic/"+pkg.Name {
			t.Fatalf("platform package metadata = %+v", pkg)
		}
		delete(wantPackages, key)
	}
	if len(wantPackages) != 0 {
		t.Fatalf("missing platform packages: %+v in %+v", wantPackages, view.Evidence.Packages)
	}
	if view.LatestJob == nil || view.LatestJob.Status != "pending" {
		t.Fatalf("job = %+v", view.LatestJob)
	}

	// The scan-job claim flow itself lives in the handler/scanning sub-package;
	// to avoid an import cycle this asserts the equivalent invariant directly:
	// the platform-facts report enqueued a pending scan job for the platform
	// target, linked to the latest package evidence and inventory hash.
	var (
		claimTargetType    string
		claimTargetRef     string
		claimTargetID      uuid.UUID
		claimInventoryHash string
	)
	if err := pool.QueryRow(ctx, `
SELECT st.type, st.ref, st.id, COALESCE(st.inventory_hash, '')
  FROM scan_jobs sj
  JOIN scan_targets st ON st.id = sj.target_id
 WHERE sj.org_id = $1
   AND sj.target_id = $2
   AND sj.status = 'pending'
 ORDER BY sj.requested_at DESC
 LIMIT 1`, orgID, report.ScanTargetID).Scan(&claimTargetType, &claimTargetRef, &claimTargetID, &claimInventoryHash); err != nil {
		t.Fatalf("pending scan job lookup: %v", err)
	}
	if claimTargetType != "platform" || claimTargetRef != platformTargetRef(clusterID) || claimTargetID != report.ScanTargetID {
		t.Fatalf("claim target = type %q ref %q id %s", claimTargetType, claimTargetRef, claimTargetID)
	}
	if claimInventoryHash != report.InventoryHash {
		t.Fatalf("claim inventory hash = %q report = %q", claimInventoryHash, report.InventoryHash)
	}
	var latestEvidenceID uuid.UUID
	if err := pool.QueryRow(ctx, `
SELECT id
  FROM scan_evidence
 WHERE org_id = $1
   AND scan_target_id = $2
   AND evidence_type = $3
 ORDER BY observed_at DESC
 LIMIT 1`, orgID, report.ScanTargetID, PackageInventoryEvidence).Scan(&latestEvidenceID); err != nil {
		t.Fatalf("latest evidence lookup: %v", err)
	}
	if latestEvidenceID != report.ScanEvidenceID {
		t.Fatalf("latest evidence = %s report = %s", latestEvidenceID, report.ScanEvidenceID)
	}
}
