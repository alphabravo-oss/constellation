package scanning

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/alphabravocompany/constellation/internal/handler"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestScannerPackagesFromWorkloadPackagesAddsImageHints(t *testing.T) {
	got := scannerPackagesFromWorkloadPackages(WorkloadPackagesPayload{
		WorkloadID: "payments/pod/api",
		Containers: []WorkloadPackageContainer{{
			ContainerName: "api",
			Image:         "example.test/api:dev",
			ImageRef:      "example.test/api@sha256:aaaaaaaa",
			Distro:        "ubuntu",
			DistroVersion: "24.04",
			Source:        "dpkg",
			Items: []handler.HostPackageItem{{
				Name:    "openssl",
				Version: "3.0.13-0ubuntu3.5",
				Arch:    "amd64",
			}},
		}},
	})
	if len(got) != 1 {
		t.Fatalf("packages = %d, want 1", len(got))
	}
	pkg := got[0]
	if pkg.Ecosystem != "deb" || pkg.NamespaceName != "ubuntu" || pkg.NamespaceVersion != "24.04" {
		t.Fatalf("package namespace = %+v", pkg)
	}
	if pkg.BaseImage != "example.test/api@sha256:aaaaaaaa" {
		t.Fatalf("base image = %q", pkg.BaseImage)
	}
}

func TestWorkloadPackagesReportQueuesScanEvidence(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := httptest.NewRequest("GET", "/", nil).Context()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.scan_evidence')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: scan_evidence migration not applied (%v)", err)
	}

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	clusterID := uuid.New()
	clusterName := "workload-evidence-" + clusterID.String()
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state)
VALUES ($1, $2, $3, 'k3s', 'connected')`, clusterID, orgID, clusterName); err != nil {
		t.Fatal(err)
	}

	workloadID := "payments/pod/api-" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	_, _ = pool.Exec(ctx, `DELETE FROM scan_targets WHERE org_id = $1 AND type = 'workload' AND ref = $2`, orgID, workloadID)
	clearScanQueue(t, pool, orgID)
	_, _ = pool.Exec(ctx, `DELETE FROM runtime_agent_tokens WHERE name = 'workload-evidence-test'`)
	_, _ = pool.Exec(ctx, `DELETE FROM scanner_tokens WHERE name = 'workload-evidence-test'`)

	runtimeToken, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, "workload-evidence-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(WorkloadPackagesPayload{
		ClusterID:  &clusterID,
		Node:       "node-a",
		ObservedAt: time.Now().UTC(),
		Runtime:    "containerd",
		WorkloadID: workloadID,
		Namespace:  "payments",
		PodName:    "api",
		PodUID:     "pod-uid",
		Count:      1,
		Containers: []WorkloadPackageContainer{{
			ContainerID:   "container-1",
			ContainerName: "api",
			Image:         "example.test/api:dev",
			ImageRef:      "example.test/api@sha256:aaaaaaaa",
			Distro:        "ubuntu",
			DistroVersion: "24.04",
			Source:        "dpkg",
			Count:         1,
			Items: []handler.HostPackageItem{{
				Name:    "openssl",
				Version: "3.0.13-0ubuntu3.5",
				Arch:    "amd64",
			}},
		}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workload-packages:report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+runtimeToken)
	rec := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(NewWorkloadPackages(d).Report)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("report status: %d body: %s", rec.Code, rec.Body.String())
	}
	var report struct {
		ScanTargetID     uuid.UUID                    `json:"scan_target_id"`
		ScanEvidenceID   uuid.UUID                    `json:"scan_evidence_id"`
		InventoryHash    string                       `json:"inventory_hash"`
		PackageCount     int                          `json:"package_count"`
		ScanJobEnqueued  bool                         `json:"scan_job_enqueued"`
		ImageScanTargets []runtimeImageEvidenceReport `json:"image_scan_targets"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.ScanTargetID == uuid.Nil || report.ScanEvidenceID == uuid.Nil || report.InventoryHash == "" {
		t.Fatalf("report = %+v", report)
	}
	if !report.ScanJobEnqueued || report.PackageCount != 1 {
		t.Fatalf("report = %+v", report)
	}
	if len(report.ImageScanTargets) != 1 ||
		report.ImageScanTargets[0].ScanTargetID == uuid.Nil ||
		report.ImageScanTargets[0].ScanEvidenceID == uuid.Nil ||
		report.ImageScanTargets[0].ImageRef != "example.test/api@sha256:aaaaaaaa" ||
		report.ImageScanTargets[0].PackageCount != 1 {
		t.Fatalf("image scan targets = %+v", report.ImageScanTargets)
	}

	scannerToken, _, err := handler.IssueScannerToken(ctx, pool, orgID, "workload-evidence-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	jobs := NewScanJobs(d, nil)
	type claimResponse struct {
		TargetType      string    `json:"target_type"`
		TargetRef       string    `json:"target_ref"`
		TargetID        uuid.UUID `json:"target_id"`
		TargetClusterID uuid.UUID `json:"target_cluster_id"`
		ImageDigest     string    `json:"image_digest"`
		EvidenceID      uuid.UUID `json:"evidence_id"`
		InventoryHash   string    `json:"inventory_hash"`
	}
	claims := map[string]claimResponse{}
	for i := 0; i < 2; i++ {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim", nil)
		req.Header.Set("Authorization", "Bearer "+scannerToken)
		rec = httptest.NewRecorder()
		handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(jobs.Claim)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("claim %d status: %d body: %s", i, rec.Code, rec.Body.String())
		}
		var claim claimResponse
		if err := json.NewDecoder(rec.Body).Decode(&claim); err != nil {
			t.Fatal(err)
		}
		claims[claim.TargetType] = claim
	}
	claim := claims["workload"]
	if claim.TargetType != "workload" || claim.TargetRef != workloadID || claim.TargetID != report.ScanTargetID {
		t.Fatalf("claim = %+v", claim)
	}
	if claim.EvidenceID != report.ScanEvidenceID || claim.InventoryHash != report.InventoryHash {
		t.Fatalf("claim evidence = %+v report = %+v", claim, report)
	}
	imageClaim := claims["image"]
	if imageClaim.TargetType != "image" ||
		imageClaim.TargetRef != report.ImageScanTargets[0].ImageRef ||
		imageClaim.TargetID != report.ImageScanTargets[0].ScanTargetID ||
		imageClaim.EvidenceID != report.ImageScanTargets[0].ScanEvidenceID ||
		imageClaim.InventoryHash != report.ImageScanTargets[0].InventoryHash {
		t.Fatalf("image claim = %+v report = %+v", imageClaim, report.ImageScanTargets[0])
	}

	evidence := handler.NewScanEvidence(d)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/scan-evidence/"+report.ScanEvidenceID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+scannerToken)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", report.ScanEvidenceID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(evidence.Get)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("evidence status: %d body: %s", rec.Code, rec.Body.String())
	}
	var evidenceRes struct {
		TargetType string `json:"target_type"`
		TargetRef  string `json:"target_ref"`
		WorkloadID string `json:"workload_id"`
		Containers []struct {
			ContainerName string `json:"container_name"`
			ImageRef      string `json:"image_ref"`
		} `json:"containers"`
		Packages []struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			BaseImage string `json:"base_image"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&evidenceRes); err != nil {
		t.Fatal(err)
	}
	if evidenceRes.TargetType != "workload" || evidenceRes.TargetRef != workloadID || evidenceRes.WorkloadID != workloadID {
		t.Fatalf("evidence = %+v", evidenceRes)
	}
	if len(evidenceRes.Containers) != 1 || evidenceRes.Containers[0].ContainerName != "api" {
		t.Fatalf("containers = %+v", evidenceRes.Containers)
	}
	if len(evidenceRes.Packages) != 1 || evidenceRes.Packages[0].Ecosystem != "deb" || evidenceRes.Packages[0].BaseImage == "" {
		t.Fatalf("packages = %+v", evidenceRes.Packages)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/scan-evidence/"+report.ImageScanTargets[0].ScanEvidenceID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+scannerToken)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", report.ImageScanTargets[0].ScanEvidenceID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(evidence.Get)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("image evidence status: %d body: %s", rec.Code, rec.Body.String())
	}
	var imageEvidenceRes struct {
		TargetType string `json:"target_type"`
		TargetRef  string `json:"target_ref"`
		SourceType string `json:"source_type"`
		SourceRef  string `json:"source_ref"`
		WorkloadID string `json:"workload_id"`
		Containers []struct {
			ContainerName string `json:"container_name"`
			ImageRef      string `json:"image_ref"`
		} `json:"containers"`
		Packages []struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			BaseImage string `json:"base_image"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&imageEvidenceRes); err != nil {
		t.Fatal(err)
	}
	if imageEvidenceRes.TargetType != "image" ||
		imageEvidenceRes.TargetRef != "example.test/api@sha256:aaaaaaaa" ||
		imageEvidenceRes.SourceType != "runtime-agent" ||
		imageEvidenceRes.SourceRef != "node-a" ||
		imageEvidenceRes.WorkloadID != workloadID {
		t.Fatalf("image evidence = %+v", imageEvidenceRes)
	}
	if len(imageEvidenceRes.Containers) != 1 || len(imageEvidenceRes.Packages) != 1 || imageEvidenceRes.Packages[0].BaseImage == "" {
		t.Fatalf("image evidence details = containers=%+v packages=%+v", imageEvidenceRes.Containers, imageEvidenceRes.Packages)
	}
}
