package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestHostPackagesBuildsScannerPackageEvidence(t *testing.T) {
	body := HostPackagesPayload{
		Node:          "node-a",
		ObservedAt:    time.Now(),
		Distro:        "rocky",
		DistroVersion: "9.4",
		Source:        "rpm",
		Items: []HostPackageItem{
			{Name: "openssl-libs", Version: "1:3.0.7-27.el9", Arch: "x86_64"},
			{Name: "missing-version"},
			{Version: "1.0.0"},
		},
	}

	got := scannerPackagesFromHostPackages(body)
	if len(got) != 1 {
		t.Fatalf("packages = %d, want 1: %+v", len(got), got)
	}
	pkg := got[0]
	if pkg.Name != "openssl-libs" || pkg.Version != "1:3.0.7-27.el9" {
		t.Fatalf("package = %+v", pkg)
	}
	if pkg.Ecosystem != "rpm" {
		t.Fatalf("ecosystem = %q, want rpm", pkg.Ecosystem)
	}
	if pkg.NamespaceKind != "os" || pkg.NamespaceName != "rocky" || pkg.NamespaceVersion != "9.4" {
		t.Fatalf("namespace = %s/%s/%s", pkg.NamespaceKind, pkg.NamespaceName, pkg.NamespaceVersion)
	}
}

func TestHostPackagesNormalizesDpkgToDeb(t *testing.T) {
	got := scannerPackagesFromHostPackages(HostPackagesPayload{
		Distro:        "ubuntu",
		DistroVersion: "24.04",
		Source:        "dpkg",
		Items:         []HostPackageItem{{Name: "openssl", Version: "3.0.13-0ubuntu3.5"}},
	})
	if len(got) != 1 {
		t.Fatalf("packages = %d, want 1", len(got))
	}
	if got[0].Ecosystem != "deb" {
		t.Fatalf("ecosystem = %q, want deb", got[0].Ecosystem)
	}
	if got[0].NamespaceName != "ubuntu" || got[0].NamespaceVersion != "24.04" {
		t.Fatalf("namespace = %+v", got[0])
	}
}

func TestPackageEvidenceHashIsStable(t *testing.T) {
	payload := scanEvidencePackagePayload{
		Node:   "node-a",
		Distro: "ubuntu",
		Packages: scannerPackagesFromHostPackages(HostPackagesPayload{
			Distro:        "ubuntu",
			DistroVersion: "24.04",
			Source:        "dpkg",
			Items:         []HostPackageItem{{Name: "openssl", Version: "3.0.13-0ubuntu3.5"}},
		}),
	}
	first, err := packageEvidenceHash(payload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := packageEvidenceHash(payload)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("hash changed: %s vs %s", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("hash prefix = %q", first)
	}
}

func TestHostPackagesReportQueuesHostScanEvidence(t *testing.T) {
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
	node := "host-evidence-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, _ = pool.Exec(ctx, `DELETE FROM scan_targets WHERE org_id = $1 AND ref = $2`, orgID, node)
	_, _ = pool.Exec(ctx, `DELETE FROM scan_jobs WHERE org_id = $1 AND status = 'pending'`, orgID)
	_, _ = pool.Exec(ctx, `DELETE FROM runtime_agent_tokens WHERE name = 'host-evidence-test'`)
	_, _ = pool.Exec(ctx, `DELETE FROM scanner_tokens WHERE name = 'host-evidence-test'`)

	runtimeToken, _, err := IssueRuntimeAgentToken(ctx, pool, orgID, "host-evidence-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(HostPackagesPayload{
		Node:          node,
		ObservedAt:    time.Now().UTC(),
		Distro:        "ubuntu",
		DistroVersion: "24.04",
		Source:        "dpkg",
		Items: []HostPackageItem{{
			Name:    "openssl",
			Version: "3.0.13-0ubuntu3.5",
			Arch:    "amd64",
		}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host-packages:report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+runtimeToken)
	rec := httptest.NewRecorder()
	RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(NewHostPackages(d).Report)).ServeHTTP(rec, req)
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
		t.Fatalf("report = %+v", report)
	}
	if !report.ScanJobEnqueued || report.PackageCount != 1 {
		t.Fatalf("report = %+v", report)
	}

	scannerToken, _, err := IssueScannerToken(ctx, pool, orgID, "host-evidence-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The scan-job claim flow itself lives in the handler/scanning sub-package;
	// to avoid an import cycle this asserts the equivalent invariant directly:
	// the host-package report enqueued a pending scan job for the right target,
	// linked to the right evidence/inventory hash.
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
	if claimTargetType != "host" || claimTargetRef != node || claimTargetID != report.ScanTargetID {
		t.Fatalf("pending job target = type %q ref %q id %s", claimTargetType, claimTargetRef, claimTargetID)
	}
	if claimInventoryHash != report.InventoryHash {
		t.Fatalf("pending job inventory hash = %q report = %q", claimInventoryHash, report.InventoryHash)
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

	evidence := NewScanEvidence(d)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/scan-evidence/"+report.ScanEvidenceID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+scannerToken)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", report.ScanEvidenceID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	ScannerTokenMiddleware(pool)(http.HandlerFunc(evidence.Get)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("evidence status: %d body: %s", rec.Code, rec.Body.String())
	}
	var evidenceRes struct {
		TargetType string `json:"target_type"`
		TargetRef  string `json:"target_ref"`
		Packages   []struct {
			Ecosystem     string `json:"ecosystem"`
			Name          string `json:"name"`
			NamespaceName string `json:"namespace_name"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&evidenceRes); err != nil {
		t.Fatal(err)
	}
	if evidenceRes.TargetType != "host" || evidenceRes.TargetRef != node || len(evidenceRes.Packages) != 1 {
		t.Fatalf("evidence = %+v", evidenceRes)
	}
	if evidenceRes.Packages[0].Ecosystem != "deb" || evidenceRes.Packages[0].NamespaceName != "ubuntu" {
		t.Fatalf("package evidence = %+v", evidenceRes.Packages[0])
	}
}
