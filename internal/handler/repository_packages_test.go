package handler

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

	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestScannerPackagesFromRepositoryPackagesDefaultsNamespace(t *testing.T) {
	got := scannerPackagesFromRepositoryPackages(RepositoryPackagesPayload{
		RepositoryRef: "github.com/acme/payments",
		Packages: []scanner.Package{{
			Ecosystem: "npm",
			Name:      "lodash",
			Version:   "4.17.20",
			Purl:      "pkg:npm/lodash@4.17.20",
		}},
	})
	if len(got) != 1 {
		t.Fatalf("packages = %+v", got)
	}
	pkg := got[0]
	if pkg.NamespaceKind != "language" || pkg.NamespaceName != "npm" || pkg.BaseImage != "" {
		t.Fatalf("package defaults = %+v", pkg)
	}
}

func TestRepositoryPackagesReportQueuesScanEvidence(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"scan_targets", "scan_evidence"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Repository Packages Test')`, orgID, "repository-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Repository Reporter')`, userID, orgID, "repository-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	rawToken, _, err := IssueScannerToken(ctx, pool, orgID, "repository-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	repoRef := "github.com/acme/payments"
	commitSHA := "abcdef1234567890abcdef1234567890abcdef12"
	body, _ := json.Marshal(RepositoryPackagesPayload{
		RepositoryRef: repoRef,
		RepositoryURL: "https://github.com/acme/payments",
		SourceType:    "repository",
		CommitSHA:     commitSHA,
		Branch:        "main",
		Path:          ".",
		Workflow:      "dependency-scan",
		RunID:         "12345",
		PackageSource: "syft",
		Packages: []scanner.Package{{
			Ecosystem: "npm",
			Name:      "lodash",
			Version:   "4.17.20",
			Purl:      "pkg:npm/lodash@4.17.20",
		}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/repository-packages:report", bytes.NewReader(body))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewRepositoryPackages(d).Report(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("report status: %d body: %s", rec.Code, rec.Body.String())
	}
	var report struct {
		ScanTargetID     uuid.UUID `json:"scan_target_id"`
		ScanEvidenceID   uuid.UUID `json:"scan_evidence_id"`
		ScanJobID        uuid.UUID `json:"scan_job_id"`
		ScannerTargetRef string    `json:"scanner_target_ref"`
		PackageCount     int       `json:"package_count"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.ScanTargetID == uuid.Nil || report.ScanEvidenceID == uuid.Nil || report.ScanJobID == uuid.Nil || report.PackageCount != 1 {
		t.Fatalf("bad report response: %+v", report)
	}
	if report.ScannerTargetRef != repoRef+"@"+commitSHA {
		t.Fatalf("scanner target ref = %q", report.ScannerTargetRef)
	}

	var targetType, targetRef, sourceType, sourceRef string
	var metadataRaw []byte
	if err := pool.QueryRow(ctx, `
SELECT type, ref, source_type, COALESCE(source_ref, ''), metadata
  FROM scan_targets
 WHERE id = $1 AND org_id = $2`, report.ScanTargetID, orgID).Scan(&targetType, &targetRef, &sourceType, &sourceRef, &metadataRaw); err != nil {
		t.Fatal(err)
	}
	if targetType != "repository" || targetRef != repoRef+"@"+commitSHA || sourceType != "repository" || sourceRef != commitSHA {
		t.Fatalf("target = %s/%s source=%s/%s", targetType, targetRef, sourceType, sourceRef)
	}
	var metadata struct {
		RepositoryRef string `json:"repository_ref"`
		CommitSHA     string `json:"commit_sha"`
		Branch        string `json:"branch"`
		Workflow      string `json:"workflow"`
		RunID         string `json:"run_id"`
		PackageCount  int    `json:"package_count"`
	}
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.RepositoryRef != repoRef || metadata.CommitSHA != commitSHA || metadata.Branch != "main" || metadata.Workflow != "dependency-scan" || metadata.RunID != "12345" || metadata.PackageCount != 1 {
		t.Fatalf("metadata = %+v", metadata)
	}

	// The scan-job claim flow itself lives in the handler/scanning sub-package;
	// to avoid an import cycle this asserts the equivalent invariant directly:
	// the repository-package report enqueued a pending scan job (matching
	// report.ScanJobID) for the right repository target, with no cluster scope
	// and a non-empty inventory hash, linked to the latest package evidence.
	var claim struct {
		ID              uuid.UUID
		TargetType      string
		TargetRef       string
		SourceType      string
		SourceRef       string
		InventoryHash   string
		TargetClusterID *uuid.UUID
	}
	if err := pool.QueryRow(ctx, `
SELECT sj.id, st.type, st.ref, st.source_type, COALESCE(st.source_ref, ''),
       COALESCE(st.inventory_hash, ''), st.cluster_id
  FROM scan_jobs sj
  JOIN scan_targets st ON st.id = sj.target_id
 WHERE sj.org_id = $1
   AND sj.id = $2
   AND sj.status = 'pending'`, orgID, report.ScanJobID).Scan(
		&claim.ID, &claim.TargetType, &claim.TargetRef, &claim.SourceType,
		&claim.SourceRef, &claim.InventoryHash, &claim.TargetClusterID); err != nil {
		t.Fatalf("pending scan job lookup: %v", err)
	}
	if claim.ID != report.ScanJobID ||
		claim.TargetType != "repository" ||
		claim.TargetRef != repoRef+"@"+commitSHA ||
		claim.SourceType != "repository" ||
		claim.SourceRef != commitSHA ||
		claim.TargetClusterID != nil ||
		claim.InventoryHash == "" {
		t.Fatalf("claim = %+v want job=%s", claim, report.ScanJobID)
	}
	var claimEvidenceID uuid.UUID
	if err := pool.QueryRow(ctx, `
SELECT id
  FROM scan_evidence
 WHERE org_id = $1
   AND scan_target_id = (SELECT target_id FROM scan_jobs WHERE id = $2)
   AND evidence_type = $3
 ORDER BY observed_at DESC
 LIMIT 1`, orgID, report.ScanJobID, PackageInventoryEvidence).Scan(&claimEvidenceID); err != nil {
		t.Fatalf("latest evidence lookup: %v", err)
	}
	if claimEvidenceID != report.ScanEvidenceID {
		t.Fatalf("claim evidence = %s want %s", claimEvidenceID, report.ScanEvidenceID)
	}

	evidenceReq := httptest.NewRequest(http.MethodGet, "/api/v1/scan-evidence/"+report.ScanEvidenceID.String(), nil)
	evidenceReq.Header.Set("Authorization", "Bearer "+rawToken)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", report.ScanEvidenceID.String())
	evidenceReq = evidenceReq.WithContext(context.WithValue(evidenceReq.Context(), chi.RouteCtxKey, rctx))
	evidenceRec := httptest.NewRecorder()
	ScannerTokenMiddleware(pool)(http.HandlerFunc(NewScanEvidence(d).Get)).ServeHTTP(evidenceRec, evidenceReq)
	if evidenceRec.Code != http.StatusOK {
		t.Fatalf("evidence status: %d body: %s", evidenceRec.Code, evidenceRec.Body.String())
	}
	var evidence struct {
		TargetType    string            `json:"target_type"`
		TargetRef     string            `json:"target_ref"`
		RepositoryRef string            `json:"repository_ref"`
		CommitSHA     string            `json:"commit_sha"`
		Workflow      string            `json:"workflow"`
		Packages      []scanner.Package `json:"packages"`
	}
	if err := json.NewDecoder(evidenceRec.Body).Decode(&evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.TargetType != "repository" ||
		evidence.TargetRef != repoRef+"@"+commitSHA ||
		evidence.RepositoryRef != repoRef ||
		evidence.CommitSHA != commitSHA ||
		evidence.Workflow != "dependency-scan" ||
		len(evidence.Packages) != 1 ||
		evidence.Packages[0].NamespaceName != "npm" {
		t.Fatalf("evidence = %+v", evidence)
	}
}
