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
	"github.com/alphabravocompany/constellation/internal/handler/authctx"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestScannerPackagesFromServerlessPackagesDefaultsEcosystem(t *testing.T) {
	got := scannerPackagesFromServerlessPackages(ServerlessPackagesPayload{
		Runtime:      "python3.11",
		Architecture: "arm64",
		Packages: []scanner.Package{{
			Name:    "django",
			Version: "4.2.0",
		}},
		Items: []handler.HostPackageItem{{
			Name:    "requests",
			Version: "2.32.0",
		}},
	})
	if len(got) != 2 {
		t.Fatalf("packages = %+v", got)
	}
	for _, pkg := range got {
		if pkg.Ecosystem != "pypi" || pkg.NamespaceKind != "language" || pkg.NamespaceName != "pypi" || pkg.NamespaceVersion != "python3.11" || pkg.Arch != "arm64" {
			t.Fatalf("bad package defaults: %+v", pkg)
		}
	}
}

func TestServerlessPackagesReportQueuesScanEvidence(t *testing.T) {
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
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Serverless Packages Test')`, orgID, "serverless-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Serverless Reporter')`, userID, orgID, "serverless-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	rawToken, _, err := handler.IssueScannerToken(ctx, pool, orgID, "serverless-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	functionRef := "arn:aws:lambda:us-east-1:123456789012:function:payments"
	body, _ := json.Marshal(ServerlessPackagesPayload{
		FunctionRef:  functionRef,
		FunctionName: "payments",
		Provider:     "aws",
		AccountID:    "123456789012",
		Region:       "us-east-1",
		Runtime:      "python3.11",
		Version:      "42",
		Architecture: "x86_64",
		SourceType:   "discoverer",
		CodeSHA256:   "code-sha",
		Role:         "arn:aws:iam::123456789012:role/payments",
		Handler:      "handler.main",
		PackageType:  "Zip",
		Layers: []string{
			"arn:aws:lambda:us-east-1:123456789012:layer:deps:7",
			"arn:aws:lambda:us-east-1:123456789012:layer:deps:7",
		},
		PermissionAnalysis: json.RawMessage(`{"status":"complete","level":"critical","findings":[{"id":"aws-lambda-role-wildcard-admin","severity":"critical"}]}`),
		Packages: []scanner.Package{{
			Name:    "django",
			Version: "4.2.0",
			Purl:    "pkg:pypi/django@4.2.0",
		}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/serverless-packages:report", bytes.NewReader(body))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewServerlessPackages(d).Report(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("report status: %d body: %s", rec.Code, rec.Body.String())
	}
	var report struct {
		ScanTargetID   uuid.UUID `json:"scan_target_id"`
		ScanEvidenceID uuid.UUID `json:"scan_evidence_id"`
		ScanJobID      uuid.UUID `json:"scan_job_id"`
		PackageCount   int       `json:"package_count"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.ScanTargetID == uuid.Nil || report.ScanEvidenceID == uuid.Nil || report.ScanJobID == uuid.Nil || report.PackageCount != 1 {
		t.Fatalf("bad report response: %+v", report)
	}

	var targetType, targetRef, sourceType, sourceRef string
	var metadataRaw []byte
	if err := pool.QueryRow(ctx, `
SELECT type, ref, source_type, COALESCE(source_ref, ''), metadata
  FROM scan_targets
 WHERE id = $1 AND org_id = $2`, report.ScanTargetID, orgID).Scan(&targetType, &targetRef, &sourceType, &sourceRef, &metadataRaw); err != nil {
		t.Fatal(err)
	}
	if targetType != "serverless" || targetRef != functionRef || sourceType != "discoverer" || sourceRef == "" {
		t.Fatalf("target = %s/%s source=%s/%s", targetType, targetRef, sourceType, sourceRef)
	}
	var metadata struct {
		FunctionName       string   `json:"function_name"`
		CodeSHA256         string   `json:"code_sha256"`
		Role               string   `json:"role"`
		Handler            string   `json:"handler"`
		PackageType        string   `json:"package_type"`
		Layers             []string `json:"layers"`
		PermissionAnalysis struct {
			Status   string `json:"status"`
			Level    string `json:"level"`
			Findings []struct {
				ID string `json:"id"`
			} `json:"findings"`
		} `json:"permission_analysis"`
	}
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.FunctionName != "payments" ||
		metadata.CodeSHA256 != "code-sha" ||
		metadata.Role == "" ||
		metadata.Handler != "handler.main" ||
		metadata.PackageType != "Zip" ||
		len(metadata.Layers) != 1 ||
		metadata.PermissionAnalysis.Level != "critical" ||
		len(metadata.PermissionAnalysis.Findings) != 1 {
		t.Fatalf("metadata = %+v", metadata)
	}

	var assetKind, assetName, findingKind, externalID, findingSeverity, findingLifecycle, stableKey string
	var riskScore int
	if err := pool.QueryRow(ctx, `
SELECT a.kind, a.name, f.kind, COALESCE(f.external_id, ''), f.severity, f.risk_score,
       f.lifecycle, COALESCE(f.detail_json->>'stable_key', '')
  FROM findings f
  JOIN assets a ON a.id = f.asset_id
 WHERE f.org_id = $1
   AND f.scan_target_id = $2
   AND f.kind = 'cloud-config'
   AND f.detail_json->>'category' = 'serverless-permission'`,
		orgID, report.ScanTargetID).Scan(&assetKind, &assetName, &findingKind, &externalID, &findingSeverity, &riskScore, &findingLifecycle, &stableKey); err != nil {
		t.Fatalf("permission finding: %v", err)
	}
	if assetKind != "cloud-resource" ||
		assetName != "arn:aws:iam::123456789012:role/payments" ||
		findingKind != "cloud-config" ||
		externalID != "aws-lambda-role-wildcard-admin" ||
		findingSeverity != "critical" ||
		riskScore < 90 ||
		findingLifecycle != "open" ||
		stableKey == "" {
		t.Fatalf("permission finding asset=%s/%s kind=%s external=%s severity=%s risk=%d lifecycle=%s stable=%s",
			assetKind, assetName, findingKind, externalID, findingSeverity, riskScore, findingLifecycle, stableKey)
	}

	cleanBody, _ := json.Marshal(ServerlessPackagesPayload{
		FunctionRef:        functionRef,
		FunctionName:       "payments",
		Provider:           "aws",
		AccountID:          "123456789012",
		Region:             "us-east-1",
		Runtime:            "python3.11",
		Version:            "42",
		Architecture:       "x86_64",
		SourceType:         "discoverer",
		Role:               "arn:aws:iam::123456789012:role/payments",
		PermissionAnalysis: json.RawMessage(`{"status":"complete","level":"low","role_arn":"arn:aws:iam::123456789012:role/payments","role_name":"payments","findings":[]}`),
		Packages: []scanner.Package{{
			Name:    "django",
			Version: "4.2.0",
			Purl:    "pkg:pypi/django@4.2.0",
		}},
	})
	cleanReq := httptest.NewRequest(http.MethodPost, "/api/v1/serverless-packages:report", bytes.NewReader(cleanBody))
	cleanReq = cleanReq.WithContext(authctx.WithSubject(cleanReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	cleanRec := httptest.NewRecorder()
	NewServerlessPackages(d).Report(cleanRec, cleanReq)
	if cleanRec.Code != http.StatusOK {
		t.Fatalf("clean report status: %d body: %s", cleanRec.Code, cleanRec.Body.String())
	}
	if err := pool.QueryRow(ctx, `
SELECT lifecycle
  FROM findings
 WHERE org_id = $1
   AND scan_target_id = $2
   AND detail_json->>'stable_key' = $3`,
		orgID, report.ScanTargetID, stableKey).Scan(&findingLifecycle); err != nil {
		t.Fatalf("resolved permission finding: %v", err)
	}
	if findingLifecycle != "resolved" {
		t.Fatalf("finding lifecycle after clean analysis = %s, want resolved", findingLifecycle)
	}

	var evidenceTargetType string
	var evidencePackages int
	if err := pool.QueryRow(ctx, `
SELECT target_type, package_count
  FROM scan_evidence
 WHERE id = $1 AND org_id = $2`, report.ScanEvidenceID, orgID).Scan(&evidenceTargetType, &evidencePackages); err != nil {
		t.Fatal(err)
	}
	if evidenceTargetType != "serverless" || evidencePackages != 1 {
		t.Fatalf("evidence = %s packages=%d", evidenceTargetType, evidencePackages)
	}

	claimReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/claim", nil)
	claimReq.Header.Set("Authorization", "Bearer "+rawToken)
	claimRec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(NewScanJobs(d, audit.New(pool)).Claim)).ServeHTTP(claimRec, claimReq)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("claim status: %d body: %s", claimRec.Code, claimRec.Body.String())
	}
	var claim struct {
		ID         uuid.UUID  `json:"id"`
		TargetType string     `json:"target_type"`
		TargetRef  string     `json:"target_ref"`
		EvidenceID *uuid.UUID `json:"evidence_id"`
	}
	if err := json.NewDecoder(claimRec.Body).Decode(&claim); err != nil {
		t.Fatal(err)
	}
	if claim.ID != report.ScanJobID || claim.TargetType != "serverless" || claim.TargetRef != functionRef || claim.EvidenceID == nil || *claim.EvidenceID != report.ScanEvidenceID {
		t.Fatalf("claim = %+v want job=%s evidence=%s", claim, report.ScanJobID, report.ScanEvidenceID)
	}
}
