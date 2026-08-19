package scanning

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

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestServerlessInventoryListAndGet(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"assets", "findings", "scan_targets", "scan_evidence"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Serverless Inventory Test')`, orgID, "serverless-inv-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Serverless Inventory User')`, userID, orgID, "serverless-inv-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

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
		SourceRef:    "aws/123456789012/us-east-1",
		Role:         "arn:aws:iam::123456789012:role/payments",
		Handler:      "handler.main",
		PackageType:  "Zip",
		Layers:       []string{"arn:aws:lambda:us-east-1:123456789012:layer:deps:7"},
		PermissionAnalysis: json.RawMessage(`{
			"status":"complete",
			"level":"critical",
			"role_arn":"arn:aws:iam::123456789012:role/payments",
			"role_name":"payments",
			"findings":[{
				"id":"aws-lambda-role-wildcard-admin",
				"severity":"critical",
				"title":"Lambda execution role allows all actions on all resources",
				"policy_type":"inline",
				"policy_name":"danger",
				"actions":["*"],
				"resources":["*"]
			}]
		}`),
		Packages: []scanner.Package{{
			Ecosystem: "pypi",
			Name:      "django",
			Version:   "4.2.0",
			Purl:      "pkg:pypi/django@4.2.0",
		}},
		ObservedAt: time.Now().UTC(),
	})
	reportReq := httptest.NewRequest(http.MethodPost, "/api/v1/serverless-packages:report", bytes.NewReader(body))
	reportReq = reportReq.WithContext(authctx.WithSubject(reportReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	reportRec := httptest.NewRecorder()
	NewServerlessPackages(d).Report(reportRec, reportReq)
	if reportRec.Code != http.StatusOK {
		t.Fatalf("report status: %d body: %s", reportRec.Code, reportRec.Body.String())
	}
	var report struct {
		ScanTargetID uuid.UUID `json:"scan_target_id"`
	}
	if err := json.NewDecoder(reportRec.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}

	inventory := NewServerlessInventory(d)
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/serverless-functions?q=payments", nil)
	listReq = listReq.WithContext(authctx.WithSubject(listReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	listRec := httptest.NewRecorder()
	inventory.List(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status: %d body: %s", listRec.Code, listRec.Body.String())
	}
	var list struct {
		Items []serverlessFunctionDTO `json:"serverless_functions"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("serverless functions = %+v", list.Items)
	}
	got := list.Items[0]
	if got.ID != report.ScanTargetID ||
		got.FunctionRef != functionRef ||
		got.FunctionName != "payments" ||
		got.Provider != "aws" ||
		got.PackageCount != 1 ||
		got.PermissionStatus != "complete" ||
		got.PermissionLevel != "critical" ||
		got.OpenFindings != 1 ||
		got.CriticalFindings != 1 ||
		got.LatestEvidenceID == nil ||
		got.LatestJobID == nil {
		t.Fatalf("inventory row = %+v", got)
	}

	router := chi.NewRouter()
	router.Get("/api/v1/serverless-functions/{id}", inventory.Get)
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/serverless-functions/"+report.ScanTargetID.String(), nil)
	getReq = getReq.WithContext(authctx.WithSubject(getReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status: %d body: %s", getRec.Code, getRec.Body.String())
	}
	var detail struct {
		Function       serverlessFunctionDTO  `json:"serverless_function"`
		LatestEvidence *serverlessEvidenceDTO `json:"latest_evidence"`
		Jobs           []serverlessJobDTO     `json:"jobs"`
		Findings       []serverlessFindingDTO `json:"findings"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.Function.ID != report.ScanTargetID ||
		detail.LatestEvidence == nil ||
		detail.LatestEvidence.PackageCount != 1 ||
		len(detail.LatestEvidence.Packages) != 1 ||
		len(detail.Jobs) != 1 ||
		len(detail.Findings) != 1 ||
		detail.Findings[0].Kind != "cloud-config" ||
		detail.Findings[0].ExternalID != "aws-lambda-role-wildcard-admin" {
		t.Fatalf("detail = %+v", detail)
	}
}
