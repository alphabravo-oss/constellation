package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestRepositoryInventoryListAndGet(t *testing.T) {
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
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Repository Inventory Test')`, orgID, "repository-inv-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Repository Inventory User')`, userID, orgID, "repository-inv-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	repoRef := "github.com/acme/payments"
	commitSHA := "1234567890abcdef1234567890abcdef12345678"
	body, _ := json.Marshal(RepositoryPackagesPayload{
		RepositoryRef: repoRef,
		RepositoryURL: "https://github.com/acme/payments",
		SourceType:    "repository",
		CommitSHA:     commitSHA,
		Branch:        "main",
		Path:          ".",
		Workflow:      "dependency-scan",
		RunID:         "777",
		PackageSource: "syft",
		Packages: []scanner.Package{{
			Ecosystem: "gomod",
			Name:      "golang.org/x/net",
			Version:   "v0.21.0",
			Purl:      "pkg:golang/golang.org/x/net@v0.21.0",
		}},
	})
	reportReq := httptest.NewRequest(http.MethodPost, "/api/v1/repository-packages:report", bytes.NewReader(body))
	reportReq = reportReq.WithContext(WithSubject(reportReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	reportRec := httptest.NewRecorder()
	NewRepositoryPackages(d).Report(reportRec, reportReq)
	if reportRec.Code != http.StatusOK {
		t.Fatalf("report status: %d body: %s", reportRec.Code, reportRec.Body.String())
	}
	var report struct {
		ScanTargetID uuid.UUID `json:"scan_target_id"`
	}
	if err := json.NewDecoder(reportRec.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}

	inventory := NewRepositoryInventory(d)
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/repository-scans?q=payments&branch=main&workflow=dependency-scan", nil)
	listReq = listReq.WithContext(WithSubject(listReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	listRec := httptest.NewRecorder()
	inventory.List(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status: %d body: %s", listRec.Code, listRec.Body.String())
	}
	var listRes struct {
		Items []repositoryScanDTO `json:"repository_scans"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&listRes); err != nil {
		t.Fatal(err)
	}
	if len(listRes.Items) != 1 {
		t.Fatalf("repository scans = %+v", listRes.Items)
	}
	item := listRes.Items[0]
	if item.ID != report.ScanTargetID ||
		item.RepositoryRef != repoRef ||
		item.RepositoryURL != "https://github.com/acme/payments" ||
		item.CommitSHA != commitSHA ||
		item.Branch != "main" ||
		item.Workflow != "dependency-scan" ||
		item.PackageCount != 1 ||
		item.LatestEvidenceID == nil ||
		item.LatestJobID == nil ||
		item.LatestJobStatus != "pending" {
		t.Fatalf("repository scan item = %+v", item)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/repository-scans/"+report.ScanTargetID.String(), nil)
	getReq = getReq.WithContext(WithSubject(getReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", report.ScanTargetID.String())
	getReq = getReq.WithContext(context.WithValue(getReq.Context(), chi.RouteCtxKey, rctx))
	getRec := httptest.NewRecorder()
	inventory.Get(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status: %d body: %s", getRec.Code, getRec.Body.String())
	}
	var detail struct {
		Scan           repositoryScanDTO      `json:"repository_scan"`
		LatestEvidence *repositoryEvidenceDTO `json:"latest_evidence"`
		Jobs           []repositoryJobDTO     `json:"jobs"`
		Findings       []repositoryFindingDTO `json:"findings"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.Scan.ID != report.ScanTargetID ||
		detail.LatestEvidence == nil ||
		detail.LatestEvidence.RepositoryRef != repoRef ||
		detail.LatestEvidence.CommitSHA != commitSHA ||
		len(detail.LatestEvidence.Packages) != 1 ||
		len(detail.Jobs) != 1 ||
		detail.Jobs[0].Status != "pending" ||
		len(detail.Findings) != 0 {
		t.Fatalf("repository scan detail = %+v", detail)
	}
}
