package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMigrationImportsPaginationAndScope(t *testing.T) {
	fixture := newMigrationRemainingFixture(t)
	ctx := context.Background()
	clusterID := uuid.New()
	if _, err := fixture.d.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, fixture.org, "history-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 27; index++ {
		preview, err := json.Marshal(migrationPreviewDTO{TargetClusterID: clusterID.String()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.d.Pool().Exec(ctx, `INSERT INTO migration_imports (org_id, source, source_hash, preview_json, created_at) VALUES ($1,'neuvector',$2,$3,NOW()-($4::int * INTERVAL '1 minute'))`, fixture.org, fmt.Sprintf("hash-%d", index), preview, index); err != nil {
			t.Fatal(err)
		}
	}
	foreignOrg := uuid.New()
	if _, err := fixture.d.Pool().Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,$2)`, foreignOrg, "history-foreign-"+foreignOrg.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = fixture.d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, foreignOrg) })
	if _, err := fixture.d.Pool().Exec(ctx, `INSERT INTO migration_imports (org_id, source, source_hash, preview_json) VALUES ($1,'neuvector','foreign','{}')`, foreignOrg); err != nil {
		t.Fatal(err)
	}

	call := func(query string) (int, struct {
		Imports    []migrationImportListItemDTO `json:"imports"`
		HasMore    bool                         `json:"has_more"`
		NextOffset int                          `json:"next_offset"`
		NextCursor string                       `json:"next_cursor"`
	}) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/migration/imports"+query, nil)
		request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: fixture.org, UserID: fixture.user}))
		response := httptest.NewRecorder()
		fixture.h.MigrationImports(response, request)
		var body struct {
			Imports    []migrationImportListItemDTO `json:"imports"`
			HasMore    bool                         `json:"has_more"`
			NextOffset int                          `json:"next_offset"`
			NextCursor string                       `json:"next_cursor"`
		}
		if response.Code == http.StatusOK && json.Unmarshal(response.Body.Bytes(), &body) != nil {
			t.Fatalf("invalid history response: %s", response.Body.String())
		}
		return response.Code, body
	}
	status, first := call("")
	if status != http.StatusOK || len(first.Imports) != 25 || !first.HasMore || first.NextOffset != 25 || first.NextCursor == "" {
		t.Fatalf("first page: status=%d count=%d more=%v offset=%d cursor=%q", status, len(first.Imports), first.HasMore, first.NextOffset, first.NextCursor)
	}
	for _, item := range first.Imports {
		if item.TargetClusterID != clusterID.String() {
			t.Fatalf("incorrect cluster attribution: %+v", item)
		}
	}
	status, second := call("?offset=25")
	if status != http.StatusOK || len(second.Imports) != 2 || second.HasMore {
		t.Fatalf("second page: status=%d count=%d more=%v", status, len(second.Imports), second.HasMore)
	}
	status, limited := call("?limit=2&offset=25")
	if status != http.StatusOK || len(limited.Imports) != 2 || limited.HasMore {
		t.Fatalf("limited page: status=%d count=%d more=%v", status, len(limited.Imports), limited.HasMore)
	}
	if _, err := fixture.d.Pool().Exec(ctx, `INSERT INTO migration_imports (org_id, source, source_hash, preview_json, created_at) VALUES ($1,'neuvector','newer','{}',NOW() + INTERVAL '1 second')`, fixture.org); err != nil {
		t.Fatal(err)
	}
	status, stable := call("?cursor=" + first.NextCursor)
	if status != http.StatusOK || len(stable.Imports) != 2 || stable.HasMore || stable.Imports[0].ID != second.Imports[0].ID || stable.Imports[1].ID != second.Imports[1].ID {
		t.Fatalf("cursor page shifted after insert: status=%d rows=%+v", status, stable.Imports)
	}
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=bad", "?offset=-1", "?offset=1000001", "?offset=bad", "?cursor=bad", "?cursor=abc&offset=0"} {
		if status, _ := call(query); status != http.StatusBadRequest {
			t.Fatalf("query %s: status=%d, want 400", query, status)
		}
	}
}

func TestMigrationPreviewPersistsValidatedTargetCluster(t *testing.T) {
	fixture := newMigrationRemainingFixture(t)
	ctx := context.Background()
	clusterID := uuid.New()
	if _, err := fixture.d.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, fixture.org, "preview-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	export := `{"vulnerability_profiles":[{"name":"history-profile","entries":[{"name":"CVE-2026-1001"}]}]}`
	preview := func(target string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(migrationPreviewRequest{Source: "neuvector", Export: export, ClusterID: target})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(body)))
		request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: fixture.org, UserID: fixture.user}))
		response := httptest.NewRecorder()
		fixture.h.MigrationPreview(response, request)
		return response
	}
	if response := preview(uuid.NewString()); response.Code != http.StatusBadRequest {
		t.Fatalf("foreign target status=%d body=%s", response.Code, response.Body.String())
	}
	response := preview(clusterID.String())
	if response.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", response.Code, response.Body.String())
	}
	var result migrationPreviewDTO
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.TargetClusterID != clusterID.String() {
		t.Fatalf("target cluster=%q err=%v", result.TargetClusterID, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/migration/imports", nil)
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: fixture.org, UserID: fixture.user}))
	history := httptest.NewRecorder()
	fixture.h.MigrationImports(history, request)
	var listed struct {
		Imports []migrationImportListItemDTO `json:"imports"`
	}
	if err := json.Unmarshal(history.Body.Bytes(), &listed); err != nil || len(listed.Imports) != 1 || listed.Imports[0].TargetClusterID != clusterID.String() {
		t.Fatalf("history=%s err=%v", history.Body.String(), err)
	}
}

func TestMigrationImportsCursorOrdersTiedTimestamps(t *testing.T) {
	fixture := newMigrationRemainingFixture(t)
	ctx := context.Background()
	for index := 0; index < 3; index++ {
		if _, err := fixture.d.Pool().Exec(ctx, `INSERT INTO migration_imports (org_id, source, source_hash, preview_json, created_at) VALUES ($1,'neuvector',$2,'{}','2026-09-26T00:00:00Z')`, fixture.org, fmt.Sprintf("tied-%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	for index := 0; index < 3; index++ {
		path := "/api/v1/migration/imports?limit=1"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: fixture.org, UserID: fixture.user}))
		response := httptest.NewRecorder()
		fixture.h.MigrationImports(response, request)
		var page struct {
			Imports    []migrationImportListItemDTO `json:"imports"`
			HasMore    bool                         `json:"has_more"`
			NextCursor string                       `json:"next_cursor"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Imports) != 1 {
			t.Fatalf("page %d: status=%d body=%s", index, response.Code, response.Body.String())
		}
		if seen[page.Imports[0].ID] {
			t.Fatalf("duplicate page row %s", page.Imports[0].ID)
		}
		seen[page.Imports[0].ID] = true
		if page.HasMore != (index < 2) {
			t.Fatalf("page %d has_more=%v", index, page.HasMore)
		}
		cursor = page.NextCursor
	}
}
