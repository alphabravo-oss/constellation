package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMigrationImportsExportRouteRBACAndContract(t *testing.T) {
	_, server, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	if _, err := pool.Exec(context.Background(), `INSERT INTO migration_imports (org_id, source, source_hash, preview_json) VALUES ($1,'neuvector','route-test','{}')`, orgID); err != nil {
		t.Fatal(err)
	}
	url := server.URL + "/api/v1/migration/imports/export"
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	if status, _ := doJSON(t, http.MethodGet, url, auditor, nil); status != http.StatusForbidden {
		t.Fatalf("auditor export status=%d", status)
	}
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+admin)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/x-ndjson" ||
		!strings.Contains(string(body), `"type":"import"`) || !strings.HasSuffix(string(body), "{\"type\":\"complete\",\"count\":1}\n") {
		t.Fatalf("admin export status=%d content-type=%q body=%s", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
	if response.Header.Get("Content-Disposition") != `attachment; filename="migration-imports.ndjson"` {
		t.Fatalf("export disposition=%q", response.Header.Get("Content-Disposition"))
	}
}
