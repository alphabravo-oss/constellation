package server

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestBackupInventoryRoutesAndOpenAPIContract(t *testing.T) {
	s, e := newSpecServer()
	if e != nil {
		t.Fatal(e)
	}
	routes, e := s.RouteList()
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/api/v1/backups/inventory", "/api/v1/backups/inventory.csv"} {
		found := false
		for _, r := range routes {
			if r.Path == path && r.Method == http.MethodGet {
				found = true
			}
		}
		if !found {
			t.Fatal("missing dedicated route", path)
		}
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatalf("unauth%d %s", w.Code, w.Body.String())
		}
		op := openAPISchemaAt(t, "paths", path, "get")
		desc := strings.ToLower(op["description"].(string))
		for _, text := range []string{"manage-org", "null-org", "read-only", "latest_success", "retained"} {
			if !strings.Contains(desc, text) {
				t.Fatal("missing ownership/source qualification", text)
			}
		}
	}
	list := openAPISchemaAt(t, "paths", "/api/v1/backups/inventory", "get")
	export := openAPISchemaAt(t, "paths", "/api/v1/backups/inventory.csv", "get")
	lp, ep := inventoryOperationParameters(t, list), inventoryOperationParameters(t, export)
	for _, key := range []string{"q", "status", "mode", "signed", "sort", "order"} {
		if !reflect.DeepEqual(lp[key], ep[key]) {
			t.Fatal("CSV filter mismatch", key)
		}
	}
	if ep["limit"] != nil || ep["offset"] != nil {
		t.Fatal("CSV should not present pagination")
	}
	if lp["offset"]["schema"].(map[string]any)["maximum"] != float64(2147483647) || lp["limit"]["schema"].(map[string]any)["maximum"] != float64(500) {
		t.Fatal("wrong continuation")
	}
	inventoryRequired(t, openAPISchemaAt(t, "components", "schemas", "BackupInventoryPage"), "backups", "org_id", "filters", "latest_success", "summary", "source_complete", "summary_scope", "total", "has_more")
	inventoryRequired(t, openAPISchemaAt(t, "components", "schemas", "BackupInventoryRow"), "id", "org_id", "status", "mode", "started_at", "size_bytes", "signed")
	headers := export["responses"].(map[string]any)["200"].(map[string]any)["headers"].(map[string]any)
	for _, key := range []string{"X-Export-Total", "X-Export-Limit", "X-Export-Truncated", "X-Export-Org-ID", "X-Export-Scope"} {
		if headers[key] == nil {
			t.Fatal("missing export receipt", key)
		}
	}
}
