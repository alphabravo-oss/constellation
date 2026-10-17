package server

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func TestDeploymentFindingInventoryRoutesRequireAuthentication(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatal(err)
	}
	routes, err := s.RouteList()
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"findings", "findings.csv"} {
		pattern := "/api/v1/deployments/{id}/" + suffix
		registered := false
		for _, route := range routes {
			registered = registered || route.Method == http.MethodGet && route.Path == pattern
		}
		if !registered {
			t.Errorf("missing dedicated route %s", pattern)
		}
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, strings.ReplaceAll(pattern, "{id}", "00000000-0000-4000-8000-000000000001"), nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s status=%d; authentication must precede evidence lookup", pattern, w.Code)
		}
	}
}

func TestOpenAPIDeploymentFindingInventoryContract(t *testing.T) {
	path := "/api/v1/deployments/{id}/findings"
	list := openAPISchemaAt(t, "paths", path, "get")
	export := openAPISchemaAt(t, "paths", path+".csv", "get")
	lp, ep := inventoryOperationParameters(t, list), inventoryOperationParameters(t, export)
	for name, p := range lp {
		if name != "limit" && name != "offset" && !reflect.DeepEqual(p, ep[name]) {
			t.Errorf("export must preserve %s", name)
		}
	}
	for _, name := range []string{"id", "cluster_id"} {
		if lp[name]["required"] != true {
			t.Errorf("%s must be required", name)
		}
	}
	if ep["limit"] != nil || ep["offset"] != nil {
		t.Error("matching CSV must not advertise page clipping")
	}
	if lp["limit"]["schema"].(map[string]any)["maximum"] != float64(500) || lp["offset"]["schema"].(map[string]any)["maximum"] != float64(inventorylist.MaxOffset) {
		t.Error("incorrect page bounds")
	}
	if lp["lifecycle"]["schema"].(map[string]any)["default"] != "open" || lp["sort"]["schema"].(map[string]any)["default"] != "risk" || lp["order"]["schema"].(map[string]any)["default"] != "desc" {
		t.Error("default cohort must preserve open, risk-ranked workload findings")
	}
	inventoryRequired(t, inventoryReferencedSchema(t, path), "deployment_id", "cluster_id", "workload_id", "owner_count", "owner_ambiguous", "items", "total", "summary", "filters", "sort", "order", "limit", "offset", "has_more", "source_complete", "summary_scope")
	inventoryRequired(t, openAPISchemaAt(t, "components", "schemas", "DeploymentFindingInventoryRecord"), "row_id", "id", "first_seen_at", "source_cluster_id", "effective_target_cluster_id", "platform_role", "attribution", "owner_count", "owner_ambiguous")
	inventoryRequired(t, openAPISchemaAt(t, "components", "schemas", "DeploymentFindingInventorySummary"), "total", "critical", "high", "fixable", "open", "canonical", "pod", "ambiguous_owners")
	for _, op := range []map[string]any{list, export} {
		for _, code := range []string{"400", "401", "403", "404", "500"} {
			if op["responses"].(map[string]any)[code] == nil {
				t.Errorf("missing %s error", code)
			}
		}
		for _, phrase := range []string{"read-only", "coalesce(target_cluster_id,cluster_id)", "ambiguous", "uniquely owned", "first_seen_at", "repeatable-read", "100-record detail sample", "not scanner coverage"} {
			if !strings.Contains(strings.ToLower(op["description"].(string)), phrase) {
				t.Errorf("missing source boundary %s", phrase)
			}
		}
	}
	headers := openAPISchemaAt(t, "paths", path+".csv", "get", "responses", "200", "headers")
	for _, name := range []string{"X-Export-Total", "X-Export-Limit", "X-Export-Truncated"} {
		if headers[name] == nil {
			t.Errorf("missing export metadata %s", name)
		}
	}
}
