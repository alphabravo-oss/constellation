package server

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func TestProfileInventoryRoutesRequireAuthentication(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatal(err)
	}
	routes, err := s.RouteList()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/v1/runtime/baselines/inventory",
		"/api/v1/runtime/baselines/inventory.csv",
		"/api/v1/runtime/file-profiles/inventory",
		"/api/v1/runtime/file-profiles/inventory.csv",
	} {
		t.Run(path, func(t *testing.T) {
			registered := false
			for _, route := range routes {
				if route.Method == http.MethodGet && route.Path == path {
					registered = true
				}
			}
			if !registered {
				t.Fatal("inventory needs its own registered route, not a workload detail fallback")
			}
			response := httptest.NewRecorder()
			s.router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("inventory must require authentication: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestOpenAPIProfileInventoryContracts(t *testing.T) {
	for _, tc := range []struct {
		path, stem, order string
		max               int
		sorts, counts     []string
	}{
		{"/api/v1/runtime/baselines/inventory", "ProcessProfile", "asc", 500, []string{"workload", "namespace", "mode", "processes", "alerts", "blocks", "rules", "last_new", "learn_started"}, []string{"total", "learn", "monitor", "enforce", "processes", "alerts_24h", "blocks_24h", "rules", "ambiguous_owners"}},
		{"/api/v1/runtime/file-profiles/inventory", "FileProfile", "desc", 2000, []string{"workload", "namespace", "mode", "rules", "paths", "alerts", "blocks", "last_observed"}, []string{"total", "learn", "monitor", "enforce", "rules", "alerts", "blocks", "retained_events", "ambiguous"}},
	} {
		t.Run(tc.stem, func(t *testing.T) {
			list := openAPISchemaAt(t, "paths", tc.path, "get")
			export := openAPISchemaAt(t, "paths", tc.path+".csv", "get")
			lp, ep := inventoryOperationParameters(t, list), inventoryOperationParameters(t, export)
			for name, p := range lp {
				if name != "limit" && name != "offset" && !reflect.DeepEqual(p, ep[name]) {
					t.Errorf("CSV must preserve %s", name)
				}
			}
			if ep["limit"] != nil || ep["offset"] != nil {
				t.Error("CSV must cover matching profiles independently of page")
			}
			if lp["cluster_id"]["required"] != true {
				t.Error("exact cluster is required")
			}
			if lp["limit"]["schema"].(map[string]any)["maximum"] != float64(tc.max) {
				t.Error("incorrect page limit")
			}
			if lp["offset"]["schema"].(map[string]any)["maximum"] != float64(inventorylist.MaxOffset) {
				t.Error("missing deep offset bound")
			}
			if lp["order"]["schema"].(map[string]any)["default"] != tc.order {
				t.Error("incorrect default order")
			}
			sorts := make([]any, len(tc.sorts))
			for i, s := range tc.sorts {
				sorts[i] = s
			}
			if !reflect.DeepEqual(lp["sort"]["schema"].(map[string]any)["enum"], sorts) {
				t.Error("sort contract differs")
			}
			response := inventoryReferencedSchema(t, tc.path)
			inventoryRequired(t, response, "profiles", "total", "summary", "limit", "offset", "has_more", "filters", "sort", "order", "cluster_id", "namespaces", "source_complete", "summary_scope")
			inventoryRequired(t, openAPISchemaAt(t, "components", "schemas", tc.stem+"InventoryRecord"), "row_id", "cluster_id", "workload_id", "owner_count", "owner_ambiguous", "platform_role", "rule_count")
			inventoryRequired(t, openAPISchemaAt(t, "components", "schemas", tc.stem+"InventorySummary"), tc.counts...)
			for _, op := range []map[string]any{list, export} {
				for _, code := range []string{"400", "401", "403", "404", "500"} {
					if op["responses"].(map[string]any)[code] == nil {
						t.Errorf("missing %s error", code)
					}
				}
			}
			for _, phrase := range []string{"read-only", "retained", "ambiguous", "1,000-event sample", "agent bundles"} {
				if !strings.Contains(strings.ToLower(list["description"].(string)), phrase) {
					t.Errorf("missing source boundary %s", phrase)
				}
			}
			headers := openAPISchemaAt(t, "paths", tc.path+".csv", "get", "responses", "200", "headers")
			for _, key := range []string{"X-Export-Total", "X-Export-Limit", "X-Export-Truncated"} {
				if headers[key] == nil {
					t.Errorf("missing export limit evidence %s", key)
				}
			}
		})
	}
}

func TestOpenAPIFileRuleRevisionAndEvidenceRoles(t *testing.T) {
	path := "/api/v1/runtime/file-profiles/{workload_id}/rules/{rule_id}"
	for _, method := range []string{"put", "delete"} {
		op := openAPISchemaAt(t, "paths", path, method)
		request := openAPISchemaAt(t, "paths", path, method, "requestBody")
		if request["required"] != true {
			t.Error("rule changes require a reason-bearing request body")
		}
		inventoryRequired(t, openAPISchemaAt(t, "paths", path, method, "requestBody", "content", "application/json", "schema"), "reason")
		body := openAPISchemaAt(t, "paths", path, method, "requestBody", "content", "application/json", "schema", "properties")
		if body["expected_updated_at"].(map[string]any)["format"] != "date-time" {
			t.Error("reviewed timestamp contract missing")
		}
		if op["responses"].(map[string]any)["409"] == nil {
			t.Error("revision conflict response missing")
		}
	}
	for _, schema := range []map[string]any{
		openAPISchemaAt(t, "components", "schemas", "AssetFindingInventoryRow"),
		openAPISchemaAt(t, "paths", "/api/v1/assets", "get", "responses", "200", "content", "application/json", "schema", "properties", "assets", "items"),
		openAPISchemaAt(t, "paths", "/api/v1/assets/{id}", "get", "responses", "200", "content", "application/json", "schema", "properties", "asset"),
		openAPISchemaAt(t, "paths", "/api/v1/findings", "get", "responses", "200", "content", "application/json", "schema", "properties", "findings", "items"),
		openAPISchemaAt(t, "paths", "/api/v1/findings/{id}", "get", "responses", "200", "content", "application/json", "schema"),
	} {
		inventoryRequired(t, schema, "platform_role")
		role := schema["properties"].(map[string]any)["platform_role"].(map[string]any)
		if !reflect.DeepEqual(role["enum"], []any{"", "core"}) {
			t.Error("unknown evidence role must remain explicit")
		}
	}
}
