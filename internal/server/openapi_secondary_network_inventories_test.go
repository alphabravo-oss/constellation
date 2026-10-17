package server

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func TestSecondaryNetworkInventoryRoutesAndContracts(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatal(err)
	}
	routes, err := s.RouteList()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, rows, record, scope string
		required                  []string
	}{
		{"/api/v1/network/conversations/streams", "entries", "NetworkConversationStreamRecord", "matching_retained_rollup_streams", []string{"cluster_id", "from", "to"}},
		{"/api/v1/runtime-pcap/inventory", "captures", "PcapInventoryRecord", "matching_retained_capture_requests", []string{"cluster_id"}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			list := openAPISchemaAt(t, "paths", tc.path, "get")
			export := openAPISchemaAt(t, "paths", tc.path+".csv", "get")
			lp, ep := inventoryOperationParameters(t, list), inventoryOperationParameters(t, export)
			for name, value := range lp {
				if name != "limit" && name != "offset" && !reflect.DeepEqual(value, ep[name]) {
					t.Errorf("CSV lost filter/sort %s", name)
				}
			}
			for _, name := range tc.required {
				if lp[name]["required"] != true {
					t.Errorf("%s must be required", name)
				}
			}
			if ep["limit"] != nil || ep["offset"] != nil {
				t.Error("CSV must not advertise page clipping")
			}
			limit := lp["limit"]["schema"].(map[string]any)
			if limit["default"] != float64(100) || limit["maximum"] != float64(500) || lp["offset"]["schema"].(map[string]any)["maximum"] != float64(inventorylist.MaxOffset) {
				t.Error("page bounds disagree with handlers")
			}
			body := inventoryReferencedSchema(t, tc.path)
			inventoryRequired(t, body, "cluster_id", tc.rows, "summary", "total", "filters", "limit", "offset", "has_more", "sort", "order", "source_complete", "summary_scope")
			props := body["properties"].(map[string]any)
			if !reflect.DeepEqual(props["summary_scope"].(map[string]any)["enum"], []any{tc.scope}) {
				t.Error("retained source scope missing")
			}
			inventoryRequired(t, openAPISchemaAt(t, "components", "schemas", tc.record), "row_id")
			for _, suffix := range []string{"", ".csv"} {
				path := tc.path + suffix
				registered := false
				for _, route := range routes {
					registered = registered || route.Method == http.MethodGet && route.Path == path
				}
				if !registered {
					t.Errorf("missing exact route %s", path)
				}
				w := httptest.NewRecorder()
				s.router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
				if w.Code != http.StatusUnauthorized {
					t.Errorf("%s must authenticate before evidence lookup: %d", path, w.Code)
				}
				operation := openAPISchemaAt(t, "paths", path, "get")
				for _, code := range []string{"400", "401", "403", "404", "500"} {
					if operation["responses"].(map[string]any)[code] == nil {
						t.Errorf("missing %s error", code)
					}
				}
				if !strings.Contains(operation["description"].(string), "read-findings") {
					t.Error("read permission not documented")
				}
			}
			csv := openAPISchemaAt(t, "paths", tc.path+".csv", "get", "responses", "200")
			if csv["content"].(map[string]any)["text/csv"] == nil {
				t.Error("CSV media type missing")
			}
			headers := csv["headers"].(map[string]any)
			for _, name := range []string{"X-Export-Total", "X-Export-Limit", "X-Export-Truncated"} {
				if headers[name] == nil {
					t.Errorf("missing %s", name)
				}
			}
			if !reflect.DeepEqual(headers["X-Export-Limit"].(map[string]any)["schema"].(map[string]any)["enum"], []any{float64(100000)}) {
				t.Error("matching export cap changed")
			}
		})
	}
}

func TestSecondaryNetworkInventoryIdentityAndUnknownMeasurements(t *testing.T) {
	stream := openAPISchemaAt(t, "components", "schemas", "NetworkConversationStreamRecord")
	inventoryRequired(t, stream, "row_id", "protocol", "application", "port", "verdict", "from_platform_role", "to_platform_role", "bytes", "client_bytes", "server_bytes", "packets", "sessions", "severity", "threat_id", "last_seen_at")
	if !strings.Contains(stream["properties"].(map[string]any)["row_id"].(map[string]any)["description"].(string), "not a physical event") {
		t.Error("stream tuple identity must not imply physical event identity")
	}
	capture := openAPISchemaAt(t, "components", "schemas", "PcapInventoryRecord")
	inventoryRequired(t, capture, "row_id", "id", "org_id", "cluster_id", "packet_count", "file_size_bytes", "platform_role")
	for _, field := range []string{"packet_count", "file_size_bytes"} {
		if capture["properties"].(map[string]any)[field].(map[string]any)["nullable"] != true {
			t.Errorf("%s must preserve unknown measurements", field)
		}
	}
	inventoryRequired(t, openAPISchemaAt(t, "components", "schemas", "PcapInventorySummary"), "total", "pending", "running", "completed", "failed", "expired", "packets", "bytes", "packet_reports", "file_reports", "platform")
}
