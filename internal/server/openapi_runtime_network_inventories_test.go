package server

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func inventoryOperationParameters(t *testing.T, op map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, raw := range op["parameters"].([]any) {
		p := raw.(map[string]any)
		name := p["name"].(string)
		if out[name] != nil {
			t.Fatalf("duplicate parameter %s", name)
		}
		out[name] = p
	}
	return out
}
func inventoryReferencedSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	response := openAPISchemaAt(t, "paths", path, "get", "responses", "200", "content", "application/json", "schema")
	return openAPISchemaAt(t, "components", "schemas", strings.TrimPrefix(response["$ref"].(string), "#/components/schemas/"))
}
func inventoryRequired(t *testing.T, schema map[string]any, names ...string) {
	t.Helper()
	required := map[string]bool{}
	for _, raw := range schema["required"].([]any) {
		required[raw.(string)] = true
	}
	for _, name := range names {
		if !required[name] {
			t.Errorf("missing required response field %s", name)
		}
	}
}

func TestOpenAPIRuntimeNetworkInventoryContracts(t *testing.T) {
	cases := []struct {
		path, rows             string
		limit, max             int
		sort                   string
		filters, sorts, counts []string
		notFound               bool
	}{
		{"/api/v1/network/conversations", "conversations", 5000, 5000, "bytes", []string{"cluster_id", "hours", "hide_platform", "namespace", "verdict", "group", "port", "peer", "application", "from", "to", "verdict_group"}, []string{"from", "to", "bytes", "packets", "edges", "severity", "verdict", "last_seen", "apps"}, []string{"total", "bytes", "packets", "edges", "nodes", "blocked", "violating", "max_severity", "source_clusters"}, true},
		{"/api/v1/network/sessions", "sessions", 500, 2000, "bytes", []string{"cluster_id", "q", "protocol", "port", "application", "peer", "workload", "node", "group", "hours", "hide_platform"}, []string{"workload", "node", "application", "protocol", "client", "server", "bytes", "packets", "client_bytes", "server_bytes", "age", "idle", "severity", "observed", "state"}, []string{"total", "tcp", "udp", "icmp", "other", "client_bytes", "server_bytes", "bytes", "packets", "threats"}, false},
		{"/api/v1/runtime-threats", "threats", 500, 2000, "at", []string{"cluster_id", "hours", "severity_min", "workload_id", "category", "group", "port", "peer", "application", "namespace", "node", "hide_platform", "q"}, []string{"at", "reported", "severity", "action", "workload", "category", "node", "signature"}, []string{"total", "critical", "blocked", "ips", "dlp", "waf", "workloads"}, true},
		{"/api/v1/events", "events", 100, 1000, "at", []string{"cluster_id", "q", "workload", "kind", "source", "severity", "verdict", "namespace", "node", "after", "before"}, []string{"at", "workload", "kind", "source", "severity", "verdict", "namespace", "node"}, []string{"total", "alerting", "blocks", "quarantines", "affected_workloads", "observed"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			list := openAPISchemaAt(t, "paths", tc.path, "get")
			export := openAPISchemaAt(t, "paths", tc.path+".csv", "get")
			lp, ep := inventoryOperationParameters(t, list), inventoryOperationParameters(t, export)
			for _, name := range append(append([]string{}, tc.filters...), "sort", "order") {
				if lp[name] == nil || !reflect.DeepEqual(lp[name], ep[name]) {
					t.Errorf("CSV must preserve filter/sort %s", name)
				}
			}
			if ep["limit"] != nil || ep["offset"] != nil {
				t.Error("CSV must not advertise page clipping")
			}
			lschema := lp["limit"]["schema"].(map[string]any)
			if lschema["default"] != float64(tc.limit) || lschema["maximum"] != float64(tc.max) || lschema["minimum"] != float64(1) {
				t.Errorf("page bounds %v", lschema)
			}
			if lp["offset"]["schema"].(map[string]any)["maximum"] != float64(inventorylist.MaxOffset) {
				t.Error("missing offset bound")
			}
			sortSchema := lp["sort"]["schema"].(map[string]any)
			expected := make([]any, len(tc.sorts))
			for i, value := range tc.sorts {
				expected[i] = value
			}
			if sortSchema["default"] != tc.sort || !reflect.DeepEqual(sortSchema["enum"], expected) {
				t.Errorf("server sort contract %v", sortSchema)
			}
			schema := inventoryReferencedSchema(t, tc.path)
			props := schema["properties"].(map[string]any)
			inventoryRequired(t, schema, "total", "summary", "limit", "offset", "has_more", "sort", "order", tc.rows)
			summaryRef := props["summary"].(map[string]any)["$ref"].(string)
			summary := openAPISchemaAt(t, "components", "schemas", strings.TrimPrefix(summaryRef, "#/components/schemas/"), "properties")
			for _, name := range tc.counts {
				if summary[name] == nil {
					t.Errorf("missing full matching summary unit %s", name)
				}
			}
			for _, operation := range []map[string]any{list, export} {
				responses := operation["responses"].(map[string]any)
				for _, status := range []string{"400", "401", "403", "500"} {
					response, ok := responses[status].(map[string]any)
					if !ok || response["content"].(map[string]any)["application/json"] == nil {
						t.Errorf("missing visible JSON %s response", status)
					}
				}
				if tc.notFound && responses["404"] == nil {
					t.Error("owned-cluster lookup requires404 contract")
				}
			}
			csv := openAPISchemaAt(t, "paths", tc.path+".csv", "get", "responses", "200")
			if csv["content"].(map[string]any)["text/csv"] == nil {
				t.Error("CSV response content missing")
			}
			headers := csv["headers"].(map[string]any)
			for _, name := range []string{"X-Export-Total", "X-Export-Limit", "X-Export-Truncated"} {
				if headers[name] == nil {
					t.Errorf("missing export header %s", name)
				}
			}
			if !reflect.DeepEqual(headers["X-Export-Limit"].(map[string]any)["schema"].(map[string]any)["enum"], []any{float64(100000)}) {
				t.Error("matching CSV cap must be100000")
			}
		})
	}
}

func TestOpenAPIRuntimeNetworkInventorySourceAndIdentity(t *testing.T) {
	conversation := inventoryReferencedSchema(t, "/api/v1/network/conversations")
	inventoryRequired(t, conversation, "source", "source_complete", "summary_scope", "filters")
	cp := conversation["properties"].(map[string]any)
	if !reflect.DeepEqual(cp["source"].(map[string]any)["enum"], []any{"rollups", "live"}) || !reflect.DeepEqual(cp["summary_scope"].(map[string]any)["enum"], []any{"matching_rollups", "live_snapshot"}) {
		t.Error("conversation snapshots must remain distinct from complete rollup counts")
	}
	headers := openAPISchemaAt(t, "paths", "/api/v1/network/conversations.csv", "get", "responses", "200", "headers")
	for _, name := range []string{"X-Conversation-Source", "X-Conversation-Window-Hours", "X-Conversation-Cluster"} {
		if headers[name] == nil {
			t.Errorf("missing source qualifier %s", name)
		}
	}
	if !reflect.DeepEqual(headers["X-Conversation-Source"].(map[string]any)["schema"].(map[string]any)["enum"], []any{"rollups"}) {
		t.Error("CSV must never claim the hot graph as complete durable evidence")
	}
	for _, name := range []string{"NetworkSessionRecord", "RuntimeEventRecord"} {
		schema := openAPISchemaAt(t, "components", "schemas", name)
		inventoryRequired(t, schema, "row_id", "cluster_id", "platform_role")
		if schema["properties"].(map[string]any)["row_id"].(map[string]any)["type"] != "string" {
			t.Error("physical row identity missing")
		}
	}
	for _, name := range []string{"from_platform_role", "to_platform_role"} {
		if openAPISchemaAt(t, "components", "schemas", "NetworkConversationRecord", "properties")[name] == nil {
			t.Errorf("missing endpoint role %s", name)
		}
	}
	events := openAPISchemaAt(t, "paths", "/api/v1/events", "get")
	ep := inventoryOperationParameters(t, events)
	for _, name := range []string{"after", "before"} {
		schema := ep[name]["schema"].(map[string]any)
		if schema["format"] != "date-time" || schema["default"] != nil {
			t.Errorf("%s must preserve an optional precise timestamp with no default bound", name)
		}
	}
	if !strings.Contains(ep["severity"]["description"].(string), "Minimum severity") {
		t.Error("existing minimum severity must not become an equality filter")
	}
	descriptions := map[string][]string{"/api/v1/network/sessions": {"five minutes", "node-local", "port/protocol hints"}, "/api/v1/runtime-threats": {"severity>=8", "action in 2,3,4", "reporter-supplied", "reported_at"}, "/api/v1/events": {"(id,at)", "including observed events", "no default time bound"}, "/api/v1/network/conversations": {"live_snapshot", "returned page"}}
	for path, phrases := range descriptions {
		description := openAPISchemaAt(t, "paths", path, "get")["description"].(string)
		for _, phrase := range phrases {
			if !strings.Contains(strings.ToLower(description), strings.ToLower(phrase)) {
				t.Errorf("%s omits source/unit qualifier %s", path, phrase)
			}
		}
	}
	conversationParams := inventoryOperationParameters(t, openAPISchemaAt(t, "paths", "/api/v1/network/conversations", "get"))
	if !strings.Contains(conversationParams["hours"]["description"].(string), "date_trunc(hour") {
		t.Error("rollup window must disclose hourly boundary rounding")
	}
	sessionSummary := openAPISchemaAt(t, "paths", "/api/v1/network/sessions/summary", "get")
	sp := inventoryOperationParameters(t, sessionSummary)
	listParams := inventoryOperationParameters(t, openAPISchemaAt(t, "paths", "/api/v1/network/sessions", "get"))
	for name, p := range listParams {
		if name != "limit" && name != "offset" && !reflect.DeepEqual(p, sp[name]) {
			t.Errorf("flat summary must preserve session filter %s", name)
		}
	}
	if !reflect.DeepEqual(sessionSummary["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"], map[string]any{"$ref": "#/components/schemas/NetworkSessionSummary"}) {
		t.Error("legacy summary must keep its flat shape")
	}
}

func TestRuntimeNetworkInventoryCSVRoutesRequireAuthentication(t *testing.T) {
	server, err := newSpecServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/network/conversations.csv", "/api/v1/network/sessions.csv", "/api/v1/runtime-threats.csv", "/api/v1/events.csv"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.router.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("CSV must use authenticated read route: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
