package server

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler"
)

// updateOpenAPI regenerates the checked-in spec instead of asserting against it.
// Run: go test ./internal/server -run TestGenerateOpenAPI -update-openapi
var updateOpenAPI = flag.Bool("update-openapi", false, "regenerate internal/handler/openapi.json from the live router")

// specPath is the embedded spec the server serves (internal/handler/openapi.json),
// resolved relative to this test package's directory.
func specPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// internal/server -> internal/handler/openapi.json
	return filepath.Clean(filepath.Join(wd, "..", "handler", "openapi.json"))
}

// TestGenerateOpenAPI mechanically (re)generates the OpenAPI spec from the live
// chi router. With -update-openapi it writes the file; otherwise it asserts the
// checked-in file already equals the generated output, so a route added without
// regenerating fails CI. Hand-written summaries/descriptions/schemas are
// preserved by MergeOpenAPI; only stubs for new routes are added.
func TestGenerateOpenAPI(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatalf("newSpecServer: %v", err)
	}
	routes, err := s.RouteList()
	if err != nil {
		t.Fatalf("RouteList: %v", err)
	}

	current, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	gen, err := handler.MergeOpenAPI(current, routes)
	if err != nil {
		t.Fatalf("MergeOpenAPI: %v", err)
	}

	if *updateOpenAPI {
		if err := os.WriteFile(specPath(t), gen, 0o644); err != nil {
			t.Fatalf("write spec: %v", err)
		}
		t.Logf("regenerated %s (%d routes)", specPath(t), len(routes))
		return
	}

	if !bytes.Equal(bytes.TrimSpace(current), bytes.TrimSpace(gen)) {
		t.Errorf("internal/handler/openapi.json is stale or hand-edited away from the generated form.\n" +
			"Run: go test ./internal/server -run TestGenerateOpenAPI -update-openapi")
	}
}

// TestOpenAPICompleteness is the I1 CI gate. It walks the live router and fails
// if any registered route+method lacks a spec entry. Adding a route without a
// corresponding spec operation is therefore a build failure.
func TestOpenAPICompleteness(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatalf("newSpecServer: %v", err)
	}
	routes, err := s.RouteList()
	if err != nil {
		t.Fatalf("RouteList: %v", err)
	}
	documented, err := handler.DocumentedRoutes()
	if err != nil {
		t.Fatalf("DocumentedRoutes: %v", err)
	}

	var missing []string
	for _, rt := range routes {
		key := rt.Method + " " + rt.Path
		if !documented[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)

	stubs, err := handler.StubRoutes()
	if err != nil {
		t.Fatalf("StubRoutes: %v", err)
	}
	documentedCount := len(routes) - len(missing)
	t.Logf("OpenAPI coverage: %d/%d route+method operations have a spec entry "+
		"(%d real, %d content-free stubs)",
		documentedCount, len(routes), documentedCount-len(stubs), len(stubs))

	if len(missing) > 0 {
		t.Errorf("%d registered route(s) have no OpenAPI spec entry:\n  %s\n\n"+
			"Every route must be documented. Regenerate the spec with:\n"+
			"  go test ./internal/server -run TestGenerateOpenAPI -update-openapi",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// maxOpenAPIStubs is the ratchet baseline: the number of content-free stub
// operations the checked-in spec is allowed to carry. It exists so the I1 gate
// is REAL, not presence-only — a new route may not ship as a bare stub (that
// would push the count above the baseline), and backfilling docs lowers it. When
// you replace stubs with real documentation, ratchet this DOWN to lock the gain
// in. It must never be raised.
const maxOpenAPIStubs = 0

// TestOpenAPINoNewStubs enforces the stub ratchet. A presence-only stub (summary
// + a lone 200 response, no requestBody/parameters/error responses/schemas) does
// not count as real documentation; this test fails if the spec carries more
// stubs than the baseline, so adding an undocumented route or regressing a
// real operation back to a stub fails CI even though the completeness gate
// (presence-only) would still pass.
func TestOpenAPINoNewStubs(t *testing.T) {
	stubs, err := handler.StubRoutes()
	if err != nil {
		t.Fatalf("StubRoutes: %v", err)
	}
	if len(stubs) > maxOpenAPIStubs {
		list := make([]string, 0, len(stubs))
		for k := range stubs {
			list = append(list, k)
		}
		sort.Strings(list)
		t.Errorf("OpenAPI stub count %d exceeds baseline %d: a new route must ship with a real "+
			"operation (requestBody for write methods and/or non-2xx responses), not a stub.\n"+
			"Document the new route(s) in internal/handler/openapi.json, then regenerate:\n"+
			"  go test ./internal/server -run TestGenerateOpenAPI -update-openapi\n"+
			"Current stub operations:\n  %s",
			len(stubs), maxOpenAPIStubs, strings.Join(list, "\n  "))
	}
}

func openAPISchemaAt(t *testing.T, path ...string) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(handler.OpenAPIBytes(), &document); err != nil {
		t.Fatalf("decode embedded OpenAPI spec: %v", err)
	}
	var current any = document
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("OpenAPI path %v: expected object before %q", path, key)
		}
		current, ok = object[key]
		if !ok {
			t.Fatalf("OpenAPI path %v: missing %q", path, key)
		}
	}
	object, ok := current.(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI path %v: expected object, got %T", path, current)
	}
	return object
}

func assertOpenAPIFields(t *testing.T, schema map[string]any, fields, required []string) {
	t.Helper()
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema has no properties: %v", schema)
	}
	actualFields := make([]string, 0, len(properties))
	for field := range properties {
		actualFields = append(actualFields, field)
	}
	sort.Strings(actualFields)
	sort.Strings(fields)
	if !reflect.DeepEqual(actualFields, fields) {
		t.Errorf("schema properties = %v, want %v", actualFields, fields)
	}
	actualRequired, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("schema has no required fields: %v", schema)
	}
	actualRequiredFields := make([]string, 0, len(actualRequired))
	for _, field := range actualRequired {
		name, ok := field.(string)
		if !ok {
			t.Fatalf("required field is not a string: %v", field)
		}
		actualRequiredFields = append(actualRequiredFields, name)
	}
	sort.Strings(actualRequiredFields)
	sort.Strings(required)
	if !reflect.DeepEqual(actualRequiredFields, required) {
		t.Errorf("required fields = %v, want %v", actualRequiredFields, required)
	}
}

func TestOpenAPIGroupUsageSchema(t *testing.T) {
	operation := openAPISchemaAt(t, "paths", "/api/v1/groups/{id}/usage", "get")
	parameters := operation["parameters"].([]any)
	if len(parameters) != 2 {
		t.Fatalf("group usage parameters = %v", parameters)
	}
	id := parameters[0].(map[string]any)
	clusterID := parameters[1].(map[string]any)
	if id["name"] != "id" || id["in"] != "path" || id["required"] != true || id["schema"].(map[string]any)["format"] != "uuid" {
		t.Errorf("invalid group ID parameter: %v", id)
	}
	if clusterID["name"] != "cluster_id" || clusterID["in"] != "query" || clusterID["required"] == true || clusterID["schema"].(map[string]any)["format"] != "uuid" {
		t.Errorf("invalid optional cluster ID parameter: %v", clusterID)
	}
	response := openAPISchemaAt(t, "paths", "/api/v1/groups/{id}/usage", "get", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, response,
		[]string{"group_id", "group_name", "summary", "references", "coverage"},
		[]string{"group_id", "group_name", "summary", "references", "coverage"})
	properties := response["properties"].(map[string]any)
	summary := properties["summary"].(map[string]any)
	assertOpenAPIFields(t, summary,
		[]string{"total_references", "blocking_references", "network_rules", "dpi_sensor_bindings", "process_profiles", "file_profiles", "response_rules", "admission_rules", "derived_references", "member_targets", "delete_blocked"},
		[]string{"total_references", "blocking_references", "network_rules", "dpi_sensor_bindings", "process_profiles", "file_profiles", "response_rules", "admission_rules", "derived_references", "member_targets", "delete_blocked"})
	for name, property := range summary["properties"].(map[string]any) {
		want := "integer"
		if name == "delete_blocked" {
			want = "boolean"
		}
		if property.(map[string]any)["type"] != want {
			t.Errorf("summary.%s type = %v, want %s", name, property, want)
		}
	}
	references := properties["references"].(map[string]any)
	assertOpenAPIFields(t, references["items"].(map[string]any),
		[]string{"id", "family", "kind", "name", "role", "mode", "detail", "route", "cluster_id", "blocking", "last_modified"},
		[]string{"id", "family", "kind", "name", "blocking"})
	coverage := properties["coverage"].(map[string]any)["items"].(map[string]any)
	assertOpenAPIFields(t, coverage, []string{"family", "status", "detail"}, []string{"family", "status", "detail"})
	for _, status := range []string{"400", "404"} {
		if _, ok := operation["responses"].(map[string]any)[status]; !ok {
			t.Errorf("group usage missing %s response", status)
		}
	}
}

func TestOpenAPIDPISensorBindingSchemas(t *testing.T) {
	basePath := "/api/v1/runtime/dpi-sensor-bindings"
	request := openAPISchemaAt(t, "components", "schemas", "CreateDPISensorBindingRequest")
	assertOpenAPIFields(t, request,
		[]string{"group_id", "sensor_kind", "sensor_id"},
		[]string{"group_id", "sensor_kind"})
	binding := openAPISchemaAt(t, "components", "schemas", "DPISensorBinding")
	assertOpenAPIFields(t, binding,
		[]string{"id", "org_id", "group_id", "sensor_kind", "sensor_id"},
		[]string{"id", "org_id", "group_id", "sensor_kind", "sensor_id"})
	for _, schema := range []map[string]any{request, binding} {
		for _, field := range []string{"group_id", "sensor_id"} {
			property := schema["properties"].(map[string]any)[field].(map[string]any)
			if property["type"] != "string" || property["format"] != "uuid" {
				t.Errorf("%s is not a UUID: %v", field, property)
			}
		}
		kind := schema["properties"].(map[string]any)["sensor_kind"].(map[string]any)
		if !reflect.DeepEqual(kind["enum"], []any{"dlp", "waf"}) {
			t.Errorf("sensor_kind enum = %v", kind["enum"])
		}
	}
	post := openAPISchemaAt(t, "paths", basePath, "post")
	if post["requestBody"].(map[string]any)["required"] != true ||
		openAPISchemaAt(t, "paths", basePath, "post", "requestBody", "content", "application/json", "schema")["$ref"] != "#/components/schemas/CreateDPISensorBindingRequest" {
		t.Error("POST must require the binding request schema")
	}
	if _, ok := post["responses"].(map[string]any)["200"]; ok {
		t.Error("POST documents 200, but the handler returns 201")
	}
	if openAPISchemaAt(t, "paths", basePath, "post", "responses", "201", "content", "application/json", "schema")["$ref"] != "#/components/schemas/DPISensorBinding" {
		t.Error("POST 201 must return a binding")
	}
	list := openAPISchemaAt(t, "paths", basePath, "get", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, list, []string{"bindings"}, []string{"bindings"})
	items := list["properties"].(map[string]any)["bindings"].(map[string]any)
	if !reflect.DeepEqual(items["type"], []any{"array", "null"}) || items["items"].(map[string]any)["$ref"] != "#/components/schemas/DPISensorBinding" {
		t.Errorf("GET bindings schema = %v", items)
	}
	deletePath := basePath + "/{id}"
	deleteOperation := openAPISchemaAt(t, "paths", deletePath, "delete")
	parameters := deleteOperation["parameters"].([]any)
	if len(parameters) != 1 || parameters[0].(map[string]any)["name"] != "id" || parameters[0].(map[string]any)["required"] != true || parameters[0].(map[string]any)["schema"].(map[string]any)["format"] != "uuid" {
		t.Errorf("DELETE ID parameter = %v", parameters)
	}
	deleted := openAPISchemaAt(t, "paths", deletePath, "delete", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, deleted, []string{"deleted"}, []string{"deleted"})
	if deleted["properties"].(map[string]any)["deleted"].(map[string]any)["format"] != "uuid" {
		t.Error("DELETE response must contain a UUID")
	}
}
