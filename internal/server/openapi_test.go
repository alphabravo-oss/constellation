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

func TestOpenAPIGroupEdgeContract(t *testing.T) {
	basePath := "/api/v1/runtime-policies/group-edges"
	row := openAPISchemaAt(t, "components", "schemas", "GroupEdgeRow")
	assertOpenAPIFields(t, row,
		[]string{"id", "cluster_id", "from_group", "to_group", "ports", "mode", "comment", "updated_at"},
		[]string{"id", "cluster_id", "from_group", "to_group", "ports", "mode", "updated_at"})
	ports := row["properties"].(map[string]any)["ports"].(map[string]any)
	if !reflect.DeepEqual(ports["type"], []any{"array", "null"}) || ports["items"].(map[string]any)["$ref"] != "#/components/schemas/PortSpec" {
		t.Errorf("edge ports schema = %v", ports)
	}
	portSpec := openAPISchemaAt(t, "components", "schemas", "PortSpec")
	if portSpec["properties"].(map[string]any)["protocol"].(map[string]any)["type"] != "string" ||
		portSpec["properties"].(map[string]any)["port"].(map[string]any)["maximum"] != float64(65535) {
		t.Errorf("PortSpec schema = %v", portSpec)
	}
	result := openAPISchemaAt(t, "components", "schemas", "ExpandResult")
	assertOpenAPIFields(t, result,
		[]string{"from_members", "to_members", "flows", "policies"},
		[]string{"from_members", "to_members", "flows", "policies"})
	policies := result["properties"].(map[string]any)["policies"].(map[string]any)
	if !reflect.DeepEqual(policies["type"], []any{"array", "null"}) || policies["items"].(map[string]any)["type"] != "string" {
		t.Errorf("expansion policies schema = %v", policies)
	}
	list := openAPISchemaAt(t, "paths", basePath, "get", "responses", "200", "content", "application/json", "schema")
	if list["properties"].(map[string]any)["edges"].(map[string]any)["items"].(map[string]any)["$ref"] != "#/components/schemas/GroupEdgeRow" {
		t.Error("GET edges must use GroupEdgeRow")
	}
	create := openAPISchemaAt(t, "paths", basePath, "post")
	request := openAPISchemaAt(t, "paths", basePath, "post", "requestBody", "content", "application/json", "schema")
	if request["properties"].(map[string]any)["ports"].(map[string]any)["items"].(map[string]any)["$ref"] != "#/components/schemas/PortSpec" {
		t.Error("POST ports must use PortSpec")
	}
	created := openAPISchemaAt(t, "paths", basePath, "post", "responses", "201", "content", "application/json", "schema")
	createdProperties := created["properties"].(map[string]any)
	if createdProperties["edge"].(map[string]any)["$ref"] != "#/components/schemas/GroupEdgeRow" ||
		createdProperties["expansion"].(map[string]any)["$ref"] != "#/components/schemas/ExpandResult" {
		t.Errorf("POST response schema = %v", created)
	}
	expanded := openAPISchemaAt(t, "paths", basePath+"/{id}/expand", "post", "responses", "200", "content", "application/json", "schema")
	if expanded["$ref"] != "#/components/schemas/ExpandResult" {
		t.Errorf("expand response schema = %v", expanded)
	}
	for _, operation := range []map[string]any{
		openAPISchemaAt(t, "paths", basePath, "get"),
		create,
		openAPISchemaAt(t, "paths", basePath+"/{id}", "delete"),
		openAPISchemaAt(t, "paths", basePath+"/{id}/expand", "post"),
	} {
		if !strings.Contains(operation["description"].(string), "cluster grant") {
			t.Errorf("group edge operation omits cluster grant authorization: %v", operation["summary"])
		}
		if _, ok := operation["responses"].(map[string]any)["403"]; !ok {
			t.Errorf("group edge operation omits 403: %v", operation["summary"])
		}
	}
	if !strings.Contains(create["description"].(string), "same transaction, even when expand is omitted") {
		t.Error("POST must document transactional replacement without expand")
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

func TestOpenAPINetworkRuleContracts(t *testing.T) {
	basePath := "/api/v1/clusters/{id}/network-rules"
	rule := openAPISchemaAt(t, "components", "schemas", "NetworkRule")
	assertOpenAPIFields(t, rule,
		[]string{"id", "comment", "from", "to", "ports", "action", "applications", "learned", "disable", "cfg_type", "priority", "match_counter", "last_match_timestamp"},
		[]string{"id", "comment", "from", "to", "ports", "action", "applications", "learned", "disable", "cfg_type", "priority", "match_counter", "last_match_timestamp"})
	mutation := openAPISchemaAt(t, "components", "schemas", "NetworkRuleMutation")
	assertOpenAPIFields(t, mutation,
		[]string{"from", "to", "ports", "applications", "action", "disable", "comment", "priority"},
		[]string{"from", "to"})
	list := openAPISchemaAt(t, "paths", basePath, "get", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, list, []string{"cluster_id", "rules", "summary"}, []string{"cluster_id", "rules", "summary"})
	if list["properties"].(map[string]any)["rules"].(map[string]any)["items"].(map[string]any)["$ref"] != "#/components/schemas/NetworkRule" {
		t.Error("network rule list must use NetworkRule")
	}
	for _, method := range []string{"post", "put"} {
		request := openAPISchemaAt(t, "paths", basePath, method, "requestBody", "content", "application/json", "schema")
		if request["$ref"] != "#/components/schemas/NetworkRuleMutation" {
			t.Errorf("%s request must use NetworkRuleMutation", method)
		}
		response := openAPISchemaAt(t, "paths", basePath, method, "responses", "200", "content", "application/json", "schema")
		assertOpenAPIFields(t, response, []string{"ok", "id", "cfg_type"}, []string{"ok", "id", "cfg_type"})
		if _, ok := openAPISchemaAt(t, "paths", basePath, method, "responses")["201"]; ok {
			t.Errorf("%s documents 201, but handler returns 200", method)
		}
	}
	deleteOperation := openAPISchemaAt(t, "paths", basePath, "delete")
	parameters := deleteOperation["parameters"].([]any)
	if len(parameters) != 3 || parameters[1].(map[string]any)["name"] != "from" || parameters[2].(map[string]any)["name"] != "to" {
		t.Errorf("delete parameters = %v", parameters)
	}
	movePath := basePath + ":move-top"
	moveRequest := openAPISchemaAt(t, "paths", movePath, "post", "requestBody", "content", "application/json", "schema")
	assertOpenAPIFields(t, moveRequest, []string{"from", "to"}, []string{"from", "to"})
	moveResponse := openAPISchemaAt(t, "paths", movePath, "post", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, moveResponse, []string{"ok", "priority"}, []string{"ok", "priority"})
	export := openAPISchemaAt(t, "paths", basePath+":export", "get", "responses", "200", "content", "application/x-yaml", "schema")
	if export["type"] != "string" {
		t.Errorf("network rule export must be YAML text, got %v", export)
	}
	importRequest := openAPISchemaAt(t, "paths", basePath+":import", "post", "requestBody", "content", "application/x-yaml", "schema")
	if importRequest["type"] != "string" {
		t.Errorf("network rule import must accept YAML text, got %v", importRequest)
	}
	importResult := openAPISchemaAt(t, "paths", basePath+":import", "post", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, importResult, []string{"created", "updated", "results"}, []string{"created", "updated", "results"})
	for _, operation := range []map[string]any{
		openAPISchemaAt(t, "paths", basePath, "delete"),
		openAPISchemaAt(t, "paths", basePath, "get"),
		openAPISchemaAt(t, "paths", basePath, "post"),
		openAPISchemaAt(t, "paths", basePath, "put"),
		openAPISchemaAt(t, "paths", movePath, "post"),
	} {
		if _, ok := operation["responses"].(map[string]any)["400"]; !ok {
			t.Errorf("%s missing 400 response", operation["summary"])
		}
	}
}

func TestOpenAPIAdmissionAssessmentContracts(t *testing.T) {
	assessPath := "/api/v1/policies/assess"
	request := openAPISchemaAt(t, "paths", assessPath, "post", "requestBody", "content", "application/json", "schema")
	if request["$ref"] != "#/components/schemas/AdmissionAssessRequest" {
		t.Error("assessment request must use AdmissionAssessRequest")
	}
	assertOpenAPIFields(t, openAPISchemaAt(t, "components", "schemas", "AdmissionAssessRequest"),
		[]string{"image", "namespace", "labels"}, []string{"image"})
	result := openAPISchemaAt(t, "components", "schemas", "AdmissionAssessResult")
	assertOpenAPIFields(t, result,
		[]string{"image", "namespace", "decision", "enforcement_mode", "dry_run_id", "assessed_at", "current_outcome", "protect_outcome", "matches"},
		[]string{"image", "namespace", "decision", "enforcement_mode", "matches"})
	if openAPISchemaAt(t, "paths", assessPath, "post", "responses", "200", "content", "application/json", "schema")["$ref"] != "#/components/schemas/AdmissionAssessResult" {
		t.Error("assessment response must use AdmissionAssessResult")
	}
	match := openAPISchemaAt(t, "components", "schemas", "AdmissionAssessMatch")
	assertOpenAPIFields(t, match,
		[]string{"policy_id", "policy_name", "category", "engine", "mode", "action", "severity", "reason", "evidence", "evidence_details", "remediation"},
		[]string{"policy_id", "policy_name", "category", "engine", "mode", "action", "severity", "reason", "evidence", "remediation"})
	if match["properties"].(map[string]any)["evidence_details"].(map[string]any)["items"].(map[string]any)["$ref"] != "#/components/schemas/AdmissionEvidenceDetail" {
		t.Error("evidence details must use AdmissionEvidenceDetail")
	}
	historyPath := "/api/v1/policies/admission/dry-runs"
	history := openAPISchemaAt(t, "paths", historyPath, "get", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, history, []string{"history", "total"}, []string{"history", "total"})
	if history["properties"].(map[string]any)["history"].(map[string]any)["items"].(map[string]any)["$ref"] != "#/components/schemas/AdmissionDryRunHistoryRow" {
		t.Error("history rows must use AdmissionDryRunHistoryRow")
	}
	clear := openAPISchemaAt(t, "paths", historyPath, "delete", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, clear, []string{"deleted"}, []string{"deleted"})
}

func TestOpenAPIRegistryOperations(t *testing.T) {
	syncPath := "/api/v1/registries/{id}/sync-now"
	sync := openAPISchemaAt(t, "components", "schemas", "RegistrySyncResult")
	assertOpenAPIFields(t, sync,
		[]string{"registry_id", "status", "images_seen", "scan_jobs_enqueued", "error"},
		[]string{"registry_id", "status", "images_seen", "scan_jobs_enqueued"})
	if got := openAPISchemaAt(t, "paths", syncPath, "post", "responses", "200", "content", "application/json", "schema")["$ref"]; got != "#/components/schemas/RegistrySyncResult" {
		t.Errorf("sync result ref = %v", got)
	}
	for _, status := range []string{"400", "401", "403", "500"} {
		if _, ok := openAPISchemaAt(t, "paths", syncPath, "post", "responses")[status]; !ok {
			t.Errorf("sync missing %s", status)
		}
	}
	cancelPath := "/api/v1/registries/{id}/cancel-scans"
	cancel := openAPISchemaAt(t, "components", "schemas", "RegistryCancelScansResponse")
	assertOpenAPIFields(t, cancel,
		[]string{"registry_id", "canceled", "active_remaining"},
		[]string{"registry_id", "canceled", "active_remaining"})
	if got := openAPISchemaAt(t, "paths", cancelPath, "post", "responses", "200", "content", "application/json", "schema")["$ref"]; got != "#/components/schemas/RegistryCancelScansResponse" {
		t.Errorf("cancel result ref = %v", got)
	}
}

func TestOpenAPIEventsExportContract(t *testing.T) {
	path := "/api/v1/events:export"
	operation := openAPISchemaAt(t, "paths", path, "get")
	params := operation["parameters"].([]any)
	if len(params) != 1 || params[0].(map[string]any)["name"] != "hours" || params[0].(map[string]any)["in"] != "query" {
		t.Errorf("export parameters = %v", params)
	}
	media := openAPISchemaAt(t, "paths", path, "get", "responses", "200", "content", "application/x-ndjson")
	if media["x-ndjson-item-schema"].(map[string]any)["$ref"] != "#/components/schemas/EventsExportRecord" {
		t.Errorf("export record schema = %v", media)
	}
	assertOpenAPIFields(t, openAPISchemaAt(t, "components", "schemas", "EventsExportRecord"),
		[]string{"event", "data"}, []string{"event", "data"})
	if _, ok := openAPISchemaAt(t, "paths", path, "get", "responses", "500", "content")["text/plain"]; !ok {
		t.Error("initial export failure should document text/plain 500")
	}
}

func TestOpenAPIPcapContracts(t *testing.T) {
	capture := openAPISchemaAt(t, "components", "schemas", "PcapCapture")
	assertOpenAPIFields(t, capture,
		[]string{"id", "org_id", "cluster_id", "workload", "namespace", "requested_by", "requested_at", "duration_s", "src_ip", "dst_ip", "dst_port", "protocol", "bpf_filter", "interface", "file_count", "file_size_mb", "status", "claimed_by_node", "claimed_at", "completed_at", "error_message", "file_size_bytes", "sha256", "packet_count", "expires_at"},
		[]string{"id", "org_id", "cluster_id", "workload", "namespace", "requested_by", "requested_at", "duration_s", "status", "expires_at"})
	assertOpenAPIFields(t, openAPISchemaAt(t, "components", "schemas", "PcapStartRequest"),
		[]string{"cluster_id", "workload", "namespace", "duration_s", "src_ip", "dst_ip", "dst_port", "protocol", "bpf_filter", "interface", "file_count", "file_size_mb"},
		[]string{"cluster_id", "workload"})
	assertOpenAPIFields(t, openAPISchemaAt(t, "components", "schemas", "PcapStatusUpdate"),
		[]string{"status", "error_message", "packet_count"}, []string{"status"})
	for _, check := range []struct {
		path, method, status string
	}{
		{"/api/v1/runtime-pcap/start", "post", "201"},
		{"/api/v1/runtime-pcap/claim", "get", "200"},
		{"/api/v1/runtime-pcap/{id}", "get", "200"},
		{"/api/v1/runtime-pcap/{id}/status", "post", "200"},
		{"/api/v1/runtime-pcap/{id}/upload", "post", "200"},
	} {
		if got := openAPISchemaAt(t, "paths", check.path, check.method, "responses", check.status, "content", "application/json", "schema")["$ref"]; got != "#/components/schemas/PcapCapture" {
			t.Errorf("%s %s response ref = %v", check.method, check.path, got)
		}
	}
	list := openAPISchemaAt(t, "paths", "/api/v1/runtime-pcap", "get", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, list, []string{"captures", "selected_group", "selected_group_members"}, []string{"captures"})
	if list["properties"].(map[string]any)["captures"].(map[string]any)["items"].(map[string]any)["$ref"] != "#/components/schemas/PcapCapture" {
		t.Error("list captures must use PcapCapture")
	}
	for _, path := range []string{"/api/v1/runtime-pcap/claim", "/api/v1/runtime-pcap/{id}/status", "/api/v1/runtime-pcap/{id}/upload"} {
		method := "post"
		if strings.HasSuffix(path, "/claim") {
			method = "get"
		}
		security := openAPISchemaAt(t, "paths", path, method)["security"].([]any)
		if len(security) != 1 || security[0].(map[string]any)["runtimeAgent"] == nil {
			t.Errorf("%s agent security = %v", path, security)
		}
	}
	if _, ok := openAPISchemaAt(t, "paths", "/api/v1/runtime-pcap/claim", "get", "responses")["204"]; !ok {
		t.Error("claim must document empty queue as 204")
	}
	if _, ok := openAPISchemaAt(t, "paths", "/api/v1/runtime-pcap/start", "post", "responses")["200"]; ok {
		t.Error("start incorrectly documents 200 instead of 201")
	}
	if _, ok := openAPISchemaAt(t, "paths", "/api/v1/runtime-pcap/{id}/upload", "post", "responses")["413"]; !ok {
		t.Error("upload must document oversize 413")
	}
	if _, ok := openAPISchemaAt(t, "paths", "/api/v1/runtime-pcap/{id}/download", "get", "responses", "200", "content")["application/vnd.tcpdump.pcap"]; !ok {
		t.Error("download must document pcap bytes")
	}
}

func TestOpenAPISupportBundleContracts(t *testing.T) {
	bundle := openAPISchemaAt(t, "components", "schemas", "SupportBundle")
	assertOpenAPIFields(t, bundle,
		[]string{"schema_version", "bundle_id", "generated_at", "org_id", "format", "redaction", "integrity", "sections"},
		[]string{"schema_version", "bundle_id", "generated_at", "org_id", "format", "redaction", "integrity", "sections"})
	if got := openAPISchemaAt(t, "paths", "/api/v1/support/bundle", "get", "responses", "200", "content", "application/json", "schema")["$ref"]; got != "#/components/schemas/SupportBundle" {
		t.Errorf("synchronous bundle ref = %v", got)
	}
	job := openAPISchemaAt(t, "components", "schemas", "SupportBundleJob")
	assertOpenAPIFields(t, job,
		[]string{"id", "status", "created_at", "started_at", "finished_at", "expires_at", "bundle_id", "error", "audit_event_id"},
		[]string{"id", "status", "created_at"})
	if got := openAPISchemaAt(t, "paths", "/api/v1/support/bundle/jobs/{id}/download", "get", "responses", "200", "content", "application/json", "schema")["$ref"]; got != "#/components/schemas/SupportBundle" {
		t.Errorf("job download bundle ref = %v", got)
	}
	if got := openAPISchemaAt(t, "paths", "/api/v1/support/bundle/jobs", "post", "responses", "202", "content", "application/json", "schema")["$ref"]; got != "#/components/schemas/SupportBundleJob" {
		t.Errorf("job create ref = %v", got)
	}
	list := openAPISchemaAt(t, "paths", "/api/v1/support/bundle/jobs", "get", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, list, []string{"items", "next_cursor"}, []string{"items", "next_cursor"})
	for _, status := range []string{"404", "409", "410", "503"} {
		if _, ok := openAPISchemaAt(t, "paths", "/api/v1/support/bundle/jobs/{id}/download", "get", "responses")[status]; !ok {
			t.Errorf("job download missing %s", status)
		}
	}
}

func TestOpenAPIMigrationContracts(t *testing.T) {
	previewPath := "/api/v1/migration/preview"
	request := openAPISchemaAt(t, "paths", previewPath, "post", "requestBody", "content", "application/json", "schema")
	assertOpenAPIFields(t, request, []string{"source", "export", "cluster_id"}, []string{"source", "export"})
	if request["properties"].(map[string]any)["cluster_id"].(map[string]any)["format"] != "uuid" {
		t.Error("preview cluster_id must be a UUID")
	}
	preview := openAPISchemaAt(t, "components", "schemas", "MigrationPreview")
	assertOpenAPIFields(t, preview,
		[]string{"import_id", "target_cluster_id", "summary", "vulnerability_profiles", "registries", "policies", "groups", "file_profiles", "process_profiles", "network_rules", "dpi_rules", "dpi_bindings", "unsupported", "rollback_bundle"},
		[]string{"summary", "vulnerability_profiles", "registries", "policies", "groups", "file_profiles", "process_profiles", "network_rules", "dpi_rules", "dpi_bindings", "rollback_bundle"})
	if preview["properties"].(map[string]any)["target_cluster_id"].(map[string]any)["format"] != "uuid" {
		t.Error("preview target_cluster_id must be a UUID")
	}
	if openAPISchemaAt(t, "paths", previewPath, "post", "responses", "200", "content", "application/json", "schema")["$ref"] != "#/components/schemas/MigrationPreview" {
		t.Error("preview response must use MigrationPreview")
	}
	previewResponses := openAPISchemaAt(t, "paths", previewPath, "post", "responses")
	for _, status := range []string{"400", "403", "default"} {
		if previewResponses[status].(map[string]any)["$ref"] != "#/components/responses/Error" {
			t.Errorf("preview %s must use the JSON error response", status)
		}
	}
	if _, ok := previewResponses["413"]; ok {
		t.Error("preview documents 413, but oversized JSON returns 400")
	}
	previewFamilies := map[string]string{
		"vulnerability_profiles": "MigrationVulnerabilityProfile", "registries": "MigrationRegistry",
		"policies": "MigrationPolicy", "groups": "MigrationGroup", "file_profiles": "MigrationFileProfile",
		"process_profiles": "MigrationProcessProfile", "network_rules": "MigrationNetworkRule",
		"dpi_rules": "MigrationDPIRule", "dpi_bindings": "MigrationDPIBinding", "unsupported": "MigrationUnsupported",
	}
	for field, component := range previewFamilies {
		property := preview["properties"].(map[string]any)[field].(map[string]any)
		if property["type"] != "array" || property["items"].(map[string]any)["$ref"] != "#/components/schemas/"+component {
			t.Errorf("preview %s = %v, want %s items", field, property, component)
		}
	}
	for _, family := range []struct {
		component string
		field     string
		item      string
	}{
		{"MigrationGroup", "criteria", "MigrationGroupCriterion"},
		{"MigrationFileProfile", "rules", "MigrationFileProfileRule"},
		{"MigrationProcessProfile", "rules", "MigrationProcessRule"},
		{"MigrationNetworkRule", "ports", "MigrationNetworkPort"},
		{"MigrationDPIRule", "patterns", "MigrationDPIPattern"},
	} {
		schema := openAPISchemaAt(t, "components", "schemas", family.component)
		property := schema["properties"].(map[string]any)[family.field].(map[string]any)
		if property["items"].(map[string]any)["$ref"] != "#/components/schemas/"+family.item {
			t.Errorf("%s.%s must use %s", family.component, family.field, family.item)
		}
	}
	assertOpenAPIFields(t, openAPISchemaAt(t, "components", "schemas", "MigrationDPIBinding"),
		[]string{"source_group", "target_group_id", "target_group_name", "sensor_kind", "source_sensors", "imported_from", "diff_action"},
		[]string{"source_group", "target_group_id", "target_group_name", "sensor_kind", "diff_action"})

	importsPath := "/api/v1/migration/imports"
	imports := openAPISchemaAt(t, "paths", importsPath, "get", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, imports, []string{"imports", "has_more", "next_offset", "next_cursor"}, []string{"imports", "has_more"})
	importItem := imports["properties"].(map[string]any)["imports"].(map[string]any)["items"].(map[string]any)
	assertOpenAPIFields(t, importItem,
		[]string{"id", "source", "status", "target_cluster_id", "summary", "applied_summary", "unsupported", "error", "created_at", "applied_at", "rolled_back_at"},
		[]string{"id", "source", "status", "summary", "created_at"})
	if importItem["properties"].(map[string]any)["target_cluster_id"].(map[string]any)["format"] != "uuid" {
		t.Error("history target_cluster_id must be a UUID")
	}
	parameters := openAPISchemaAt(t, "paths", importsPath, "get")["parameters"].([]any)
	if len(parameters) != 3 || parameters[0].(map[string]any)["name"] != "limit" || parameters[1].(map[string]any)["name"] != "offset" || parameters[2].(map[string]any)["name"] != "cursor" {
		t.Errorf("migration history pagination parameters = %v", parameters)
	}
	for _, parameter := range parameters {
		if parameter.(map[string]any)["in"] != "query" {
			t.Errorf("migration history pagination parameter is not a query: %v", parameter)
		}
	}
	limit := parameters[0].(map[string]any)["schema"].(map[string]any)
	if limit["minimum"] != float64(1) || limit["maximum"] != float64(100) || limit["default"] != float64(25) {
		t.Errorf("migration history limit = %v", limit)
	}
	offset := parameters[1].(map[string]any)["schema"].(map[string]any)
	if offset["minimum"] != float64(0) || offset["maximum"] != float64(1000000) || offset["default"] != float64(0) {
		t.Errorf("migration history offset = %v", offset)
	}
	if parameters[2].(map[string]any)["schema"].(map[string]any)["type"] != "string" {
		t.Errorf("migration history cursor = %v", parameters[2])
	}
	if _, ok := openAPISchemaAt(t, "paths", importsPath, "get", "responses")["400"]; !ok {
		t.Error("migration history must document invalid pagination as 400")
	}

	bundlePath := importsPath + "/{id}/rollback-bundle"
	bundle := openAPISchemaAt(t, "paths", bundlePath, "get", "responses", "200", "content", "application/json", "schema")
	rollbackFamilies := map[string]string{
		"vulnerability_profiles": "MigrationVulnerabilityRollback", "registries": "MigrationRegistryRollback",
		"policies": "MigrationPolicyRollback", "groups": "MigrationGroupRollback",
		"file_profiles": "MigrationFileProfileRollback", "process_profiles": "MigrationProcessProfileRollback",
		"network_rules": "MigrationNetworkRuleRollback", "dpi_rules": "MigrationDPIRuleRollback",
		"dpi_bindings": "MigrationDPIBindingRollback",
	}
	for field, component := range rollbackFamilies {
		property := bundle["properties"].(map[string]any)[field].(map[string]any)
		if property["type"] != "array" || property["items"].(map[string]any)["$ref"] != "#/components/schemas/"+component {
			t.Errorf("rollback bundle %s = %v, want %s items", field, property, component)
		}
	}
	bundleFields := []string{"source", "generated_at"}
	for field := range rollbackFamilies {
		bundleFields = append(bundleFields, field)
	}
	assertOpenAPIFields(t, bundle, bundleFields, append([]string(nil), bundleFields...))
	applyPath := importsPath + "/{id}:apply"
	apply := openAPISchemaAt(t, "paths", applyPath, "post", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, apply, []string{"id", "status", "already_applied", "applied", "unsupported"}, []string{"id", "status"})
	if !reflect.DeepEqual(apply["properties"].(map[string]any)["status"].(map[string]any)["enum"], []any{"applied", "partial_applied"}) {
		t.Error("apply status must allow applied and partial_applied")
	}
	rollbackPath := importsPath + "/{id}:rollback"
	rollback := openAPISchemaAt(t, "paths", rollbackPath, "post", "responses", "200", "content", "application/json", "schema")
	assertOpenAPIFields(t, rollback, []string{"id", "status", "restored", "deleted", "already_rolled_back"}, []string{"id", "status"})
	if rollback["properties"].(map[string]any)["status"].(map[string]any)["const"] != "rolled_back" {
		t.Error("rollback status must be rolled_back")
	}
	for _, path := range []string{bundlePath, applyPath, rollbackPath} {
		method := "post"
		if path == bundlePath {
			method = "get"
		}
		operation := openAPISchemaAt(t, "paths", path, method)
		parameters := operation["parameters"].([]any)
		if len(parameters) != 1 || parameters[0].(map[string]any)["name"] != "id" || parameters[0].(map[string]any)["required"] != true || parameters[0].(map[string]any)["schema"].(map[string]any)["format"] != "uuid" {
			t.Errorf("%s id parameter = %v", path, parameters)
		}
		for _, status := range []string{"400", "403", "404", "409"} {
			if _, ok := operation["responses"].(map[string]any)[status]; !ok {
				t.Errorf("%s omits %s response", path, status)
			}
		}
	}
}
