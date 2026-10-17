package server

import (
	"strings"
	"testing"
)

func TestOpenAPIThreatUint32BoundsAndHistoricalCompleteness(t *testing.T) {
	for _, name := range []string{"RuntimeThreatRecord", "NetworkConversationStreamRecord", "NetworkConversationEntry", "NetworkMapFlow"} {
		t.Run(name, func(t *testing.T) {
			schema := openAPISchemaAt(t, "components", "schemas", name)
			id := openAPISchemaAt(t, "components", "schemas", name, "properties", "threat_id")
			if id["type"] != "integer" || id["format"] != "int64" || id["minimum"] != float64(0) || id["maximum"] != float64(4294967295) {
				t.Fatalf("native unsigned threat-ID bounds lost: %v", id)
			}
			if name == "RuntimeThreatRecord" {
				return
			}
			inventoryRequired(t, schema, "threat_id_complete")
			complete := openAPISchemaAt(t, "components", "schemas", name, "properties", "threat_id_complete")
			if complete["type"] != "boolean" || !strings.Contains(complete["description"].(string), "pruned or partial") {
				t.Error("aggregate must distinguish observed ID from a proven historical maximum")
			}
		})
	}
	summary := openAPISchemaAt(t, "components", "schemas", "NetworkConversationStreamSummary")
	inventoryRequired(t, summary, "threat_id_incomplete")
	count := openAPISchemaAt(t, "components", "schemas", "NetworkConversationStreamSummary", "properties", "threat_id_incomplete")
	if count["type"] != "integer" || count["minimum"] != float64(0) || !strings.Contains(count["description"].(string), "Independent of pagination") {
		t.Error("unknown-maximum summary must count the full matching cohort")
	}
}

func TestOpenAPIThreatCompletenessResponseBindings(t *testing.T) {
	for _, tc := range []struct{ path, schema string }{
		{"/api/v1/network/map", "NetworkMapResponse"},
		{"/api/v1/network/conversations/entries", "NetworkConversationEntriesResponse"},
	} {
		response := openAPISchemaAt(t, "paths", tc.path, "get", "responses", "200", "content", "application/json", "schema")
		if response["$ref"] != "#/components/schemas/"+tc.schema {
			t.Errorf("%s does not bind its threat completeness contract", tc.path)
		}
	}
	flows := openAPISchemaAt(t, "components", "schemas", "NetworkMapResponse", "properties", "flows", "items")
	if flows["$ref"] != "#/components/schemas/NetworkMapFlow" {
		t.Error("map aggregate lost its completeness contract")
	}
	recent := openAPISchemaAt(t, "components", "schemas", "NetworkMapResponse", "properties", "recent_flows", "items")
	if recent["$ref"] != nil {
		t.Error("raw recent flows must not inherit aggregate completeness semantics")
	}
}
