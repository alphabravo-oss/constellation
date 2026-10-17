package server

import (
	"reflect"
	"strings"
	"testing"
)

func TestOpenAPIPcapCompletionRequiresVerifiedUpload(t *testing.T) {
	status := openAPISchemaAt(t, "components", "schemas", "PcapStatusUpdate", "properties", "status")
	if !reflect.DeepEqual(status["enum"], []any{"running", "failed"}) {
		t.Error("status notification must not establish capture completion")
	}
	count := openAPISchemaAt(t, "components", "schemas", "PcapStatusUpdate", "properties", "packet_count")
	if count["minimum"] != float64(0) {
		t.Error("packet count must not allow negative values")
	}
	for _, operation := range []struct{ path, method, explanation string }{
		{"/api/v1/runtime-pcap/{id}/status", "post", "lost upload acknowledgement"},
		{"/api/v1/runtime-pcap/{id}/download", "get", "before any packet bytes"},
	} {
		spec := openAPISchemaAt(t, "paths", operation.path, operation.method)
		if !strings.Contains(spec["description"].(string), operation.explanation) {
			t.Errorf("%s must document receipt integrity", operation.path)
		}
		responses := spec["responses"].(map[string]any)
		if responses["409"] == nil || responses["500"] == nil {
			t.Errorf("%s must document conflicting state and unverifiable evidence", operation.path)
		}
	}
}
