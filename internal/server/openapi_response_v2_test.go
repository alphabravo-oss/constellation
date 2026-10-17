package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestProcessResponseV2RoutesRequireAgentAuthentication(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatal(err)
	}
	for path, method := range map[string]string{
		"/api/v1/runtime/response-actions/v2/pending": http.MethodGet,
		"/api/v1/runtime/response-actions/v2/result":  http.MethodPost,
	} {
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status=%d; agent authentication missing", method, path, w.Code)
		}
	}
}

func TestProcessResponseV2OpenAPIPreservesIdentityAndReceipts(t *testing.T) {
	raw, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	action := spec.Components.Schemas["RuntimeProcessActionV2"]
	assertOpenAPIFields(t, action, []string{"protocol_version", "id", "action_token", "type", "node", "workload_id", "container_id", "pid", "comm", "boot_id", "process_start_ticks", "start_boot_ns"}, []string{"protocol_version", "id", "action_token", "type", "node", "workload_id", "container_id", "pid", "comm", "boot_id", "process_start_ticks", "start_boot_ns"})
	properties := action["properties"].(map[string]any)
	for _, field := range []string{"process_start_ticks", "start_boot_ns"} {
		if properties[field].(map[string]any)["type"] != "string" {
			t.Fatalf("%s must retain integer precision across JSON clients", field)
		}
	}
	receipt := spec.Components.Schemas["RuntimeProcessReceiptV2"]
	assertOpenAPIFields(t, receipt, []string{"acknowledged", "protocol_version", "id", "action_token", "node", "outcome", "state"}, []string{"acknowledged", "protocol_version", "id", "action_token", "node", "outcome", "state"})
	states := receipt["properties"].(map[string]any)["state"].(map[string]any)["enum"].([]any)
	for _, state := range states {
		if state == "uncertain" {
			return
		}
	}
	t.Fatal("uncertain execution must have an explicit receipt state")
}
