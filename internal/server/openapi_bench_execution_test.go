package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/pkg/compliance"
)

func TestBenchmarkExecutionOpenAPIContract(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(handler.OpenAPIBytes(), &spec); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"claim", "{id}/heartbeat", "{id}/result"} {
		op := complianceSpecOperation(t, spec.Paths["/api/v1/agent/compliance/bench/requests/"+suffix]["post"])
		if len(op.Security) != 1 || op.Security[0]["runtimeAgent"] == nil {
			t.Fatalf("agent credential boundary missing: %s", suffix)
		}
		for _, status := range []string{"200", "400", "401", "403", "409", "500"} {
			if op.Responses[status] == nil {
				t.Fatalf("%s missing response %s", suffix, status)
			}
		}
	}
	for name, dto := range map[string]any{
		"BenchExecutionRequest": compliance.BenchExecutionRequest{},
		"BenchExecutionAttempt": compliance.BenchExecutionAttempt{},
		"BenchExecutionCounts":  compliance.BenchExecutionCounts{},
	} {
		var fields []string
		typ := reflect.TypeOf(dto)
		for field := range typ.Fields() {
			fields = append(fields, strings.Split(field.Tag.Get("json"), ",")[0])
		}
		assertOpenAPIFields(t, openAPISchemaAt(t, "components", "schemas", name), fields, fields)
	}
	retry := complianceSpecOperation(t, spec.Paths["/api/v1/compliance/bench/requests/{id}/retry"]["post"])
	if retry.Responses["202"] == nil || retry.Responses["409"] == nil || !strings.Contains(retry.Description, "reviewed_revision") {
		t.Fatal("reviewed retry contract missing")
	}
}

func TestBenchmarkExecutionRoutesRequireAuthentication(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/v1/compliance/bench/requests",
		"/api/v1/compliance/bench/requests/00000000-0000-4000-8000-000000000001/retry",
		"/api/v1/agent/compliance/bench/requests/claim",
		"/api/v1/agent/compliance/bench/requests/00000000-0000-4000-8000-000000000001/heartbeat",
		"/api/v1/agent/compliance/bench/requests/00000000-0000-4000-8000-000000000001/result",
	} {
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected authentication rejection, got %d", path, w.Code)
		}
	}
}
