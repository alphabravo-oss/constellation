package server

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func TestRuntimePolicyBundleOpenAPIRequiresScopedProtocol(t *testing.T) {
	raw, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	var op struct {
		Parameters []struct {
			Name     string `json:"name"`
			Required bool   `json:"required"`
			Schema   struct {
				Enum []string `json:"enum"`
			} `json:"schema"`
		} `json:"parameters"`
		Responses map[string]struct {
			Content map[string]struct {
				Schema map[string]any `json:"schema"`
			} `json:"content"`
		} `json:"responses"`
		Security []map[string]any `json:"security"`
	}
	if err := json.Unmarshal(spec.Paths["/api/v1/runtime/policies:bundle"]["get"], &op); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, parameter := range op.Parameters {
		if parameter.Name == "protocol" {
			found = parameter.Required && len(parameter.Schema.Enum) == 1 && parameter.Schema.Enum[0] == "2"
		}
	}
	if !found || len(op.Security) != 1 || op.Security[0]["runtimeAgent"] == nil {
		t.Fatal("bundle requires explicit protocol capability and agent authentication")
	}
	for _, code := range []string{"400", "401", "403", "404", "426", "500"} {
		if _, ok := op.Responses[code]; !ok {
			t.Fatalf("missing scoped bundle failure %s", code)
		}
	}
	envelope := op.Responses["200"].Content["application/json"].Schema
	fields := []string{"protocol_version", "cluster_id", "source_complete", "policies"}
	assertOpenAPIFields(t, envelope, fields, fields)
	policy := envelope["properties"].(map[string]any)["policies"].(map[string]any)["items"].(map[string]any)
	fields = []string{"id", "dp_policy_id", "workload", "namespace", "binding_status", "pod_bindings", "mode", "def_action", "apply_dir", "rules", "version"}
	assertOpenAPIFields(t, policy, fields, fields)
	properties := policy["properties"].(map[string]any)
	if properties["def_action"].(map[string]any)["maximum"] != float64(dp.PolicyActionDeny) {
		t.Fatal("contract must include native deny action")
	}
	pod := properties["pod_bindings"].(map[string]any)["items"].(map[string]any)
	fields = []string{"namespace", "pod_name", "pod_uid"}
	assertOpenAPIFields(t, pod, fields, fields)
}
