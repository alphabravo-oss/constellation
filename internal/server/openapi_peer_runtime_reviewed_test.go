package server

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOpenAPIPeerAndReviewedRuntimeContracts(t *testing.T) {
	raw, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	peer := spec.Components.Schemas["NetworkPeerEvidence"]
	props := peer["properties"].(map[string]any)
	for _, key := range []string{"cluster_id", "workload_platform_role", "hide_platform", "source_limit", "total", "has_more"} {
		if props[key] == nil {
			t.Fatalf("peer metadata missing %s", key)
		}
	}
	rows := props["peers"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	for _, key := range []string{"peer_platform_role", "peer_cluster_id"} {
		if rows[key] == nil {
			t.Fatalf("peer row missing %s", key)
		}
	}
	for path, method := range map[string]string{"/api/v1/runtime-policies/{id}/reviewed": "put", "/api/v1/runtime-policies/{id}/reviewed/promote": "post", "/api/v1/runtime-policies/{id}/reviewed/demote": "post", "/api/v1/runtime-policies/{id}/reviewed/disable": "post"} {
		op, ok := spec.Paths[path][method].(map[string]any)
		if !ok {
			t.Fatalf("reviewed route missing %s", path)
		}
		responses := op["responses"].(map[string]any)
		if responses["409"] == nil || responses["428"] == nil {
			t.Fatal("review precondition responses missing")
		}
	}
	if spec.Paths["/api/v1/runtime-policies/{id}/reviewed"]["delete"] == nil {
		t.Fatal("reviewed delete missing")
	}
	for _, name := range []string{"RuntimePolicyReviewedRequest", "RuntimePolicyReviewedUpdate"} {
		schema := spec.Components.Schemas[name]
		required := schema["required"].([]any)
		seen := map[string]bool{}
		for _, value := range required {
			seen[value.(string)] = true
		}
		if !seen["cluster_id"] || !seen["expected_version"] {
			t.Fatal("missing mandatory exact review fields", name)
		}
	}
}

func TestOpenAPINetworkRuleInventoryContract(t *testing.T) {
	raw, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", ".csv"} {
		op, ok := spec.Paths["/api/v1/clusters/{id}/network-rules/inventory"+suffix]["get"].(map[string]any)
		if !ok {
			t.Fatal("inventory operation missing", suffix)
		}
		seen := map[string]bool{}
		for _, raw := range op["parameters"].([]any) {
			p := raw.(map[string]any)
			seen[p["name"].(string)] = true
		}
		for _, key := range []string{"q", "action", "status", "cfg_type", "from", "to", "sort", "order", "limit", "offset", "hide_platform"} {
			if !seen[key] {
				t.Fatal("missing matching parameter", key)
			}
		}
	}
	props := spec.Components.Schemas["NetworkRuleInventoryRow"]["properties"].(map[string]any)
	for _, key := range []string{"row_id", "id", "from_platform_role", "to_platform_role"} {
		if props[key] == nil {
			t.Fatal("missing exact inventory row field", key)
		}
	}
	csv := spec.Paths["/api/v1/clusters/{id}/network-rules/inventory.csv"]["get"].(map[string]any)["responses"].(map[string]any)["200"].(map[string]any)
	headers := csv["headers"].(map[string]any)
	for _, key := range []string{"X-Export-Limit", "X-Export-Total", "X-Export-Truncated"} {
		if headers[key] == nil {
			t.Fatal("missing bounded export metadata", key)
		}
	}
}
