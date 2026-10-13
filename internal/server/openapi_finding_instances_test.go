package server

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOpenAPIFindingInstanceContracts(t *testing.T) {
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
	if err = json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"", "/triage", "/suppress", "/accept-risk", "/reachability", "/comments"} {
		path := "/api/v1/finding-instances/{id}" + action
		method := "post"
		if action == "" {
			method = "get"
		}
		op, _ := spec.Paths[path][method].(map[string]any)
		if op == nil {
			t.Fatalf("missing%s%s", method, path)
		}
		params := op["parameters"].([]any)
		required := false
		for _, p := range params {
			v := p.(map[string]any)
			if v["name"] == "first_seen_at" && v["required"] == true {
				required = true
			}
		}
		if !required {
			t.Fatal("exactselectornotrequired")
		}
		if method == "post" {
			responses := op["responses"].(map[string]any)
			if responses["409"] == nil || responses["428"] == nil {
				t.Fatal("preconditionresponsesmissing")
			}
		}
	}
	props := spec.Components.Schemas["FindingInstanceIdentity"]["properties"].(map[string]any)
	for _, key := range []string{"row_id", "first_seen_at", "revision", "source_cluster_id", "target_cluster_id"} {
		if props[key] == nil {
			t.Fatal("missingidentityfield", key)
		}
	}
}
