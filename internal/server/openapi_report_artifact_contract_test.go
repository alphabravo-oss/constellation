package server

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOpenAPIActualReportArtifactMetadataAndScope(t *testing.T) {
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
	for _, path := range []string{"/api/v1/reports/compliance.html", "/api/v1/reports/compliance.pdf", "/api/v1/reports/executive.html", "/api/v1/reports/executive.pdf"} {
		op := spec.Paths[path]["get"].(map[string]any)
		found := false
		for _, raw := range op["parameters"].([]any) {
			if raw.(map[string]any)["name"] == "cluster_id" {
				found = true
			}
		}
		if !found {
			t.Fatal("missing exact source cluster report parameter", path)
		}
	}
	props := spec.Components.Schemas["ComplianceRunRecord"]["properties"].(map[string]any)
	for _, name := range []string{"artifact_format", "artifact_media_type", "artifact_filename", "artifact_metadata_known"} {
		if props[name] == nil {
			t.Fatal("missing actual artifact metadata", name)
		}
	}
	tuple := spec.Components.Schemas["NetworkPolicyObservedTuple"]["properties"].(map[string]any)
	if tuple["peer_platform_role"] == nil {
		t.Fatal("observed peer role missing")
	}
}
