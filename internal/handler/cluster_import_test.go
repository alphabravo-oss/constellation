package handler

import (
	"strings"
	"testing"
)

func TestRenderImportManifest(t *testing.T) {
	m, err := renderImportManifest(importParams{
		ControlPlaneURL: "https://constellation.dev.alphabravo.io",
		Token:           "raw-agent-token-abc123def456",
		ClusterID:       "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130",
		ClusterName:     "prod-us-east-1",
		AgentImage:      "ghcr.io/alphabravocompany/constellation/runtime-agent:latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"kind: Namespace",
		"kind: DaemonSet",
		"kind: ClusterRoleBinding",
		`value: "https://constellation.dev.alphabravo.io"`, // control plane FQDN
		`token: "raw-agent-token-abc123def456"`,             // credential in the secret
		`value: "prod-us-east-1"`,                            // cluster name
		`value: "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130"`,      // cluster id
		"ghcr.io/alphabravocompany/constellation/runtime-agent:latest",
	} {
		if !strings.Contains(m, want) {
			t.Fatalf("manifest missing %q", want)
		}
	}
}
