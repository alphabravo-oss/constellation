//go:build e2etools

// Cluster-integration drift driver. Loads two YAML files (declared vs live), feeds
// them into pkg/gitops.DetectDrift and prints the DriftFinding output as JSON. Used
// by the e2e wave to prove the drift comparator works end-to-end without needing a
// real Argo CD server. Build with:
//
//	go run -tags e2etools deploy/e2e/cluster-integration/drift_driver.go \
//	    deploy/e2e/gitops/declared-rolebinding.yaml \
//	    deploy/e2e/gitops/live-rolebinding.yaml
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"sigs.k8s.io/yaml"

	"github.com/alphabravocompany/constellation/pkg/gitops"
)

type rawResource struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   map[string]any `json:"metadata"`
	Spec       map[string]any `json:"spec,omitempty"`
	RoleRef    map[string]any `json:"roleRef,omitempty"`
	Subjects   []any          `json:"subjects,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}

func load(path string) gitops.Resource {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(2)
	}
	var raw rawResource
	if err := yaml.Unmarshal(b, &raw); err != nil {
		fmt.Fprintln(os.Stderr, "yaml:", err)
		os.Exit(2)
	}
	name, _ := raw.Metadata["name"].(string)
	ns, _ := raw.Metadata["namespace"].(string)
	// Flatten roleRef/subjects/spec/data into a single comparable map so the hash
	// covers every field regardless of resource kind.
	spec := map[string]any{}
	if raw.Spec != nil {
		spec["spec"] = raw.Spec
	}
	if raw.RoleRef != nil {
		spec["roleRef"] = raw.RoleRef
	}
	if raw.Subjects != nil {
		spec["subjects"] = raw.Subjects
	}
	if raw.Data != nil {
		spec["data"] = raw.Data
	}
	return gitops.Resource{Kind: raw.Kind, Name: name, Namespace: ns, Spec: spec}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: drift_driver <declared.yaml> <live.yaml>")
		os.Exit(2)
	}
	decl := load(os.Args[1])
	live := load(os.Args[2])
	findings := gitops.DetectDrift("argocd", "platform-rbac",
		[]gitops.Resource{decl}, []gitops.Resource{live})
	out := map[string]any{
		"source":      "argocd",
		"application": "platform-rbac",
		"declared":    map[string]string{"kind": decl.Kind, "name": decl.Name, "hash": decl.Hash()},
		"live":        map[string]string{"kind": live.Kind, "name": live.Name, "hash": live.Hash()},
		"findings":    findings,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(2)
	}
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "no drift detected (unexpected for this test)")
		os.Exit(1)
	}
}
