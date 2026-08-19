package stackrox

import (
	"strings"
	"testing"
)

const sampleExport = `
{
  "policies": [
    {
      "id": "p-001",
      "name": "Privileged Container",
      "description": "Block privileged containers at deploy.",
      "categories": ["Security Best Practices"],
      "lifecycleStages": ["DEPLOY"],
      "severity": "HIGH_SEVERITY",
      "disabled": false,
      "enforcementActions": ["SCALE_TO_ZERO_ENFORCEMENT"],
      "policySections": [{
        "sectionName": "container",
        "policyGroups": [{"fieldName": "Privileged", "booleanOperator": "OR", "values": [{"value": "true"}]}]
      }]
    },
    {
      "id": "p-002",
      "name": "Old Latest Tag",
      "description": "No latest tag on production images.",
      "categories": ["Build"],
      "lifecycleStages": ["BUILD"],
      "severity": "MEDIUM_SEVERITY",
      "disabled": true,
      "policySections": [{
        "sectionName": "image",
        "policyGroups": [{"fieldName": "Image Tag", "booleanOperator": "OR", "values": [{"value": "latest"}]}]
      }]
    }
  ]
}`

func TestConvert_TopLevelObject(t *testing.T) {
	out, err := Convert([]byte(sampleExport))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(out))
	}
	// Deploy-stage policy with mapped fields → Kyverno.
	if out[0].Engine != "kyverno" {
		t.Fatalf("first policy engine: %q (want kyverno)", out[0].Engine)
	}
	if !strings.Contains(out[0].SpecYAML, "kyverno.io/v1") {
		t.Fatalf("missing kyverno apiVersion:\n%s", out[0].SpecYAML)
	}
	// Build-stage policy → builtin scan-finding-policy.
	if out[1].Engine != "constellation-builtin" {
		t.Fatalf("build-stage engine: %q", out[1].Engine)
	}
	// Disabled flag carried through.
	if out[1].Enabled {
		t.Fatal("disabled policy must remain disabled after import")
	}
}

func TestConvert_TopLevelArray(t *testing.T) {
	arr := `[{"id":"p","name":"X","lifecycleStages":["RUNTIME"]}]`
	out, err := Convert([]byte(arr))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d", len(out))
	}
	if out[0].Engine != "constellation-builtin" {
		t.Fatalf("runtime engine: %q", out[0].Engine)
	}
}

// A non-disabled DEPLOY policy with no enforcement action is monitor mode and
// must embed validationFailureAction=audit, not enforce.
func TestConvert_MonitorPolicyEmitsAudit(t *testing.T) {
	export := `[{
	  "id":"p-mon","name":"Monitor Privileged","lifecycleStages":["DEPLOY"],
	  "disabled":false,"enforcementActions":[],
	  "policySections":[{"sectionName":"c","policyGroups":[{"fieldName":"Privileged","values":[{"value":"true"}]}]}]
	}]`
	out, err := Convert([]byte(export))
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Mode != "monitor" {
		t.Fatalf("mode: %q (want monitor)", out[0].Mode)
	}
	if out[0].Engine != "kyverno" {
		t.Fatalf("engine: %q", out[0].Engine)
	}
	if !strings.Contains(out[0].SpecYAML, "validationFailureAction: audit") {
		t.Fatalf("monitor policy must emit audit, got:\n%s", out[0].SpecYAML)
	}
	if strings.Contains(out[0].SpecYAML, "validationFailureAction: enforce") {
		t.Fatalf("monitor policy must not emit enforce:\n%s", out[0].SpecYAML)
	}
}

// A disabled policy is never enforce mode.
func TestConvert_DisabledPolicyNotEnforce(t *testing.T) {
	export := `[{
	  "id":"p-dis","name":"Disabled","lifecycleStages":["DEPLOY"],
	  "disabled":true,"enforcementActions":["SCALE_TO_ZERO_ENFORCEMENT"],
	  "policySections":[{"sectionName":"c","policyGroups":[{"fieldName":"Privileged","values":[{"value":"true"}]}]}]
	}]`
	out, err := Convert([]byte(export))
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Mode == "enforce" {
		t.Fatalf("disabled policy must not be enforce: %+v", out[0])
	}
	if strings.Contains(out[0].SpecYAML, "validationFailureAction: enforce") {
		t.Fatalf("disabled policy must not embed enforce:\n%s", out[0].SpecYAML)
	}
}

// Supported-but-previously-dropped criteria (Image Tag, Read-Only Root Filesystem)
// now emit real validate patterns rather than an empty no-op.
func TestConvert_RealPatternsForMappedCriteria(t *testing.T) {
	export := `[{
	  "id":"p-real","name":"Hardening","lifecycleStages":["DEPLOY"],
	  "enforcementActions":["SCALE_TO_ZERO_ENFORCEMENT"],
	  "policySections":[{"sectionName":"c","policyGroups":[
	    {"fieldName":"Read-Only Root Filesystem","values":[{"value":"false"}]},
	    {"fieldName":"Image Tag","values":[{"value":"latest"}]}
	  ]}]
	}]`
	out, err := Convert([]byte(export))
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Engine != "kyverno" {
		t.Fatalf("engine: %q", out[0].Engine)
	}
	spec := out[0].SpecYAML
	if !strings.Contains(spec, "readOnlyRootFilesystem") {
		t.Fatalf("missing readOnlyRootFilesystem pattern:\n%s", spec)
	}
	if !strings.Contains(spec, "'!*:latest'") && !strings.Contains(spec, "!*:latest") {
		t.Fatalf("missing image-tag pattern:\n%s", spec)
	}
}

// A DEPLOY policy whose only criterion has no Kyverno mapping must NOT emit a
// no-op enforce ClusterPolicy; it routes to the constellation-builtin path.
func TestConvert_UnsupportedCriteriaNotNoOpKyverno(t *testing.T) {
	export := `[{
	  "id":"p-uns","name":"Env Var Policy","lifecycleStages":["DEPLOY"],
	  "enforcementActions":["SCALE_TO_ZERO_ENFORCEMENT"],
	  "policySections":[{"sectionName":"c","policyGroups":[{"fieldName":"Environment Variable","values":[{"value":"SECRET"}]}]}]
	}]`
	out, err := Convert([]byte(export))
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Engine == "kyverno" {
		t.Fatalf("unsupported criteria must not emit a kyverno policy: %+v", out[0])
	}
	if out[0].Engine != "constellation-builtin" {
		t.Fatalf("engine: %q (want constellation-builtin)", out[0].Engine)
	}
}

func TestSlug_RemovesNonAlnum(t *testing.T) {
	if got := slug("Privileged Container!! (foo/bar)"); got != "privileged-container-foo-bar" {
		t.Fatalf("slug: %q", got)
	}
}
