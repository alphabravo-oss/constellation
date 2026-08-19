// Package fields exposes the curated metadata catalog for the policy DSL.
// Inspired by StackRox's pkg/search/fields.go, re-implemented as a small Go
// catalogue. Each entry has a stable Name (dot-path used by the eval package),
// a human description, a Type hint for the UI picker, optional EnumValues for
// dropdown rendering, and the ScopeApplicability stages where it is meaningful.
package fields

import "sort"

// Type controls how the UI renders the value picker.
type Type string

const (
	TypeString Type = "string"
	TypeBool   Type = "bool"
	TypeInt    Type = "int"
	TypeFloat  Type = "float"
	TypeEnum   Type = "enum"
	TypeRegex  Type = "regex"
)

// Field is the metadata for one criterion field.
type Field struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Type              Type     `json:"type"`
	EnumValues        []string `json:"enum_values,omitempty"`
	ScopeApplicability []string `json:"scope_applicability"` // BUILD / DEPLOY / RUNTIME
	Category          string   `json:"category"`
}

// All returns the curated catalogue, sorted alphabetically by Name. Returned
// slice is a freshly allocated copy — callers may sort or filter freely.
func All() []Field {
	out := make([]Field, len(catalogue))
	copy(out, catalogue)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ByName returns the field for the given dot-path name, if known.
func ByName(name string) (Field, bool) {
	for _, f := range catalogue {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// catalogue lists every policy-criterion field we expose to the wizard. The
// list is intentionally curated (not auto-derived from a schema) so we ship
// human-readable descriptions and operator hints with each entry.
var catalogue = []Field{
	// --- image ---
	{
		Name: "image.registry", Description: "Image registry hostname (e.g. ghcr.io, docker.io).",
		Type: TypeString, Category: "image",
		ScopeApplicability: []string{"BUILD", "DEPLOY"},
	},
	{
		Name: "image.repository", Description: "Image repository path (e.g. library/nginx).",
		Type: TypeString, Category: "image",
		ScopeApplicability: []string{"BUILD", "DEPLOY"},
	},
	{
		Name: "image.tag", Description: "Image tag (e.g. v1.2.3, latest).",
		Type: TypeString, Category: "image",
		ScopeApplicability: []string{"BUILD", "DEPLOY"},
	},
	{
		Name: "image.signature.verified",
		Description: "Whether the image carries a cosign-verified signature matching trust policy.",
		Type: TypeBool, Category: "image",
		ScopeApplicability: []string{"BUILD", "DEPLOY"},
	},
	{
		Name: "image.sbom.present", Description: "Whether the image has a published SBOM (SPDX/CycloneDX).",
		Type: TypeBool, Category: "image",
		ScopeApplicability: []string{"BUILD", "DEPLOY"},
	},
	{
		Name: "image.age_days", Description: "Age of the image manifest in days (since pushed).",
		Type: TypeInt, Category: "image",
		ScopeApplicability: []string{"BUILD", "DEPLOY"},
	},

	// --- cve ---
	{
		Name: "cve.severity", Description: "Highest CVE severity present in the image.",
		Type: TypeEnum, EnumValues: []string{"info", "low", "medium", "high", "critical"},
		Category: "cve",
		ScopeApplicability: []string{"BUILD", "DEPLOY"},
	},
	{
		Name: "cve.cvss", Description: "Highest CVSS v3 base score across image vulnerabilities (0-10).",
		Type: TypeFloat, Category: "cve",
		ScopeApplicability: []string{"BUILD", "DEPLOY"},
	},
	{
		Name: "cve.kev_listed", Description: "Image contains a CISA KEV-listed CVE.",
		Type: TypeBool, Category: "cve",
		ScopeApplicability: []string{"BUILD", "DEPLOY", "RUNTIME"},
	},

	// --- container security context ---
	{
		Name: "container.securityContext.runAsNonRoot",
		Description: "Container runs as a non-root UID.",
		Type: TypeBool, Category: "securityContext",
		ScopeApplicability: []string{"DEPLOY", "RUNTIME"},
	},
	{
		Name: "container.securityContext.privileged",
		Description: "Container is privileged (--privileged / privileged: true).",
		Type: TypeBool, Category: "securityContext",
		ScopeApplicability: []string{"DEPLOY", "RUNTIME"},
	},
	{
		Name: "container.securityContext.readOnlyRootFilesystem",
		Description: "Container has a read-only root filesystem.",
		Type: TypeBool, Category: "securityContext",
		ScopeApplicability: []string{"DEPLOY", "RUNTIME"},
	},
	{
		Name: "container.securityContext.allowPrivilegeEscalation",
		Description: "Container allows privilege escalation (default: true).",
		Type: TypeBool, Category: "securityContext",
		ScopeApplicability: []string{"DEPLOY", "RUNTIME"},
	},
	{
		Name: "container.securityContext.capabilities.added",
		Description: "Linux capabilities added beyond the K8s default set.",
		Type: TypeString, Category: "securityContext",
		ScopeApplicability: []string{"DEPLOY", "RUNTIME"},
	},

	// --- resources ---
	{
		Name: "container.resources.limits.cpu",
		Description: "CPU limit (millicores or core string).",
		Type: TypeString, Category: "resources",
		ScopeApplicability: []string{"DEPLOY"},
	},
	{
		Name: "container.resources.limits.memory",
		Description: "Memory limit (Mi/Gi).",
		Type: TypeString, Category: "resources",
		ScopeApplicability: []string{"DEPLOY"},
	},

	// --- pod / namespace ---
	{
		Name: "pod.hostNetwork", Description: "Pod requested host network namespace.",
		Type: TypeBool, Category: "pod",
		ScopeApplicability: []string{"DEPLOY", "RUNTIME"},
	},
	{
		Name: "pod.hostPID", Description: "Pod requested host PID namespace.",
		Type: TypeBool, Category: "pod",
		ScopeApplicability: []string{"DEPLOY", "RUNTIME"},
	},
	{
		Name: "namespace", Description: "Kubernetes namespace.",
		Type: TypeString, Category: "scope",
		ScopeApplicability: []string{"DEPLOY", "RUNTIME"},
	},
	{
		Name: "cluster", Description: "Cluster name (matches the cluster registered in Constellation).",
		Type: TypeString, Category: "scope",
		ScopeApplicability: []string{"DEPLOY", "RUNTIME"},
	},

	// --- runtime ---
	{
		Name: "process.name", Description: "Process name observed at runtime (eBPF/Falco).",
		Type: TypeString, Category: "runtime",
		ScopeApplicability: []string{"RUNTIME"},
	},
	{
		Name: "network.egress.domain",
		Description: "Egress DNS domain observed for a workload.",
		Type: TypeRegex, Category: "runtime",
		ScopeApplicability: []string{"RUNTIME"},
	},
}
