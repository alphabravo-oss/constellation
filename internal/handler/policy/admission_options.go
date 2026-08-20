package policy

import (
	"net/http"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// Admission criteria catalog — the dropdown source for the NV-style admission rule builder
// (NeuVector's GET /v1/admission/options). Each entry names a criterion the constellation
// admission engine already enforces (see pkg/admission), and how its value is entered, so
// the UI builds rules from live options instead of hand-written YAML. Keys map 1:1 to the
// criteria the CreateAdmissionRule builder translates into an admissionRuleSpec.
type admissionCriterionOption struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	ValueType   string `json:"value_type"` // none | int | float | csv | severity | pss
	Placeholder string `json:"placeholder,omitempty"`
	Help        string `json:"help"`
}

// admissionCriteriaCatalog lists exactly the keys CreateAdmissionRule can translate. Keep
// the two in lockstep: a key here with no builder case would produce a rule that silently
// omits the criterion.
func admissionCriteriaCatalog() []admissionCriterionOption {
	return []admissionCriterionOption{
		{Key: "namespace", Label: "Namespace is one of", ValueType: "csv", Placeholder: "prod, staging", Help: "Scope the rule to these namespaces (blank = all)."},
		{Key: "allowed_registries", Label: "Registry not in allow-list", ValueType: "csv", Placeholder: "ghcr.io, docker.io/library", Help: "Deny images from registries outside this allow-list."},
		{Key: "disallow_latest_tag", Label: "Uses :latest tag", ValueType: "none", Help: "Deny images using the floating :latest tag."},
		{Key: "require_digest", Label: "Not pinned to a digest", ValueType: "none", Help: "Deny images that are not pinned to a content digest."},
		{Key: "run_as_privileged", Label: "Runs privileged", ValueType: "none", Help: "Deny pods that request a privileged security context."},
		{Key: "run_as_root", Label: "Runs as root", ValueType: "none", Help: "Deny pods that would run as UID 0 (require non-root)."},
		{Key: "read_only_rootfs", Label: "Writable root filesystem", ValueType: "none", Help: "Deny pods without a read-only root filesystem."},
		{Key: "host_network", Label: "Uses host network", ValueType: "none", Help: "Deny pods that share the host network namespace."},
		{Key: "host_pid", Label: "Uses host PID", ValueType: "none", Help: "Deny pods that share the host PID namespace."},
		{Key: "max_critical_cves", Label: "Critical CVEs over", ValueType: "int", Placeholder: "0", Help: "Deny if the image has more than N critical CVEs."},
		{Key: "max_high_cves", Label: "High CVEs over", ValueType: "int", Placeholder: "5", Help: "Deny if the image has more than N high CVEs."},
		{Key: "deny_cvss_at_score", Label: "Any CVE at CVSS score ≥", ValueType: "float", Placeholder: "9.0", Help: "Deny if any CVE has a CVSS base score at or above this value."},
		{Key: "denied_cves", Label: "Contains CVE id", ValueType: "csv", Placeholder: "CVE-2023-45853", Help: "Deny if any of these specific CVEs is present."},
		{Key: "max_allowed_severity", Label: "Worst severity over", ValueType: "severity", Help: "Deny images whose worst CVE exceeds this severity."},
		{Key: "require_fix_available", Label: "Has a fixable CVE with no fix", ValueType: "none", Help: "Deny if a CVE has no fix available."},
		{Key: "pss_level", Label: "Violates Pod Security Standard", ValueType: "pss", Help: "Deny pods that violate the chosen PSS level."},
	}
}

// AdmissionOptions serves the criteria catalog + the fixed enums the rule builder needs.
// GET /policies/admission/options
func (p *Policies) AdmissionOptions(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"criteria":   admissionCriteriaCatalog(),
		"rule_modes": []string{"monitor", "enforce"},
		"severities": []string{"low", "medium", "high", "critical"},
		"pss_levels": []string{"baseline", "restricted"},
	})
}
