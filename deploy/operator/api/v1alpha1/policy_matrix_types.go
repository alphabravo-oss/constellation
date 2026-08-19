// This file extends the Constellation policy CRD family (see policy_types.go) with the
// B7 "broader CRD coverage" kinds — the additional NeuVector-parity policy domains that
// today are REST/UI-only and therefore GitOps-invisible:
//
//	ConstellationSignatureRule     → runtime_dlp_rules row, category='signature'
//	                                 (migrations 044/046) — the DPI/WAF replacement surface
//	ConstellationVulnProfile       → vuln_profiles row (migration 022)          — vuln exception/profile
//	ConstellationComplianceExemption → compliance_exemptions row (migration 056) — SCAFFOLD, see below
//
// Like the existing policy kinds these are Cluster-scoped (Constellation policy is scoped to a
// Constellation org, not a Kubernetes namespace) and every Spec carries an explicit OrgID.
//
// PROVENANCE / OWNERSHIP GUARD. The policies/response_rules tables carry an explicit
// source='declarative' column (migrations 027/108) so the operator can tell the rows it owns
// from REST/UI-authored ones. The runtime_dlp_rules / vuln_profiles tables predate
// that convention and (per this subsystem's "no app migration" scope) are NOT altered here, so the
// operator keys ownership on the created_by column instead: every REST handler stamps
// created_by = the authenticated user, and the operator has no user identity, so a NULL created_by
// is the operator's declarative marker. See policydb.OwnedByOperator for the guard SQL and the
// TODO(matrix) note tracking a dedicated source column for full parity with the policies table.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: ConstellationDLPSensor (→ dlp_sensors) was removed in P0-01. The dlp_sensors
// table never reached the dataplane — no agent bundle, sync worker, or dp consumer read
// it — so the CRD was an orphan surface exactly like the WS-G G1 waf/groups CRUD. The
// authoritative enforced DLP path is runtime_dlp_rules (ConstellationSignatureRule owns
// the category='signature' slice; the code-level dlp.DefaultCatalog seeds the built-ins).

// ----------------------------- ConstellationSignatureRule ---------------------------

// ConstellationSignatureRuleSpec mirrors a `runtime_dlp_rules` row of category='signature'
// (migrations 044/046) — the DPI/L7 signature surface that replaced the removed WAF-groups CRUD
// (see internal/handler/waf_removed_test.go). Signatures are per-cluster: dp compiles the PCRE
// patterns into its hyperscan engine and fires threat events on payload matches. The rule name is
// taken from .metadata.name (mirroring UNIQUE(org_id, cluster_id, name)).
//
// SAFETY: Mode defaults to "monitor" (observe only). "enforce" (dp drops the connection) is
// explicit opt-in per the safety-by-default rule; it is never the default for a declarative rule.
type ConstellationSignatureRuleSpec struct {
	// OrgID is the Constellation org that owns this rule (runtime_dlp_rules.org_id scope).
	OrgID string `json:"orgID"`
	// ClusterID is the cluster whose dataplane loads this signature (runtime_dlp_rules.cluster_id).
	ClusterID string `json:"clusterID"`
	// Mode is the enforcement mode: monitor | enforce | disabled. Defaults to "monitor".
	Mode string `json:"mode,omitempty"`
	// Severity is the 1..9 threat severity dp stamps on a match (runtime_dlp_rules.severity).
	Severity int `json:"severity,omitempty"`
	// ApplyDir is the traffic direction inspected: 1=egress, 2=ingress, 3=both. Defaults to 3.
	ApplyDir int `json:"applyDir,omitempty"`
	// Patterns is the list of PCRE strings compiled into dp's engine (runtime_dlp_rules.patterns).
	Patterns []string `json:"patterns,omitempty"`
	// Description is the operator-facing summary (runtime_dlp_rules.description).
	Description string `json:"description,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=csig
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterID`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// ConstellationSignatureRule is the Schema for the constellationsignaturerules API.
type ConstellationSignatureRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConstellationSignatureRuleSpec `json:"spec,omitempty"`
	Status            PolicyStatus                   `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConstellationSignatureRuleList contains a list of ConstellationSignatureRule.
type ConstellationSignatureRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstellationSignatureRule `json:"items"`
}

// ----------------------------- ConstellationVulnProfile -----------------------------

// VulnProfileEntry is one exception/exemption rule inside a vulnerability profile,
// mirroring pkg/vulnprofile.Entry and the vuln_profiles.entries JSONB element shape.
type VulnProfileEntry struct {
	// Name is the entry identifier.
	Name string `json:"name"`
	// NameRegex optionally matches CVE ids (e.g. "CVE-2024-.*").
	NameRegex string `json:"nameRegex,omitempty"`
	// Images is a list of image-name globs the entry scopes to.
	Images []string `json:"images,omitempty"`
	// Action is the effect when matched: suppress | escalate.
	Action string `json:"action"`
	// DaysToFix is a remediation deadline in days (0 = none).
	DaysToFix int `json:"daysToFix,omitempty"`
	// SeverityFloor gates on severity: low | medium | high | critical.
	SeverityFloor string `json:"severityFloor,omitempty"`
	// ScoreFloor gates on a CVSS base score floor.
	ScoreFloor float64 `json:"scoreFloor,omitempty"`
	// Reserved is the NeuVector reserved selector: "" | "_recent".
	Reserved string `json:"reserved,omitempty"`
	// RecentDays is the window for Reserved="_recent".
	RecentDays int `json:"recentDays,omitempty"`
	// Comment is an optional human note.
	Comment string `json:"comment,omitempty"`
}

// VulnDomainScope narrows a profile to specific clusters/namespaces, mirroring
// pkg/vulnprofile.DomainScope and the vuln_profiles.domain_scope JSONB shape.
type VulnDomainScope struct {
	// Clusters is a list of cluster names the profile applies to (empty = all).
	Clusters []string `json:"clusters,omitempty"`
	// Namespaces is a list of namespaces the profile applies to (empty = all).
	Namespaces []string `json:"namespaces,omitempty"`
}

// ConstellationVulnProfileSpec mirrors a `vuln_profiles` row (migration 022), the vulnerability
// exception/exemption profile. The profile name is taken from .metadata.name
// (mirroring UNIQUE(org_id, name)).
type ConstellationVulnProfileSpec struct {
	// OrgID is the Constellation org that owns this profile (vuln_profiles.org_id scope).
	OrgID string `json:"orgID"`
	// Description is the operator-facing summary (vuln_profiles.description).
	Description string `json:"description,omitempty"`
	// Active toggles whether the profile is applied during vuln evaluation (vuln_profiles.active).
	// Defaults to false — a profile only alters scoring once explicitly activated.
	Active bool `json:"active,omitempty"`
	// Entries are the exception/exemption rules (vuln_profiles.entries JSONB).
	Entries []VulnProfileEntry `json:"entries,omitempty"`
	// DomainScope optionally narrows the profile (vuln_profiles.domain_scope JSONB).
	DomainScope VulnDomainScope `json:"domainScope,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cvp
// +kubebuilder:printcolumn:name="Active",type=boolean,JSONPath=`.spec.active`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// ConstellationVulnProfile is the Schema for the constellationvulnprofiles API.
type ConstellationVulnProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConstellationVulnProfileSpec `json:"spec,omitempty"`
	Status            PolicyStatus                 `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConstellationVulnProfileList contains a list of ConstellationVulnProfile.
type ConstellationVulnProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstellationVulnProfile `json:"items"`
}

// ----------------------------- ConstellationComplianceExemption ---------------------
//
// TODO(matrix): SCAFFOLD ONLY — the API type + CRD ship so compliance exemptions can be
// declared in GitOps, but the reconciler is not yet wired. Unlike the other policy kinds, the
// compliance_exemptions table (migration 056) has no (org_id, name) uniqueness to key an
// idempotent upsert on — its identity is (framework, control_id, cluster_id) with a mandatory
// expires_at and an approved_by (not created_by) actor column — so the name-keyed upsert +
// created_by ownership guard the other kinds use does not map cleanly. Finishing this domain
// needs either a name/source column on compliance_exemptions (an app migration, out of scope
// for this subsystem) or a synthetic-identity reconcile strategy. See policydb for the matching
// TODO(matrix).

// ConstellationComplianceExemptionSpec mirrors a `compliance_exemptions` row (migration 056):
// an approved, time-boxed waiver of a single compliance control.
type ConstellationComplianceExemptionSpec struct {
	// OrgID is the Constellation org that owns this exemption (compliance_exemptions.org_id).
	OrgID string `json:"orgID"`
	// ClusterID optionally scopes the exemption to one cluster (empty = org-wide).
	ClusterID string `json:"clusterID,omitempty"`
	// Framework is the compliance framework id (e.g. "cis-1.8", "pci-4.0").
	Framework string `json:"framework"`
	// ControlID is the specific control being exempted.
	ControlID string `json:"controlID"`
	// Reason is the required justification for the waiver.
	Reason string `json:"reason"`
	// ExpiresAt is the RFC3339 timestamp the exemption expires (required — waivers are time-boxed).
	ExpiresAt string `json:"expiresAt"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cce
// +kubebuilder:printcolumn:name="Framework",type=string,JSONPath=`.spec.framework`
// +kubebuilder:printcolumn:name="Control",type=string,JSONPath=`.spec.controlID`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// ConstellationComplianceExemption is the Schema for the constellationcomplianceexemptions API.
// TODO(matrix): reconciler pending — see the scaffold note above.
type ConstellationComplianceExemption struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConstellationComplianceExemptionSpec `json:"spec,omitempty"`
	Status            PolicyStatus                         `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConstellationComplianceExemptionList contains a list of ConstellationComplianceExemption.
type ConstellationComplianceExemptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstellationComplianceExemption `json:"items"`
}
