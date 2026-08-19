// This file defines the Constellation policy CRD family — the GitOps-managed,
// declarative representation of security policy that today lives only in Postgres
// (REST-only), which is the audit's GitOps gap.
//
// Each kind's Spec is a faithful mapping of the corresponding DB policy shape so
// the operator's reconciler can upsert a CR straight into the policy store and back:
//
//	ConstellationAdmissionRule  → policies row (category="admission")        — migration 006
//	ConstellationResponseRule   → response_rules row (E1 CLUSResponseRule)   — migration 103
//
// Every policy row is org-scoped, so every Spec carries an explicit OrgID. The kinds
// are Cluster-scoped (like ConstellationCluster) because Constellation policy is scoped
// to a Constellation org, not a Kubernetes namespace.
//
// The ConstellationGroup and ConstellationNetworkRule kinds (P0-08) live in group_types.go: they
// mirror the stored, org-scoped groups / group_rule_edges rows (the NeuVector NvSecurityRule
// segmentation surface). pkg/netpolicy remains a flow-driven *generator* of NetworkPolicy YAML, but
// the group→group edge that seeds it is itself a durable row, so it does round-trip as a CRD.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Policy condition types reported on every policy CR's Status.
const (
	// ConditionSynced is True once the CR has been reconciled into the policy store
	// at the CR's current generation, False (with a reason) while it is pending or drifted.
	ConditionSynced = "Synced"
	// ConditionError is True when the most recent reconcile failed (e.g. validation
	// rejected the spec or the store write errored), carrying the failure in its Message.
	ConditionError = "Error"
)

// PolicyStatus is the shared observed state for the policy CR family. Conditions carry
// Synced / Error; ObservedGeneration is the .metadata.generation the controller last
// reconciled, so clients can detect a spec change that has not yet been applied.
type PolicyStatus struct {
	// Phase is a short human-readable summary ("Synced", "Error", "Pending").
	Phase string `json:"phase,omitempty"`
	// Conditions follow the standard Kubernetes condition contract (type Synced/Error).
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// ObservedGeneration is the generation last reconciled into the policy store.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// LastAppliedOrgID is the org scope the controller last successfully wrote the
	// backing row under. Deletion keys the row delete on this value when .spec.orgID
	// can no longer be parsed (e.g. it was mutated to a non-UUID), so the backing row
	// is still removed instead of orphaned.
	LastAppliedOrgID string `json:"lastAppliedOrgID,omitempty"`
}

// ----------------------------- ConstellationAdmissionRule ---------------------------

// ConstellationAdmissionRuleSpec mirrors a `policies` row of category="admission"
// (migration 006). The rule's name is taken from .metadata.name (mirroring the table's
// UNIQUE(org_id, name)). SpecYAML carries the Constellation AdmissionRule document that
// pkg/admission.RuleFromYAML parses into an evaluator rule.
type ConstellationAdmissionRuleSpec struct {
	// OrgID is the Constellation org that owns this rule (the policies.org_id scope).
	OrgID string `json:"orgID"`

	// Description is the operator-facing summary (policies.description).
	Description string `json:"description,omitempty"`

	// Engine selects the admission engine the spec targets:
	// kyverno | opa-rego | k8s-cel | internal-waf | internal-dlp | internal-license.
	// Defaults to "kyverno" when empty.
	Engine string `json:"engine,omitempty"`

	// Mode is the enforcement mode: learn | monitor | enforce (policies.mode).
	Mode string `json:"mode"`

	// Enabled toggles whether the rule is loaded by the webhook (policies.enabled).
	Enabled bool `json:"enabled"`

	// SpecYAML is the AdmissionRule policy document (policies.spec_yaml), the same
	// YAML the REST policies API stores and the webhook hot-reloads.
	SpecYAML string `json:"specYAML"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=car
// +kubebuilder:printcolumn:name="Engine",type=string,JSONPath=`.spec.engine`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// ConstellationAdmissionRule is the Schema for the constellationadmissionrules API.
type ConstellationAdmissionRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConstellationAdmissionRuleSpec `json:"spec,omitempty"`
	Status            PolicyStatus                   `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConstellationAdmissionRuleList contains a list of ConstellationAdmissionRule.
type ConstellationAdmissionRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstellationAdmissionRule `json:"items"`
}

// ----------------------------- ConstellationResponseRule ----------------------------

// ResponseRuleCondition is one match clause, mirroring pkg/responserule.Condition and the
// response_rules.conditions JSONB element shape ({field, op, value}).
type ResponseRuleCondition struct {
	// Field names the event attribute (e.g. "process_name", "path", "severity").
	Field string `json:"field"`
	// Op is the comparator: eq | ne | contains | regex | gt | lt.
	Op string `json:"op"`
	// Value is the right-hand side, interpreted as a string or (gt/lt) a number.
	Value string `json:"value"`
}

// ResponseRuleAction is one structured action, mirroring pkg/responserule.Action and the
// response_rules.actions JSONB element shape ({type, params}).
type ResponseRuleAction struct {
	// Type is the action kind: quarantine | suppress_log | webhook | tag.
	Type string `json:"type"`
	// Params carries action-specific knobs (e.g. {"receiver":"sec-webhook"} for webhook).
	Params map[string]string `json:"params,omitempty"`
}

// ConstellationResponseRuleSpec mirrors a `response_rules` row (migration 103, the E1
// CLUSResponseRule-parity engine). The rule's name is taken from .metadata.name
// (mirroring UNIQUE(org_id, name)).
type ConstellationResponseRuleSpec struct {
	// OrgID is the Constellation org that owns this rule (response_rules.org_id scope).
	OrgID string `json:"orgID"`

	// Enabled toggles whether the rule participates in evaluation (response_rules.enabled).
	Enabled bool `json:"enabled"`

	// Priority orders evaluation: lower number = higher precedence (response_rules.priority).
	Priority int `json:"priority"`

	// EventType is the runtime event category that triggers the rule:
	// process | file | network | admission | scan (response_rules.event_type).
	EventType string `json:"eventType"`

	// Conditions are AND-combined match clauses (response_rules.conditions JSONB).
	Conditions []ResponseRuleCondition `json:"conditions,omitempty"`

	// Actions are the ordered effects produced when the rule fires (response_rules.actions JSONB).
	Actions []ResponseRuleAction `json:"actions"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=crr
// +kubebuilder:printcolumn:name="Event",type=string,JSONPath=`.spec.eventType`
// +kubebuilder:printcolumn:name="Priority",type=integer,JSONPath=`.spec.priority`
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// ConstellationResponseRule is the Schema for the constellationresponserules API.
type ConstellationResponseRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConstellationResponseRuleSpec `json:"spec,omitempty"`
	Status            PolicyStatus                  `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConstellationResponseRuleList contains a list of ConstellationResponseRule.
type ConstellationResponseRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstellationResponseRule `json:"items"`
}

// DeepCopy / DeepCopyInto / DeepCopyObject implementations live in zz_generated_deepcopy.go
// (hand-written in the same style as the ConstellationCluster methods).
