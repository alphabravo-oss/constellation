// group_types.go extends the Constellation policy CRD family (see policy_types.go) with the
// P0-08 "policy-groups" kinds — the NeuVector NvSecurityRule/NvGroupDefinition parity surface
// that today is REST/UI-only and therefore GitOps-invisible:
//
//	ConstellationGroup       → groups row (migrations 023/031/088)          — workload selector + modes
//	ConstellationNetworkRule → group_rule_edges row (migration 121)         — group→group segmentation edge
//
// This supersedes the stale note in policy_types.go that declined a network-rule CRD on
// "flow-driven generator / no clean DB shape" grounds: groups and group_rule_edges are stored,
// org-scoped rows with a clean upsert identity, exactly like the policies/response_rules tables.
//
// Like the existing policy kinds these are Cluster-scoped (Constellation policy is scoped to a
// Constellation org, not a Kubernetes namespace) and every Spec carries an explicit OrgID.
//
// PROVENANCE / OWNERSHIP GUARD. The groups / group_rule_edges tables predate the source='declarative'
// column (migrations 027/108) and — per the operator-crds subsystem's "no app migration" scope — are
// not altered here, so the operator keys ownership on created_by IS NULL, exactly like the B7 matrix
// kinds (store_matrix.go): every REST handler stamps created_by = the authenticated user, and the
// operator has no user identity, so a NULL created_by marks an operator-authored (declarative) row.
// See policydb/store_group.go for the guard SQL. Members (groups.members) and edge expansion
// (runtime_policies) stay server-computed — the operator writes only the authored columns and the
// existing GroupMembershipReconciler recomputes membership and re-expands edges downstream.
//
// PROCESS/FILE PROFILE FIELDS are intentionally deferred (P0-08 task: "extend later with per-group
// process/file profile fields") — ProfileMode is carried (it drives member baseline mode) but the
// per-group process/file rule lists are not yet mirrored.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ----------------------------- ConstellationGroup -----------------------------------

// GroupCriterion is one (key, value, op) match clause on workload metadata, mirroring
// pkg/group.Criterion and the groups.criteria JSONB element shape. The json tags are the
// on-disk shape the membership evaluator reads.
type GroupCriterion struct {
	// Key names the workload field: "cluster" | "namespace" | "id" | "label.<name>".
	Key string `json:"key"`
	// Value is the right-hand side matched against the field.
	Value string `json:"value"`
	// Op is the comparator: eq | contains | regex (empty = eq).
	Op string `json:"op,omitempty"`
}

// ConstellationGroupSpec mirrors a `groups` row (migrations 023/031/088) — a NeuVector-style
// workload selector plus its policy/profile modes. The group name is taken from .metadata.name
// (mirroring UNIQUE(org_id, name)). Members are server-computed from Criteria and are NOT part of
// the spec (the GroupMembershipReconciler derives them, matching NeuVector's groupWorkloadJoin).
type ConstellationGroupSpec struct {
	// OrgID is the Constellation org that owns this group (groups.org_id scope).
	OrgID string `json:"orgID"`
	// Kind classifies the group: learned | ground | federated (groups.kind). Defaults to "ground"
	// (a user-defined ground-truth selector — the natural kind for a declaratively authored group).
	Kind string `json:"kind,omitempty"`
	// Comment is an operator-facing note (groups.comment).
	Comment string `json:"comment,omitempty"`
	// Criteria are the AND-combined match clauses (groups.criteria JSONB).
	Criteria []GroupCriterion `json:"criteria,omitempty"`
	// PolicyMode is the network-policy mode: discover | monitor | protect (groups.policy_mode).
	// SAFETY: defaults to "monitor" (observe, never block).
	PolicyMode string `json:"policyMode,omitempty"`
	// ProfileMode is the process/file-profile mode: discover | monitor | protect (groups.profile_mode).
	// It drives member workloads' process-baseline mode downstream. SAFETY: defaults to "monitor".
	ProfileMode string `json:"profileMode,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cgrp
// +kubebuilder:printcolumn:name="Kind",type=string,JSONPath=`.spec.kind`
// +kubebuilder:printcolumn:name="PolicyMode",type=string,JSONPath=`.spec.policyMode`
// +kubebuilder:printcolumn:name="ProfileMode",type=string,JSONPath=`.spec.profileMode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// ConstellationGroup is the Schema for the constellationgroups API.
type ConstellationGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConstellationGroupSpec `json:"spec,omitempty"`
	Status            PolicyStatus           `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConstellationGroupList contains a list of ConstellationGroup.
type ConstellationGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstellationGroup `json:"items"`
}

// ----------------------------- ConstellationNetworkRule -----------------------------

// NetworkRulePort is one L4 opening on a network-rule edge, mirroring pkg/netpolicy.PortSpec and
// the group_rule_edges.ports JSONB element shape. Port 0 means "any port" for that protocol.
type NetworkRulePort struct {
	// Protocol is the L4 protocol: TCP | UDP | SCTP | ICMP (empty = TCP).
	Protocol string `json:"protocol,omitempty"`
	// Port is the destination port; 0 means any port.
	Port int `json:"port,omitempty"`
}

// ConstellationNetworkRuleSpec mirrors a `group_rule_edges` row (migration 121) — a directed
// group→group network segmentation edge: members of FromGroup may initiate to members of ToGroup
// on Ports. It is Constellation's parity for NeuVector's NvSecurityRule ingress/egress rules
// (CLUSPolicyRule.From/To group edges). The backing row's identity is
// (org_id, cluster_id, from_group, to_group); .metadata.name is the CR handle only.
type ConstellationNetworkRuleSpec struct {
	// OrgID is the Constellation org that owns this edge (group_rule_edges.org_id scope).
	OrgID string `json:"orgID"`
	// ClusterID is the cluster the edge applies to (group_rule_edges.cluster_id; required).
	ClusterID string `json:"clusterID"`
	// FromGroup is the source group name (group_rule_edges.from_group).
	FromGroup string `json:"fromGroup"`
	// ToGroup is the destination group name (group_rule_edges.to_group).
	ToGroup string `json:"toGroup"`
	// Ports are the allowed L4 openings (group_rule_edges.ports JSONB); empty means "all ports".
	Ports []NetworkRulePort `json:"ports,omitempty"`
	// Mode is the enforcement mode: discover | monitor | protect (group_rule_edges.mode).
	// SAFETY: defaults to "monitor" so a freshly-authored edge is observed, never enforced,
	// until an operator explicitly promotes it to protect.
	Mode string `json:"mode,omitempty"`
	// Comment is an operator-facing note (group_rule_edges.comment).
	Comment string `json:"comment,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cnr
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterID`
// +kubebuilder:printcolumn:name="From",type=string,JSONPath=`.spec.fromGroup`
// +kubebuilder:printcolumn:name="To",type=string,JSONPath=`.spec.toGroup`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// ConstellationNetworkRule is the Schema for the constellationnetworkrules API.
type ConstellationNetworkRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConstellationNetworkRuleSpec `json:"spec,omitempty"`
	Status            PolicyStatus                 `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConstellationNetworkRuleList contains a list of ConstellationNetworkRule.
type ConstellationNetworkRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstellationNetworkRule `json:"items"`
}
