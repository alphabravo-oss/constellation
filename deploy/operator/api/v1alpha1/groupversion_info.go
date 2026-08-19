// Package v1alpha1 contains API Schema definitions for the constellation.alphabravo.io v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=constellation.alphabravo.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "constellation.alphabravo.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(&ConstellationCluster{}, &ConstellationClusterList{})
	SchemeBuilder.Register(&ConstellationAdmissionRule{}, &ConstellationAdmissionRuleList{})
	SchemeBuilder.Register(&ConstellationResponseRule{}, &ConstellationResponseRuleList{})
	// B7 — broader CRD coverage (see policy_matrix_types.go).
	// (ConstellationDLPSensor was removed in P0-01 — orphan surface, never enforced.)
	SchemeBuilder.Register(&ConstellationSignatureRule{}, &ConstellationSignatureRuleList{})
	SchemeBuilder.Register(&ConstellationVulnProfile{}, &ConstellationVulnProfileList{})
	SchemeBuilder.Register(&ConstellationComplianceExemption{}, &ConstellationComplianceExemptionList{})
	// P0-08 — policy-groups (NvSecurityRule/NvGroupDefinition parity; see group_types.go).
	SchemeBuilder.Register(&ConstellationGroup{}, &ConstellationGroupList{})
	SchemeBuilder.Register(&ConstellationNetworkRule{}, &ConstellationNetworkRuleList{})
}
