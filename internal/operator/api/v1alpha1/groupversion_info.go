// Package v1alpha1 contains API Schema definitions for the constellation.alphabravo.io v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=constellation.alphabravo.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "constellation.alphabravo.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// addKnownTypes registers every kind served by this group-version (what
// controller-runtime's deprecated scheme.Builder used to do for us).
func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&ConstellationCluster{}, &ConstellationClusterList{},
		&ConstellationAdmissionRule{}, &ConstellationAdmissionRuleList{},
		&ConstellationResponseRule{}, &ConstellationResponseRuleList{},
		// B7 — broader CRD coverage (see policy_matrix_types.go).
		// (ConstellationDLPSensor was removed in P0-01 — orphan surface, never enforced.)
		&ConstellationSignatureRule{}, &ConstellationSignatureRuleList{},
		&ConstellationVulnProfile{}, &ConstellationVulnProfileList{},
		// P0-08 — policy-groups (NvSecurityRule/NvGroupDefinition parity; see group_types.go).
		&ConstellationGroup{}, &ConstellationGroupList{},
		&ConstellationNetworkRule{}, &ConstellationNetworkRuleList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
