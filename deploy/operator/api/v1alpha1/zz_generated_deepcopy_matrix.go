// Hand-written DeepCopy methods for the B7 "broader CRD coverage" types
// (policy_matrix_types.go). Mirrors what controller-gen would emit, in the same style as
// zz_generated_deepcopy.go, so it can be regenerated cleanly when controller-gen is wired in.
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// ConstellationDLPSensor DeepCopy methods were removed in P0-01 along with the type.

// ---------------------------- ConstellationSignatureRule ----------------------------

// DeepCopyInto copies the receiver into out.
func (in *ConstellationSignatureRuleSpec) DeepCopyInto(out *ConstellationSignatureRuleSpec) {
	*out = *in
	if in.Patterns != nil {
		out.Patterns = make([]string, len(in.Patterns))
		copy(out.Patterns, in.Patterns)
	}
}

// DeepCopy creates a deep copy of ConstellationSignatureRuleSpec.
func (in *ConstellationSignatureRuleSpec) DeepCopy() *ConstellationSignatureRuleSpec {
	if in == nil {
		return nil
	}
	out := new(ConstellationSignatureRuleSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationSignatureRule) DeepCopyInto(out *ConstellationSignatureRule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy creates a deep copy of ConstellationSignatureRule.
func (in *ConstellationSignatureRule) DeepCopy() *ConstellationSignatureRule {
	if in == nil {
		return nil
	}
	out := new(ConstellationSignatureRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationSignatureRule) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationSignatureRuleList) DeepCopyInto(out *ConstellationSignatureRuleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ConstellationSignatureRule, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationSignatureRuleList.
func (in *ConstellationSignatureRuleList) DeepCopy() *ConstellationSignatureRuleList {
	if in == nil {
		return nil
	}
	out := new(ConstellationSignatureRuleList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationSignatureRuleList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// ----------------------------- ConstellationVulnProfile -----------------------------

// DeepCopyInto copies the receiver into out.
func (in *VulnProfileEntry) DeepCopyInto(out *VulnProfileEntry) {
	*out = *in
	if in.Images != nil {
		out.Images = make([]string, len(in.Images))
		copy(out.Images, in.Images)
	}
}

// DeepCopy creates a deep copy of VulnProfileEntry.
func (in *VulnProfileEntry) DeepCopy() *VulnProfileEntry {
	if in == nil {
		return nil
	}
	out := new(VulnProfileEntry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *VulnDomainScope) DeepCopyInto(out *VulnDomainScope) {
	*out = *in
	if in.Clusters != nil {
		out.Clusters = make([]string, len(in.Clusters))
		copy(out.Clusters, in.Clusters)
	}
	if in.Namespaces != nil {
		out.Namespaces = make([]string, len(in.Namespaces))
		copy(out.Namespaces, in.Namespaces)
	}
}

// DeepCopy creates a deep copy of VulnDomainScope.
func (in *VulnDomainScope) DeepCopy() *VulnDomainScope {
	if in == nil {
		return nil
	}
	out := new(VulnDomainScope)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationVulnProfileSpec) DeepCopyInto(out *ConstellationVulnProfileSpec) {
	*out = *in
	if in.Entries != nil {
		out.Entries = make([]VulnProfileEntry, len(in.Entries))
		for i := range in.Entries {
			in.Entries[i].DeepCopyInto(&out.Entries[i])
		}
	}
	in.DomainScope.DeepCopyInto(&out.DomainScope)
}

// DeepCopy creates a deep copy of ConstellationVulnProfileSpec.
func (in *ConstellationVulnProfileSpec) DeepCopy() *ConstellationVulnProfileSpec {
	if in == nil {
		return nil
	}
	out := new(ConstellationVulnProfileSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationVulnProfile) DeepCopyInto(out *ConstellationVulnProfile) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy creates a deep copy of ConstellationVulnProfile.
func (in *ConstellationVulnProfile) DeepCopy() *ConstellationVulnProfile {
	if in == nil {
		return nil
	}
	out := new(ConstellationVulnProfile)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationVulnProfile) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationVulnProfileList) DeepCopyInto(out *ConstellationVulnProfileList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ConstellationVulnProfile, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationVulnProfileList.
func (in *ConstellationVulnProfileList) DeepCopy() *ConstellationVulnProfileList {
	if in == nil {
		return nil
	}
	out := new(ConstellationVulnProfileList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationVulnProfileList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// ------------------------ ConstellationComplianceExemption (scaffold) ---------------

// DeepCopyInto copies the receiver into out.
func (in *ConstellationComplianceExemptionSpec) DeepCopyInto(out *ConstellationComplianceExemptionSpec) {
	*out = *in
}

// DeepCopy creates a deep copy of ConstellationComplianceExemptionSpec.
func (in *ConstellationComplianceExemptionSpec) DeepCopy() *ConstellationComplianceExemptionSpec {
	if in == nil {
		return nil
	}
	out := new(ConstellationComplianceExemptionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationComplianceExemption) DeepCopyInto(out *ConstellationComplianceExemption) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy creates a deep copy of ConstellationComplianceExemption.
func (in *ConstellationComplianceExemption) DeepCopy() *ConstellationComplianceExemption {
	if in == nil {
		return nil
	}
	out := new(ConstellationComplianceExemption)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationComplianceExemption) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationComplianceExemptionList) DeepCopyInto(out *ConstellationComplianceExemptionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ConstellationComplianceExemption, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationComplianceExemptionList.
func (in *ConstellationComplianceExemptionList) DeepCopy() *ConstellationComplianceExemptionList {
	if in == nil {
		return nil
	}
	out := new(ConstellationComplianceExemptionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationComplianceExemptionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
