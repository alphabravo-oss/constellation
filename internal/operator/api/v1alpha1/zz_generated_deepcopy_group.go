// Hand-written DeepCopy methods for the P0-08 "policy-groups" types (group_types.go).
// Mirrors what controller-gen would emit, in the same style as zz_generated_deepcopy.go, so it
// can be regenerated cleanly when controller-gen is wired in.
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// ---------------------------- ConstellationGroup ----------------------------

// DeepCopyInto copies the receiver into out.
func (in *GroupCriterion) DeepCopyInto(out *GroupCriterion) {
	*out = *in
}

// DeepCopy creates a deep copy of GroupCriterion.
func (in *GroupCriterion) DeepCopy() *GroupCriterion {
	if in == nil {
		return nil
	}
	out := new(GroupCriterion)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationGroupSpec) DeepCopyInto(out *ConstellationGroupSpec) {
	*out = *in
	if in.Criteria != nil {
		out.Criteria = make([]GroupCriterion, len(in.Criteria))
		copy(out.Criteria, in.Criteria)
	}
}

// DeepCopy creates a deep copy of ConstellationGroupSpec.
func (in *ConstellationGroupSpec) DeepCopy() *ConstellationGroupSpec {
	if in == nil {
		return nil
	}
	out := new(ConstellationGroupSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationGroup) DeepCopyInto(out *ConstellationGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy creates a deep copy of ConstellationGroup.
func (in *ConstellationGroup) DeepCopy() *ConstellationGroup {
	if in == nil {
		return nil
	}
	out := new(ConstellationGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationGroupList) DeepCopyInto(out *ConstellationGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ConstellationGroup, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationGroupList.
func (in *ConstellationGroupList) DeepCopy() *ConstellationGroupList {
	if in == nil {
		return nil
	}
	out := new(ConstellationGroupList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationGroupList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// -------------------------- ConstellationNetworkRule --------------------------

// DeepCopyInto copies the receiver into out.
func (in *NetworkRulePort) DeepCopyInto(out *NetworkRulePort) {
	*out = *in
}

// DeepCopy creates a deep copy of NetworkRulePort.
func (in *NetworkRulePort) DeepCopy() *NetworkRulePort {
	if in == nil {
		return nil
	}
	out := new(NetworkRulePort)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationNetworkRuleSpec) DeepCopyInto(out *ConstellationNetworkRuleSpec) {
	*out = *in
	if in.Ports != nil {
		out.Ports = make([]NetworkRulePort, len(in.Ports))
		copy(out.Ports, in.Ports)
	}
}

// DeepCopy creates a deep copy of ConstellationNetworkRuleSpec.
func (in *ConstellationNetworkRuleSpec) DeepCopy() *ConstellationNetworkRuleSpec {
	if in == nil {
		return nil
	}
	out := new(ConstellationNetworkRuleSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationNetworkRule) DeepCopyInto(out *ConstellationNetworkRule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy creates a deep copy of ConstellationNetworkRule.
func (in *ConstellationNetworkRule) DeepCopy() *ConstellationNetworkRule {
	if in == nil {
		return nil
	}
	out := new(ConstellationNetworkRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationNetworkRule) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationNetworkRuleList) DeepCopyInto(out *ConstellationNetworkRuleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ConstellationNetworkRule, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationNetworkRuleList.
func (in *ConstellationNetworkRuleList) DeepCopy() *ConstellationNetworkRuleList {
	if in == nil {
		return nil
	}
	out := new(ConstellationNetworkRuleList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationNetworkRuleList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
