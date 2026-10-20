// Hand-written DeepCopy methods for v1alpha1 types. Mirrors what controller-gen would emit,
// so it can be regenerated cleanly when controller-gen is wired into the build.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto copies the receiver into out.
func (in *AgentResources) DeepCopyInto(out *AgentResources) {
	*out = *in
}

// DeepCopy creates a deep copy of AgentResources.
func (in *AgentResources) DeepCopy() *AgentResources {
	if in == nil {
		return nil
	}
	out := new(AgentResources)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationClusterSpec) DeepCopyInto(out *ConstellationClusterSpec) {
	*out = *in
	if in.AgentResources != nil {
		in, out := &in.AgentResources, &out.AgentResources
		*out = new(AgentResources)
		(*in).DeepCopyInto(*out)
	}
	if in.ScannerReplicas != nil {
		v := *in.ScannerReplicas
		out.ScannerReplicas = &v
	}
	if in.AdmissionReplicas != nil {
		v := *in.AdmissionReplicas
		out.AdmissionReplicas = &v
	}
	if in.ScannerAutoscale != nil {
		v := *in.ScannerAutoscale
		out.ScannerAutoscale = &v
	}
}

// DeepCopy creates a deep copy of ConstellationClusterSpec.
func (in *ConstellationClusterSpec) DeepCopy() *ConstellationClusterSpec {
	if in == nil {
		return nil
	}
	out := new(ConstellationClusterSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationClusterStatus) DeepCopyInto(out *ConstellationClusterStatus) {
	*out = *in
	if in.LastHeartbeat != nil {
		out.LastHeartbeat = in.LastHeartbeat.DeepCopy()
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationClusterStatus.
func (in *ConstellationClusterStatus) DeepCopy() *ConstellationClusterStatus {
	if in == nil {
		return nil
	}
	out := new(ConstellationClusterStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationCluster) DeepCopyInto(out *ConstellationCluster) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy creates a deep copy of ConstellationCluster.
func (in *ConstellationCluster) DeepCopy() *ConstellationCluster {
	if in == nil {
		return nil
	}
	out := new(ConstellationCluster)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationCluster) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationClusterList) DeepCopyInto(out *ConstellationClusterList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ConstellationCluster, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationClusterList.
func (in *ConstellationClusterList) DeepCopy() *ConstellationClusterList {
	if in == nil {
		return nil
	}
	out := new(ConstellationClusterList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationClusterList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// ----------------------------- PolicyStatus -----------------------------------

// DeepCopyInto copies the receiver into out.
func (in *PolicyStatus) DeepCopyInto(out *PolicyStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopy creates a deep copy of PolicyStatus.
func (in *PolicyStatus) DeepCopy() *PolicyStatus {
	if in == nil {
		return nil
	}
	out := new(PolicyStatus)
	in.DeepCopyInto(out)
	return out
}

// ------------------------ ConstellationAdmissionRule --------------------------

// DeepCopyInto copies the receiver into out.
func (in *ConstellationAdmissionRuleSpec) DeepCopyInto(out *ConstellationAdmissionRuleSpec) {
	*out = *in
}

// DeepCopy creates a deep copy of ConstellationAdmissionRuleSpec.
func (in *ConstellationAdmissionRuleSpec) DeepCopy() *ConstellationAdmissionRuleSpec {
	if in == nil {
		return nil
	}
	out := new(ConstellationAdmissionRuleSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationAdmissionRule) DeepCopyInto(out *ConstellationAdmissionRule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy creates a deep copy of ConstellationAdmissionRule.
func (in *ConstellationAdmissionRule) DeepCopy() *ConstellationAdmissionRule {
	if in == nil {
		return nil
	}
	out := new(ConstellationAdmissionRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationAdmissionRule) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationAdmissionRuleList) DeepCopyInto(out *ConstellationAdmissionRuleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ConstellationAdmissionRule, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationAdmissionRuleList.
func (in *ConstellationAdmissionRuleList) DeepCopy() *ConstellationAdmissionRuleList {
	if in == nil {
		return nil
	}
	out := new(ConstellationAdmissionRuleList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationAdmissionRuleList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// ------------------------- ConstellationResponseRule --------------------------

// DeepCopyInto copies the receiver into out.
func (in *ResponseRuleCondition) DeepCopyInto(out *ResponseRuleCondition) {
	*out = *in
}

// DeepCopy creates a deep copy of ResponseRuleCondition.
func (in *ResponseRuleCondition) DeepCopy() *ResponseRuleCondition {
	if in == nil {
		return nil
	}
	out := new(ResponseRuleCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ResponseRuleAction) DeepCopyInto(out *ResponseRuleAction) {
	*out = *in
	if in.Params != nil {
		out.Params = make(map[string]string, len(in.Params))
		for k, v := range in.Params {
			out.Params[k] = v
		}
	}
}

// DeepCopy creates a deep copy of ResponseRuleAction.
func (in *ResponseRuleAction) DeepCopy() *ResponseRuleAction {
	if in == nil {
		return nil
	}
	out := new(ResponseRuleAction)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationResponseRuleSpec) DeepCopyInto(out *ConstellationResponseRuleSpec) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]ResponseRuleCondition, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	}
	if in.Actions != nil {
		out.Actions = make([]ResponseRuleAction, len(in.Actions))
		for i := range in.Actions {
			in.Actions[i].DeepCopyInto(&out.Actions[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationResponseRuleSpec.
func (in *ConstellationResponseRuleSpec) DeepCopy() *ConstellationResponseRuleSpec {
	if in == nil {
		return nil
	}
	out := new(ConstellationResponseRuleSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationResponseRule) DeepCopyInto(out *ConstellationResponseRule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy creates a deep copy of ConstellationResponseRule.
func (in *ConstellationResponseRule) DeepCopy() *ConstellationResponseRule {
	if in == nil {
		return nil
	}
	out := new(ConstellationResponseRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationResponseRule) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *ConstellationResponseRuleList) DeepCopyInto(out *ConstellationResponseRuleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ConstellationResponseRule, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a deep copy of ConstellationResponseRuleList.
func (in *ConstellationResponseRuleList) DeepCopy() *ConstellationResponseRuleList {
	if in == nil {
		return nil
	}
	out := new(ConstellationResponseRuleList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ConstellationResponseRuleList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
