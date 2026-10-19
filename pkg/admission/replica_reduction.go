package admission

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// isReplicaReduction accepts only a full-object UPDATE of a known apps/v1
// controller whose spec changes solely by reducing replicas. Unknown fields
// participate in the comparison, so a future workload option cannot bypass
// policy through this path. Kubernetes still authorizes the update itself.
func isReplicaReduction(req *admissionv1.AdmissionRequest) bool {
	if req.Operation != admissionv1.Update || req.SubResource != "" || req.Kind.Group != "apps" || req.Kind.Version != "v1" {
		return false
	}
	resources := map[string]string{"Deployment": "deployments", "ReplicaSet": "replicasets", "StatefulSet": "statefulsets"}
	resource, ok := resources[req.Kind.Kind]
	if !ok || req.Resource.Group != "apps" || req.Resource.Version != "v1" || req.Resource.Resource != resource {
		return false
	}
	type controller struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		Metadata   metav1.ObjectMeta `json:"metadata"`
		Spec       map[string]any    `json:"spec"`
	}
	var old, next controller
	decode := func(raw []byte, out *controller) bool {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(out) != nil {
			return false
		}
		var trailing any
		return d.Decode(&trailing) == io.EOF
	}
	if !decode(req.OldObject.Raw, &old) || !decode(req.Object.Raw, &next) {
		return false
	}
	if old.APIVersion != "apps/v1" || next.APIVersion != old.APIVersion || old.Kind != req.Kind.Kind || next.Kind != old.Kind || old.Spec == nil || next.Spec == nil {
		return false
	}
	if old.Metadata.UID == "" || old.Metadata.UID != next.Metadata.UID || old.Metadata.Name != req.Name || next.Metadata.Name != req.Name || old.Metadata.Namespace != req.Namespace || next.Metadata.Namespace != req.Namespace || req.Name == "" || req.Namespace == "" {
		return false
	}
	if template, ok := old.Spec["template"].(map[string]any); !ok || len(template) == 0 {
		return false
	}
	count := func(spec map[string]any) (int64, bool) {
		value, exists := spec["replicas"]
		if !exists {
			return 1, true
		}
		number, ok := value.(json.Number)
		if !ok {
			return 0, false
		}
		n, err := number.Int64()
		return n, err == nil && n >= 0 && n <= 2147483647
	}
	before, validBefore := count(old.Spec)
	after, validAfter := count(next.Spec)
	if !validBefore || !validAfter || after >= before {
		return false
	}
	delete(old.Spec, "replicas")
	delete(next.Spec, "replicas")
	return reflect.DeepEqual(old.Spec, next.Spec)
}
