package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/alphabravocompany/constellation/pkg/quarantine"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"time"
)

// Parent resolves a ReplicaSet or Job by namespace/name and verifies its UID.
// It returns that object's controller owner, or nil for a standalone controller.
type WorkloadOwnerResolver interface {
	Parent(context.Context, string, metav1.OwnerReference) (*metav1.OwnerReference, error)
}

func (e *PolicyEngine) SetWorkloadOwners(r WorkloadOwnerResolver) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.WorkloadOwners = r
}

func matchQuarantine(ctx context.Context, req *admissionv1.AdmissionRequest, pod *corev1.Pod, snapshot *quarantine.Snapshot, resolver WorkloadOwnerResolver) (*quarantine.Hit, error) {
	var object struct {
		Metadata metav1.ObjectMeta `json:"metadata"`
	}
	if err := json.Unmarshal(req.Object.Raw, &object); err != nil {
		return nil, err
	}
	namespace := req.Namespace
	if namespace == "" {
		namespace = object.Metadata.Namespace
	}
	if namespace == "" {
		namespace = pod.Namespace
	}
	name := req.Name
	if name == "" {
		name = object.Metadata.Name
	}
	// Controller template metadata must not substitute for the admitted object's identity.
	target := pod.DeepCopy()
	target.Namespace = namespace
	target.Name = name
	target.OwnerReferences = object.Metadata.OwnerReferences
	if hit := snapshot.Match(target); hit != nil {
		return hit, nil
	}
	if !snapshot.HasWorkloads(namespace) {
		return nil, nil
	}
	if hit := workloadQuarantineHit(snapshot, namespace, req.Kind.Kind, name); hit != nil {
		return hit, nil
	}
	owner := metav1.GetControllerOf(&object.Metadata)
	if owner == nil {
		return nil, nil
	}
	if hit := workloadQuarantineHit(snapshot, namespace, owner.Kind, owner.Name); hit != nil {
		return hit, nil
	}
	if owner.Kind != "ReplicaSet" && owner.Kind != "Job" {
		return nil, nil
	}
	if resolver == nil {
		return nil, fmt.Errorf("controller owner resolver is not configured")
	}
	lookup, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	parent, err := resolver.Parent(lookup, namespace, *owner)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		return nil, nil
	}
	return workloadQuarantineHit(snapshot, namespace, parent.Kind, parent.Name), nil
}

func workloadQuarantineHit(snapshot *quarantine.Snapshot, namespace, kind, name string) *quarantine.Hit {
	for _, key := range []string{namespace + "/" + name, namespace + "/" + kind + "/" + name, namespace + "/" + strings.ToLower(kind) + "/" + name} {
		if hit := snapshot.WorkloadHit(key); hit != nil {
			return hit
		}
	}
	return nil
}
