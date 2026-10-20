package main

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type workloadOwnerResolver struct{ client kubernetes.Interface }

func (r *workloadOwnerResolver) Parent(ctx context.Context, namespace string, owner metav1.OwnerReference) (*metav1.OwnerReference, error) {
	if owner.UID == "" {
		return nil, fmt.Errorf("controller owner UID is missing")
	}
	var object metav1.Object
	switch owner.Kind {
	case "ReplicaSet":
		rs, err := r.client.AppsV1().ReplicaSets(namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("resolve ReplicaSet: %w", err)
		}
		object = rs
	case "Job":
		job, err := r.client.BatchV1().Jobs(namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("resolve Job: %w", err)
		}
		object = job
	default:
		return nil, fmt.Errorf("unsupported owner kind")
	}
	if object.GetUID() != owner.UID {
		return nil, fmt.Errorf("controller owner UID mismatch")
	}
	parent := metav1.GetControllerOf(object)
	if parent != nil && ((owner.Kind == "ReplicaSet" && parent.Kind != "Deployment") || (owner.Kind == "Job" && parent.Kind != "CronJob")) {
		return nil, fmt.Errorf("unexpected controller ancestry")
	}
	return parent, nil
}
