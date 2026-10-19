package main

import (
	"context"
	"time"

	"github.com/alphabravocompany/constellation/internal/inventorypresence"
	corev1 "k8s.io/api/core/v1"
)

func podInventoryPresence(pods []corev1.Pod) inventorypresence.Snapshot {
	snapshot := inventorypresence.Snapshot{Pods: map[string]string{}, ImageDigests: map[string]bool{}}
	for _, pod := range pods {
		snapshot.Pods[pod.Namespace+"/pod/"+pod.Name] = string(pod.Status.Phase)
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, statuses := range [][]corev1.ContainerStatus{pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses, pod.Status.EphemeralContainerStatuses} {
			for _, status := range statuses {
				if digest := digestFromKubeImageID(status.ImageID); digest != "" {
					snapshot.ImageDigests[digest] = true
				}
			}
		}
	}
	return snapshot
}

func (r *reconciler) storeInventoryPresence(ctx context.Context, observed time.Time, pods []corev1.Pod) error {
	// syncPods uses a complete cluster-wide LIST. Do not derive absence from the
	// event stream, IP projection, namespace filters, or a partially processed list.
	ttl := 3 * r.staleAfter
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	return inventorypresence.Store(ctx, r.pool, r.orgID, r.clusterID, observed, observed.Add(ttl), podInventoryPresence(pods))
}

func (r *reconciler) storeWorkloadPresence(ctx context.Context, observed time.Time, workloads []workload) error {
	ttl := 3 * r.staleAfter
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	states := map[string]string{}
	for _, w := range workloads {
		state := "present"
		if w.scaledToZero {
			state = "scaled_to_zero"
		}
		states[w.namespace+"/"+w.kind+"/"+w.name] = state
	}
	return inventorypresence.StoreWorkloads(ctx, r.pool, r.orgID, r.clusterID, observed, observed.Add(ttl), states)
}
