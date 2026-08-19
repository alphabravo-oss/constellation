package main

import (
	"strings"
	"sync"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
)

type workloadIdentity struct {
	WorkloadID  string
	Namespace   string
	Pod         string
	PodUID      string
	ContainerID string
	// StartUnixNano is the container's creation time (unix nanoseconds) from the
	// runtime inventory. Zero when unknown. Used by the P0-4 zero-drift provenance
	// proxy: an executable whose ctime post-dates this is treated as drifted (not
	// from the original image). See procFileWrittenAfter.
	StartUnixNano int64
}

type workloadResolver struct {
	mu   sync.RWMutex
	byID map[string]workloadIdentity
}

func newWorkloadResolver() *workloadResolver {
	return &workloadResolver{byID: map[string]workloadIdentity{}}
}

func (r *workloadResolver) Update(snapshot hostscan.Containers) {
	next := make(map[string]workloadIdentity, len(snapshot.Items)*2)
	for _, c := range snapshot.Items {
		id := normalizeContainerID(c.ID)
		if id == "" {
			continue
		}
		ns := strings.TrimSpace(c.PodNS)
		pod := strings.TrimSpace(c.PodName)
		uid := strings.TrimSpace(c.PodUID)
		ident := workloadIdentity{
			WorkloadID:    workloadIDFromPod(ns, pod),
			Namespace:     ns,
			Pod:           pod,
			PodUID:        uid,
			ContainerID:   id,
			StartUnixNano: c.CreatedAt,
		}
		next[id] = ident
		if len(id) > 12 {
			next[id[:12]] = ident
		}
	}
	r.mu.Lock()
	r.byID = next
	r.mu.Unlock()
}

func (r *workloadResolver) Resolve(containerID string) workloadIdentity {
	id := normalizeContainerID(containerID)
	if id == "" {
		return workloadIdentity{}
	}
	if r != nil {
		r.mu.RLock()
		if ident, ok := r.byID[id]; ok {
			r.mu.RUnlock()
			return resolvedOrNodeLocal(ident)
		}
		if len(id) > 12 {
			if ident, ok := r.byID[id[:12]]; ok {
				r.mu.RUnlock()
				return resolvedOrNodeLocal(ident)
			}
		}
		r.mu.RUnlock()
	}
	// Not in the current snapshot, so we have no pod identity at all — only the
	// bare container ID.
	//
	// ALIASING RISK (#11): container IDs are reused across restarts once the
	// runtime GCs the old one (containerd/cri-o), so two DIFFERENT pods that
	// both fell out of the snapshot can collide on the same "node-local/<id>"
	// label and have their flows merged. We cannot disambiguate here — no
	// pod_uid is available for an unknown container — so we accept the risk and
	// keep the container-id fallback. When the container IS known (resolvedOrNodeLocal
	// below), the per-pod pod_uid discriminator prevents this collision.
	return workloadIdentity{WorkloadID: nodeLocalWorkloadID(id), ContainerID: id}
}

// resolvedOrNodeLocal returns the resolved "<ns>/pod/<name>" identity when the
// snapshot carried pod name/namespace. When it did not (non-k8s container, or a
// container whose pod labels were missing) the WorkloadID is empty; we then
// synthesize a node-local label. If a pod_uid is present we fold it in as a
// per-pod-generation discriminator (#11) so a container ID reused by a later
// pod generation does not alias onto the earlier one.
func resolvedOrNodeLocal(ident workloadIdentity) workloadIdentity {
	if ident.WorkloadID != "" {
		return ident
	}
	ident.WorkloadID = nodeLocalWorkloadIDDisc(ident.ContainerID, ident.PodUID)
	return ident
}

func normalizeContainerID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if i := strings.Index(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	id = strings.TrimPrefix(id, "cri-containerd-")
	id = strings.TrimPrefix(id, "containerd-")
	id = strings.TrimPrefix(id, "docker-")
	id = strings.TrimPrefix(id, "crio-")
	id = strings.TrimPrefix(id, "libpod-")
	id = strings.TrimPrefix(id, "podman-")
	id = strings.TrimSuffix(id, ".scope")
	return id
}

func workloadIDFromPod(namespace, pod string) string {
	namespace = strings.TrimSpace(namespace)
	pod = strings.TrimSpace(pod)
	if namespace == "" || pod == "" {
		return ""
	}
	return namespace + "/pod/" + pod
}

func nodeLocalWorkloadID(containerID string) string {
	return nodeLocalWorkloadIDDisc(containerID, "")
}

// nodeLocalWorkloadIDDisc builds "node-local/<container-id-prefix>", optionally
// suffixed with a per-pod-generation discriminator derived from pod_uid (#11).
// The suffix keeps two pods that reuse the same container ID (containerd/cri-o
// GC recycles IDs across restarts) from collapsing onto one label. When podUID
// is empty the bare container-id form is returned — see the ALIASING RISK note
// in Resolve.
func nodeLocalWorkloadIDDisc(containerID, podUID string) string {
	containerID = normalizeContainerID(containerID)
	if containerID == "" {
		return ""
	}
	if len(containerID) > 12 {
		containerID = containerID[:12]
	}
	label := "node-local/" + containerID
	if podUID = strings.TrimSpace(podUID); podUID != "" {
		if len(podUID) > 8 {
			podUID = podUID[:8]
		}
		label += "-" + podUID
	}
	return label
}
