package main

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
)

func TestWorkloadResolverUsesHostContainerInventory(t *testing.T) {
	const fullID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	r := newWorkloadResolver()
	r.Update(hostscan.Containers{Items: []hostscan.Container{{
		ID:      fullID,
		Name:    "api",
		PodNS:   "platform",
		PodName: "api-7d9c",
	}}})

	got := r.Resolve(fullID[:12])
	if got.WorkloadID != "platform/pod/api-7d9c" {
		t.Fatalf("WorkloadID = %q", got.WorkloadID)
	}
	if got.Namespace != "platform" || got.Pod != "api-7d9c" {
		t.Fatalf("namespace/pod not carried: %+v", got)
	}
	if got.ContainerID != fullID {
		t.Fatalf("ContainerID = %q want %q", got.ContainerID, fullID)
	}
}

func TestWorkloadResolverFallsBackToNodeLocalContainer(t *testing.T) {
	got := newWorkloadResolver().Resolve("containerd://abcdef1234567890")
	if got.WorkloadID != "node-local/abcdef123456" {
		t.Fatalf("WorkloadID = %q", got.WorkloadID)
	}
	if got.ContainerID != "abcdef1234567890" {
		t.Fatalf("ContainerID = %q", got.ContainerID)
	}
}

// TestWorkloadResolverPodUIDDiscriminatesReusedContainerID covers #11: a
// container that carries a pod_uid but no pod name/namespace gets a node-local
// label suffixed with the pod_uid, so when the SAME container ID is later
// reused by a different pod generation the two do not alias onto one label.
func TestWorkloadResolverPodUIDDiscriminatesReusedContainerID(t *testing.T) {
	const cid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	r := newWorkloadResolver()

	// Generation A: container has a pod_uid but no ns/pod name yet.
	r.Update(hostscan.Containers{Items: []hostscan.Container{{
		ID:     cid,
		PodUID: "uid-aaaaaaaa-1111",
	}}})
	genA := r.Resolve(cid).WorkloadID
	if genA != "node-local/abcdef123456-uid-aaaa" {
		t.Fatalf("genA WorkloadID = %q", genA)
	}

	// Generation B: the runtime recycled the same container ID for a new pod.
	r.Update(hostscan.Containers{Items: []hostscan.Container{{
		ID:     cid,
		PodUID: "uid-bbbbbbbb-2222",
	}}})
	genB := r.Resolve(cid).WorkloadID
	if genB != "node-local/abcdef123456-uid-bbbb" {
		t.Fatalf("genB WorkloadID = %q", genB)
	}

	if genA == genB {
		t.Fatalf("reused container ID aliased two pod generations onto %q", genA)
	}
}

// TestWorkloadResolverResolvedPodUnchanged confirms the common case — a
// container with pod name/namespace — is untouched by the #11 discriminator
// (no pod_uid suffix), so StatefulSet-style stable names still aggregate.
func TestWorkloadResolverResolvedPodUnchanged(t *testing.T) {
	const cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	r := newWorkloadResolver()
	r.Update(hostscan.Containers{Items: []hostscan.Container{{
		ID:      cid,
		PodNS:   "platform",
		PodName: "db-0",
		PodUID:  "uid-cccccccc-3333",
	}}})
	if got := r.Resolve(cid).WorkloadID; got != "platform/pod/db-0" {
		t.Fatalf("WorkloadID = %q, want platform/pod/db-0", got)
	}
}
