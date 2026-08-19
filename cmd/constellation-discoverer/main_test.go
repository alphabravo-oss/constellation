package main

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestImageLinkFieldsForRefsPreservesOrder(t *testing.T) {
	refs := []string{
		"registry.example.test/api:dev",
		"registry.example.test/worker@sha256:worker",
		"sha256:localonly",
	}
	normalized, repositories, tags, digests := imageLinkFieldsForRefs(refs, nil)
	if len(digests) != len(refs) || digests[0] != "" || digests[1] != "sha256:worker" || digests[2] != "sha256:localonly" {
		t.Fatalf("digests = %+v", digests)
	}
	if normalized[0] != "registry.example.test/api:dev" || normalized[1] != "registry.example.test/worker@sha256:worker" || normalized[2] != "sha256:localonly" {
		t.Fatalf("normalized = %+v", normalized)
	}
	if repositories[0] != "registry.example.test/api" || repositories[1] != "registry.example.test/worker" || repositories[2] != "" {
		t.Fatalf("repositories = %+v", repositories)
	}
	if tags[0] != "dev" || tags[1] != "" || tags[2] != "" {
		t.Fatalf("tags = %+v", tags)
	}
}

func TestPodStatusImageRefsIncludesRuntimeDigests(t *testing.T) {
	pod := corev1.Pod{Status: corev1.PodStatus{
		ContainerStatuses: []corev1.ContainerStatus{{
			Image:   "ghcr.io/acme/api:dev",
			ImageID: "docker-pullable://ghcr.io/acme/api@sha256:runtime",
		}, {
			Image:   "localhost/sidecar:dev",
			ImageID: "containerd://sha256:localonly",
		}},
	}}
	got := podStatusImageRefs(pod)
	want := []string{
		"ghcr.io/acme/api:dev",
		"ghcr.io/acme/api@sha256:runtime",
		"localhost/sidecar:dev",
		"sha256:localonly",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("podStatusImageRefs = %#v, want %#v", got, want)
	}
}

func TestDigestFromKubeImageID(t *testing.T) {
	cases := []struct {
		name    string
		imageID string
		want    string
	}{
		{"docker-pullable with repo@digest", "docker-pullable://docker.io/library/nginx@sha256:abc123", "sha256:abc123"},
		{"containerd bare digest", "containerd://sha256:def456", "sha256:def456"},
		{"cri-o bare digest", "cri-o://sha256:ff00", "sha256:ff00"},
		{"plain repo@digest no scheme", "docker.io/library/nginx@sha256:cafef00d", "sha256:cafef00d"},
		{"plain bare digest", "sha256:beef", "sha256:beef"},
		{"registry with port and digest", "registry.local:5000/team/api@sha256:9988", "sha256:9988"},
		{"not started yet", "", ""},
		{"no digest present (tag-ish)", "docker://docker.io/library/nginx:1.25", ""},
		{"empty digest body", "sha256:", ""},
		{"surrounding whitespace", "  containerd://sha256:aa11  ", "sha256:aa11"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := digestFromKubeImageID(tc.imageID); got != tc.want {
				t.Fatalf("digestFromKubeImageID(%q) = %q, want %q", tc.imageID, got, tc.want)
			}
		})
	}
}

func TestPodStatusImageDigestsMapsRefToDigest(t *testing.T) {
	pod := corev1.Pod{Status: corev1.PodStatus{
		ContainerStatuses: []corev1.ContainerStatus{{
			Image:   "ghcr.io/acme/api:dev",
			ImageID: "docker-pullable://ghcr.io/acme/api@sha256:runtime",
		}, {
			Image:   "localhost/sidecar:dev",
			ImageID: "containerd://sha256:localonly",
		}, {
			// Not started yet: no imageID, so no digest is recorded.
			Image:   "ghcr.io/acme/pending:dev",
			ImageID: "",
		}},
	}}
	got := podStatusImageDigests(pod)
	want := map[string]string{
		"ghcr.io/acme/api:dev":            "sha256:runtime",
		"ghcr.io/acme/api@sha256:runtime": "sha256:runtime",
		"localhost/sidecar:dev":           "sha256:localonly",
		"sha256:localonly":                "sha256:localonly",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("podStatusImageDigests = %#v, want %#v", got, want)
	}
}

func TestImageLinkFieldsForRefsUsesResolvedDigest(t *testing.T) {
	refs := []string{
		"ghcr.io/acme/api:dev",                // tag-only spec ref; digest comes from runtime
		"ghcr.io/acme/worker@sha256:embedded", // ref already carries its own digest
		"ghcr.io/acme/none:dev",               // no runtime digest available -> stays empty
	}
	resolved := map[string]string{
		"ghcr.io/acme/api:dev": "sha256:runtime",
		// Even if a resolved digest existed for the worker, the embedded one wins.
		"ghcr.io/acme/worker@sha256:embedded": "sha256:other",
	}
	_, _, _, digests := imageLinkFieldsForRefs(refs, resolved)
	if digests[0] != "sha256:runtime" {
		t.Fatalf("tag ref digest = %q, want sha256:runtime", digests[0])
	}
	if digests[1] != "sha256:embedded" {
		t.Fatalf("embedded digest = %q, want sha256:embedded", digests[1])
	}
	if digests[2] != "" {
		t.Fatalf("unresolved digest = %q, want empty", digests[2])
	}
}

func TestPodIPsDeduplicatesAndKeepsOrder(t *testing.T) {
	pod := corev1.Pod{Status: corev1.PodStatus{
		PodIP: "10.0.0.5",
		PodIPs: []corev1.PodIP{
			{IP: "10.0.0.5"}, // duplicate of primary, dropped
			{IP: "fd00::5"},
			{IP: ""}, // empty, dropped
		},
	}}
	got := podIPs(&pod)
	want := []string{"10.0.0.5", "fd00::5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("podIPs = %#v, want %#v", got, want)
	}
	if len(podIPs(&corev1.Pod{})) != 0 {
		t.Fatalf("podIPs on empty pod should be empty")
	}
}

func TestPodIPRecordable(t *testing.T) {
	withIP := corev1.PodStatus{PodIP: "10.0.0.9"}
	cases := []struct {
		name string
		pod  corev1.Pod
		want bool
	}{
		{"running with ip", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1"}}, true},
		{"running without ip yet", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}, true},
		{"pending without ip", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending}}, true},
		{"succeeded still holding ip", corev1.Pod{Status: func() corev1.PodStatus { s := withIP; s.Phase = corev1.PodSucceeded; return s }()}, true},
		{"failed still holding ip", corev1.Pod{Status: func() corev1.PodStatus { s := withIP; s.Phase = corev1.PodFailed; return s }()}, true},
		{"succeeded no ip", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}, false},
		{"unknown no ip", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodUnknown}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := podIPRecordable(&tc.pod); got != tc.want {
				t.Fatalf("podIPRecordable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPodUIDKeyFallsBackToNamespaceName(t *testing.T) {
	withUID := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "abc-123", Namespace: "payments", Name: "api-1"}}
	if got := podUIDKey(&withUID); got != "abc-123" {
		t.Fatalf("podUIDKey with uid = %q, want abc-123", got)
	}
	noUID := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api-1"}}
	if got := podUIDKey(&noUID); got != "payments/api-1" {
		t.Fatalf("podUIDKey fallback = %q, want payments/api-1", got)
	}
}

func TestPodFromDeleteObjHandlesTombstone(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-1"}}
	if got := podFromDeleteObj(pod); got != pod {
		t.Fatalf("podFromDeleteObj(pod) did not return the pod")
	}
	tomb := cache.DeletedFinalStateUnknown{Key: "ns/api-1", Obj: pod}
	if got := podFromDeleteObj(tomb); got != pod {
		t.Fatalf("podFromDeleteObj(tombstone) = %v, want the wrapped pod", got)
	}
	if got := podFromDeleteObj("not a pod"); got != nil {
		t.Fatalf("podFromDeleteObj(garbage) = %v, want nil", got)
	}
}

func TestWorkloadKeyForPodResolvesReplicaSetOwner(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "payments",
			OwnerReferences: []metav1.OwnerReference{{
				Kind: "ReplicaSet",
				Name: "api-7f8b9d",
			}},
		},
	}
	got, ok := workloadKeyForPod(pod, map[string]workloadKey{
		"payments/api-7f8b9d": {namespace: "payments", name: "api", kind: "Deployment"},
	})
	if !ok || got.namespace != "payments" || got.name != "api" || got.kind != "Deployment" {
		t.Fatalf("workload key = %+v ok=%v", got, ok)
	}
}
