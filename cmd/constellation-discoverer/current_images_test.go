package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestMergePodStatusImagesExcludesCompletedPods(t *testing.T) {
	key := workloadKey{namespace: "apps", name: "db", kind: "StatefulSet"}
	var pods []corev1.Pod
	for _, phase := range []corev1.PodPhase{corev1.PodRunning, corev1.PodPending, corev1.PodUnknown, corev1.PodSucceeded, corev1.PodFailed} {
		ref := "registry.example/db:" + string(phase)
		pods = append(pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.namespace, Name: string(phase), OwnerReferences: []metav1.OwnerReference{{Kind: key.kind, Name: key.name}}},
			Status:     corev1.PodStatus{Phase: phase, ContainerStatuses: []corev1.ContainerStatus{{Image: ref, ImageID: "containerd://sha256:" + string(phase)}, {Image: "registry.example/db:shared", ImageID: "containerd://sha256:" + string(phase)}}},
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/apps/v1/replicasets":
			_, _ = w.Write([]byte(`{"kind":"ReplicaSetList","apiVersion":"apps/v1","items":[]}`))
		case "/api/v1/pods":
			_ = json.NewEncoder(w).Encode(corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, Items: pods})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	r := &reconciler{cs: client}
	out := []workload{{images: []string{"registry.example/db:desired"}}}
	if err := r.mergePodStatusImages(context.Background(), out, map[workloadKey]int{key: 0}); err != nil {
		t.Fatal(err)
	}
	want := []string{"registry.example/db:desired", "registry.example/db:Running", "registry.example/db:shared", "registry.example/db:Pending", "registry.example/db:Unknown"}
	if !reflect.DeepEqual(out[0].images, want) {
		t.Fatalf("current images = %v, want %v", out[0].images, want)
	}
	if got := out[0].imageDigests["registry.example/db:shared"]; got != "sha256:Unknown" {
		t.Fatalf("completed pod replaced current digest: %s", got)
	}
	// Presence still records terminal pods so existing findings can be classified
	// as historical; the current-image filter must not erase those observations.
	presence := podInventoryPresence(pods)
	if len(presence.Pods) != len(pods) || presence.Pods["apps/pod/Succeeded"] != "Succeeded" || presence.Pods["apps/pod/Failed"] != "Failed" {
		t.Fatalf("historical presence lost: %+v", presence.Pods)
	}
}

func TestRuntimeConfigurationIDIsNotAnImageReference(t *testing.T) {
	ref := "ghcr.io/alphabravo-oss/constellation/admission@sha256:manifest"
	pod := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "admission", Image: ref}}}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "admission", Image: "sha256:config", ImageID: ref}}}}
	if got := podStatusImageRefs(pod); !reflect.DeepEqual(got, []string{ref}) {
		t.Fatalf("configuration ID became scan target: %v", got)
	}
	got := podStatusImageDigests(pod)
	if got[ref] != "sha256:manifest" || got["sha256:config"] != "" {
		t.Fatalf("configuration ID aliased to manifest: %v", got)
	}
	// Status may still describe the old running container during an image update.
	// The new desired spec must not replace its observed repository identity.
	pod.Spec.Containers[0].Image = "other.example/new:desired"
	if got := podStatusImageRefs(pod); !reflect.DeepEqual(got, []string{ref}) {
		t.Fatalf("desired image replaced observed runtime: %v", got)
	}
	if got := podStatusImageDigests(pod)["other.example/new:desired"]; got != "" {
		t.Fatalf("new spec got old runtime digest: %s", got)
	}
}

func TestRuntimeImageReferenceFallbackUsesContainerNameAndFamily(t *testing.T) {
	pod := corev1.Pod{Spec: corev1.PodSpec{
		Containers:          []corev1.Container{{Name: "sidecar", Image: "registry/sidecar:desired"}, {Name: "app", Image: "registry/app:desired"}},
		InitContainers:      []corev1.Container{{Name: "init", Image: "registry/init:desired"}},
		EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "registry/debug:desired"}}},
	}, Status: corev1.PodStatus{
		ContainerStatuses:          []corev1.ContainerStatus{{Name: "app", Image: "sha256:app-config", ImageID: "containerd://sha256:app-runtime"}, {Name: "missing", Image: "sha256:unknown", ImageID: "sha256:unknown"}, {Name: "init", Image: "sha256:wrong-family", ImageID: "sha256:wrong-family"}},
		InitContainerStatuses:      []corev1.ContainerStatus{{Name: "init", Image: "sha256:init-config", ImageID: "sha256:init-runtime"}},
		EphemeralContainerStatuses: []corev1.ContainerStatus{{Name: "debug", Image: "sha256:debug-config", ImageID: "sha256:debug-runtime"}},
	}}
	want := []string{"registry/init:desired", "registry/app:desired", "registry/debug:desired"}
	if got := podStatusImageRefs(pod); !reflect.DeepEqual(got, want) {
		t.Fatalf("name/family fallback = %v, want %v", got, want)
	}
	for _, ref := range podStatusImageRefs(pod) {
		if runtimeOnlyImageRef(ref) {
			t.Fatalf("non-pullable scan target %s", ref)
		}
	}
}
