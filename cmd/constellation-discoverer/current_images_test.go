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
