package main

import (
	"context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPodInventoryPresenceIncludesIPLessAndTerminatedPods(t *testing.T) {
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pending"}, Status: corev1.PodStatus{Phase: corev1.PodPending}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "running"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{ImageID: "containerd://sha256:live"}}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "done"}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{ImageID: "containerd://sha256:old"}}}},
	}
	s := podInventoryPresence(pods)
	if len(s.Pods) != 3 || s.Pods["ns/pod/pending"] != "Pending" || s.Pods["ns/pod/done"] != "Succeeded" {
		t.Fatalf("pod states: %+v", s.Pods)
	}
	if len(s.ImageDigests) != 1 || !s.ImageDigests["sha256:live"] {
		t.Fatalf("active images: %+v", s.ImageDigests)
	}
}

func TestSyncPodsRejectsFailedAndIncompleteLists(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"forbidden", 403, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`},
		{"partial", 200, `{"kind":"PodList","apiVersion":"v1","metadata":{"continue":"next-page"},"items":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			// A nil pool ensures these paths cannot write an empty replacement snapshot.
			r := &reconciler{cs: client}
			if _, err := r.syncPods(context.Background()); err == nil {
				t.Fatal("untrusted inventory list accepted")
			}
		})
	}
}
