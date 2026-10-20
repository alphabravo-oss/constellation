package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func sessionProtectionFixture() (responseAction, []corev1.Pod, []corev1.Service, []corev1.Node) {
	a := responseAction{ID: "session", Type: "kill_session", ContainerID: "full-container-id", WorkloadID: "apps/pod/web", Protocol: "tcp", SrcIP: "10.2.0.3", SrcPort: 12345, DstIP: "203.0.113.5", DstPort: 443}
	pods := []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web", UID: "pod-uid"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIPs: []corev1.PodIP{{IP: a.SrcIP}}, ContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://" + a.ContainerID, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "security", Name: "api"}, Status: corev1.PodStatus{PodIP: "10.2.0.9"}}}
	services := []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "security", Name: "api"}, Spec: corev1.ServiceSpec{ClusterIP: "10.43.0.9", ExternalIPs: []string{"203.0.113.9"}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}, Spec: corev1.ServiceSpec{ClusterIP: "10.43.0.1"}}}
	nodes := []corev1.Node{{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.1"}}}}}
	return a, pods, services, nodes
}

func TestSessionProtectionRefusesDisruptionBeforeConntrack(t *testing.T) {
	for _, scenario := range []string{"application", "protected source", "protected destination", "service", "external service", "api server", "node", "loopback", "spoofed workload", "spoofed container", "unbound tuple", "host network", "terminating", "not running", "no guard"} {
		t.Run(scenario, func(t *testing.T) {
			a, pods, services, nodes := sessionProtectionFixture()
			switch scenario {
			case "protected source":
				pods[0].Namespace = "security"
				a.WorkloadID = "security/pod/web"
			case "protected destination":
				a.DstIP = "10.2.0.9"
			case "service":
				a.DstIP = "10.43.0.9"
			case "external service":
				a.DstIP = "203.0.113.9"
			case "api server":
				a.DstIP = "10.43.0.1"
			case "node":
				a.DstIP = "192.0.2.1"
			case "loopback":
				a.DstIP = "127.0.0.1"
			case "spoofed workload":
				a.WorkloadID = "apps/pod/other"
			case "spoofed container":
				a.ContainerID = "full"
			case "unbound tuple":
				a.SrcIP = "10.2.0.77"
			case "host network":
				pods[0].Spec.HostNetwork = true
			case "terminating":
				now := metav1.Now()
				pods[0].DeletionTimestamp = &now
			case "not running":
				pods[0].Status.ContainerStatuses[0].State = corev1.ContainerState{}
			}
			calls := 0
			cfg := responderConfig{KillSessionEnabled: true, sessionProtection: func(_ context.Context, a responseAction) string {
				return sessionProtectionDecision(a, pods, services, nodes, newProtectedSet("security", nil))
			}, conntrackRun: func(context.Context, []string) ([]byte, error) { calls++; return nil, nil }}
			if scenario == "no guard" {
				cfg.sessionProtection = nil
			}
			result := newResponder(cfg).Execute(t.Context(), a)
			if scenario == "application" {
				if !result.Applied || calls != 1 {
					t.Fatalf("valid application session refused: %+v calls%d", result, calls)
				}
			} else if result.Applied || calls != 0 || result.Reason == "" {
				t.Fatalf("unsafe session dispatched: %+v calls%d", result, calls)
			}
		})
	}
}

func TestSessionProtectionRejectsIncompleteInventory(t *testing.T) {
	for _, resource := range []string{"pods", "services", "nodes"} {
		t.Run(resource, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			client.PrependReactor("list", resource, func(clienttesting.Action) (bool, runtime.Object, error) {
				meta := metav1.ListMeta{Continue: "another-page"}
				switch resource {
				case "pods":
					return true, &corev1.PodList{ListMeta: meta}, nil
				case "services":
					return true, &corev1.ServiceList{ListMeta: meta}, nil
				default:
					return true, &corev1.NodeList{ListMeta: meta}, nil
				}
			})
			a, _, _, _ := sessionProtectionFixture()
			if reason := sessionProtectionReader(client, newProtectedSet("security", nil))(t.Context(), a); reason != "session "+map[string]string{"pods": "pod", "services": "service", "nodes": "node"}[resource]+" inventory unavailable or incomplete" {
				t.Fatal(reason)
			}
		})
	}
}
