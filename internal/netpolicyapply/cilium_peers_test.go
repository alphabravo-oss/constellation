package netpolicyapply

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestCiliumBackendIdentityBoundary(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mutate    func(*DependencySnapshot, *unstructured.Unstructured, *unstructured.Unstructured) []runtime.Object
		wantError bool
	}{
		{name: "required port only"},
		{name: "wrong owner", wantError: true, mutate: func(_ *DependencySnapshot, e, _ *unstructured.Unstructured) []runtime.Object {
			e.SetOwnerReferences(nil)
			return nil
		}},
		{name: "stale IP", wantError: true, mutate: func(_ *DependencySnapshot, e, _ *unstructured.Unstructured) []runtime.Object {
			_ = unstructured.SetNestedSlice(e.Object, []any{map[string]any{"ipv4": "10.0.0.99"}}, "status", "networking", "addressing")
			return nil
		}},
		{name: "unresolved identity", wantError: true, mutate: func(_ *DependencySnapshot, _, i *unstructured.Unstructured) []runtime.Object {
			delete(i.Object, "security-labels")
			return nil
		}},
		{name: "wrong namespace identity", wantError: true, mutate: func(_ *DependencySnapshot, _, i *unstructured.Unstructured) []runtime.Object {
			_ = unstructured.SetNestedStringMap(i.Object, map[string]string{"k8s:io.kubernetes.pod.namespace": "other"}, "security-labels")
			return nil
		}},
		{name: "unrelated shared identity", wantError: true, mutate: func(_ *DependencySnapshot, e, _ *unstructured.Unstructured) []runtime.Object {
			other := e.DeepCopy()
			other.SetName("unrelated")
			_ = unstructured.SetNestedSlice(other.Object, []any{map[string]any{"ipv4": "10.0.0.3"}}, "status", "networking", "addressing")
			return []runtime.Object{other}
		}},
		{name: "superset identity also matches", wantError: true, mutate: func(_ *DependencySnapshot, e, i *unstructured.Unstructured) []runtime.Object {
			other := e.DeepCopy()
			other.SetName("superset")
			_ = unstructured.SetNestedInt64(other.Object, 301, "status", "identity", "id")
			_ = unstructured.SetNestedSlice(other.Object, []any{map[string]any{"ipv4": "10.0.0.3"}}, "status", "networking", "addressing")
			identity := i.DeepCopy()
			identity.SetName("301")
			_ = unstructured.SetNestedField(identity.Object, "extra", "security-labels", "k8s:another")
			return []runtime.Object{other, identity}
		}},
		{name: "entire required identity cohort", mutate: func(s *DependencySnapshot, e, _ *unstructured.Unstructured) []runtime.Object {
			other := e.DeepCopy()
			other.SetName("replica")
			_ = unstructured.SetNestedSlice(other.Object, []any{map[string]any{"ipv4": "10.0.0.3"}}, "status", "networking", "addressing")
			s.Services = append(s.Services, ServicePeer{netip.MustParseAddr("10.0.0.3"), 18081, "TCP", false})
			return []runtime.Object{other}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := NewProtection("own", nil)
			pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "customer", UID: "pod-uid"}, Status: corev1.PodStatus{PodIP: "10.0.0.2"}}
			s := DependencySnapshot{Pods: []corev1.Pod{pod}, Services: []ServicePeer{{netip.MustParseAddr("10.0.0.2"), 18081, "TCP", false}}}
			endpoint := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "cilium.io/v2", "kind": "CiliumEndpoint", "metadata": map[string]any{"name": "backend", "namespace": "customer"}, "status": map[string]any{"identity": map[string]any{"id": int64(300)}, "networking": map[string]any{"addressing": []any{map[string]any{"ipv4": "10.0.0.2"}}}}}}
			endpoint.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID}})
			identity := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "cilium.io/v2", "kind": "CiliumIdentity", "metadata": map[string]any{"name": "300"}, "security-labels": map[string]any{"k8s:io.kubernetes.pod.namespace": "customer", "k8s:role": "dependency"}}}
			objects := []runtime.Object{endpoint, identity}
			if tc.mutate != nil {
				objects = append(objects, tc.mutate(&s, endpoint, identity)...)
			}
			dyn := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{{Group: "cilium.io", Version: "v2", Resource: "ciliumendpoints"}: "CiliumEndpointList", {Group: "cilium.io", Version: "v2", Resource: "ciliumidentities"}: "CiliumIdentityList"}, objects...)
			rules, err := p.ciliumPodPeers(context.Background(), dyn, s)
			if (err != nil) != tc.wantError {
				t.Fatalf("rules=%v err=%v", rules, err)
			}
			if tc.wantError {
				return
			}
			if len(rules) != 1 {
				t.Fatalf("wanted one backend port rule: %v", rules)
			}
			rule := rules[0].(map[string]any)
			ports := rule["toPorts"].([]any)[0].(map[string]any)["ports"].([]any)[0].(map[string]any)
			if ports["port"] != "18081" || ports["protocol"] != "TCP" {
				t.Fatalf("incorrect service boundary: %v", rule)
			}
			// The actual identity labels win over any arbitrary pod presentation labels.
			match := rule["toEndpoints"].([]any)[0].(map[string]any)["matchLabels"].(map[string]any)
			if match["k8s:role"] != "dependency" {
				t.Fatalf("identity not preserved: %v", match)
			}
		})
	}
}

func TestCiliumInventoryPaginationNeverAcceptsPartialSnapshot(t *testing.T) {
	for _, mode := range []string{"complete", "failed-page", "repeated-token"} {
		t.Run(mode, func(t *testing.T) {
			dyn := fake.NewSimpleDynamicClient(runtime.NewScheme())
			calls := 0
			dyn.PrependReactor("list", "ciliumendpoints", func(ktesting.Action) (bool, runtime.Object, error) {
				calls++
				if calls > 1 && mode == "failed-page" {
					return true, nil, errors.New("unavailable")
				}
				list := &unstructured.UnstructuredList{}
				if calls == 1 || mode == "repeated-token" {
					list.SetContinue("next")
				}
				return true, list, nil
			})
			_, err := listCiliumInventory(context.Background(), dyn, "ciliumendpoints")
			if (err == nil) != (mode == "complete") || calls != 2 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}
