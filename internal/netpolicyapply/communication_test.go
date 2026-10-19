package netpolicyapply

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func effectivePolicy(t *testing.T, kind string, spec map[string]any) map[string]any {
	t.Helper()
	p, _ := NewProtection("own", []string{"cnpg-system"})
	version := "networking.k8s.io/v1"
	if kind == "CiliumNetworkPolicy" {
		version = "cilium.io/v2"
	}
	if kind == "GlobalNetworkPolicy" {
		version = "projectcalico.org/v3"
	}
	obj := map[string]any{"apiVersion": version, "kind": kind, "metadata": map[string]any{"name": "test", "namespace": "customer"}, "spec": spec}
	raw, _ := json.Marshal(obj)
	ips, _ := fixtureDependencies(context.Background(), p)
	out, err := p.preserveCommunication(ManifestResource{Kind: kind}, raw, ips)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	return got["spec"].(map[string]any)
}
func TestNativeProtectionPreservesDirectionAndOriginalRules(t *testing.T) {
	original := map[string]any{"from": []any{map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "frontend"}}}}, "ports": []any{map[string]any{"port": float64(443)}}}
	for _, tc := range []struct {
		name            string
		spec            map[string]any
		ingress, egress bool
	}{
		{"implicit ingress", map[string]any{"podSelector": map[string]any{}, "ingress": []any{original}}, true, false},
		{"explicit egress", map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Egress"}, "egress": []any{}}, false, true},
		{"isolation", map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress", "Egress"}, "ingress": []any{}, "egress": []any{}}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := effectivePolicy(t, "NetworkPolicy", tc.spec)
			for _, d := range []string{"ingress", "egress"} {
				wanted := tc.ingress
				if d == "egress" {
					wanted = tc.egress
				}
				rules, _ := got[d].([]any)
				if !wanted {
					if len(rules) > 0 {
						t.Fatal("introduced unintended direction isolation", got)
					}
					continue
				}
				if len(rules) == 0 {
					t.Fatal("protected peer rules missing")
				}
				key := "from"
				if d == "egress" {
					key = "to"
				}
				peers := rules[0].(map[string]any)[key].([]any)
				if len(peers) != 4 {
					t.Fatalf("expected namespace and three exact address peers: %v", peers)
				}
				raw, _ := json.Marshal(peers[0])
				for _, ns := range []string{"own", "cnpg-system", "kube-system"} {
					if !strings.Contains(string(raw), ns) {
						t.Fatal("missing trusted namespace", ns)
					}
				}
				for _, v := range peers[1:] {
					cidr := v.(map[string]any)["ipBlock"].(map[string]any)["cidr"].(string)
					p := netip.MustParsePrefix(cidr)
					if p.Bits() != p.Addr().BitLen() {
						t.Fatal("broadened dependency address", cidr)
					}
				}
			}
			if tc.name == "implicit ingress" {
				rules := got["ingress"].([]any)
				a, _ := json.Marshal(original)
				b, _ := json.Marshal(rules[1])
				if string(a) != string(b) {
					t.Fatal("original application rule changed")
				}
			}
		})
	}
}
func TestCalicoProtectionPrecedesDenyAndKeepsIPFamiliesSeparate(t *testing.T) {
	got := effectivePolicy(t, "GlobalNetworkPolicy", map[string]any{"types": []any{"Egress"}, "egress": []any{map[string]any{"action": "Deny"}}})
	if _, exists := got["ingress"]; exists {
		t.Fatal("egress-only became ingress policy")
	}
	rules := got["egress"].([]any)
	if rules[len(rules)-1].(map[string]any)["action"] != "Deny" {
		t.Fatal("deny removed")
	}
	for _, r := range rules[:len(rules)-1] {
		if r.(map[string]any)["action"] != "Allow" {
			t.Fatal("protected allow must precede deny")
		}
	}
	for _, r := range rules[1 : len(rules)-1] {
		nets := r.(map[string]any)["destination"].(map[string]any)["nets"].([]any)
		if len(nets) != 1 {
			t.Fatal("mixed address families")
		}
	}
}
func TestCiliumDenyProtectionAndDefaultSemantics(t *testing.T) {
	p, _ := NewProtection("own", nil)
	ips, _ := fixtureDependencies(context.Background(), p)
	for _, tc := range []struct {
		cidr   string
		denied bool
	}{{"10.43.0.1/32", true}, {"192.0.2.0/24", true}, {"2001:db8::/64", true}, {"0.0.0.0/0", true}, {"198.51.100.4/32", false}} {
		spec := map[string]any{"egressDeny": []any{map[string]any{"toCIDR": []any{tc.cidr}}}}
		if err := guardCiliumDeny(spec, "egressDeny", "toCIDR", ips); (err != nil) != tc.denied {
			t.Fatalf("%s: %v", tc.cidr, err)
		}
		if !tc.denied {
			got := effectivePolicy(t, "CiliumNetworkPolicy", spec)
			if len(got["egress"].([]any)) != 3 {
				t.Fatal("deny direction omitted protected communication")
			}
		}
	}
	for _, rule := range []any{map[string]any{}, map[string]any{"toEntities": []any{"all"}}, map[string]any{"toEndpoints": []any{map[string]any{}}}} {
		if err := guardCiliumDeny(map[string]any{"egressDeny": []any{rule}}, "egressDeny", "toCIDR", ips); err == nil {
			t.Fatal("unproven deny allowed")
		}
	}
	got := effectivePolicy(t, "CiliumNetworkPolicy", map[string]any{"egress": []any{map[string]any{"toEndpoints": []any{map[string]any{"matchLabels": map[string]any{"app": "customer"}}}}}})
	if len(got["egress"].([]any)) != 4 {
		t.Fatal("missing protected namespace/entity/CIDR rules")
	}
	if containsRequirement(map[string]any{"egress": []any{map[string]any{"toRequires": []any{}}}}) != true {
		t.Fatal("requires constraint bypass")
	}
}
func TestDependencyFailureNeverWritesButAllowsRecoveryDelete(t *testing.T) {
	p, _ := NewProtection("own", nil)
	dyn := fake.NewSimpleDynamicClient(runtime.NewScheme())
	writes := 0
	dyn.PrependReactor("patch", "*", func(ktesting.Action) (bool, runtime.Object, error) {
		writes++
		return true, &unstructured.Unstructured{}, nil
	})
	client := KubernetesResourceClient{Client: dyn, Protection: p, Dependencies: func(context.Context, *Protection) ([]netip.Addr, error) {
		return nil, errors.New("inventory unavailable")
	}}
	resource, data, _ := ParseManifest(FlavorNative, "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: test\n  namespace: customer\nspec: {}")
	if err := client.Apply(context.Background(), resource, data); err == nil || writes != 0 {
		t.Fatal("unverified write")
	}
	if err := client.Delete(context.Background(), resource); err != nil {
		t.Fatal(err)
	}
}
func TestDependencyInventoryReadsAllPagesAndFailsOnIncompleteData(t *testing.T) {
	p, _ := NewProtection("own", nil)
	for _, fail := range []bool{false, true} {
		lists := map[schema.GroupVersionResource]string{}
		for _, kind := range []string{"pods", "services", "nodes"} {
			lists[schema.GroupVersionResource{Version: "v1", Resource: kind}] = map[string]string{"pods": "PodList", "services": "ServiceList", "nodes": "NodeList"}[kind]
		}
		dyn := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), lists)
		calls := 0
		dyn.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			calls++
			if calls == 1 {
				return true, &unstructured.UnstructuredList{Object: map[string]any{"metadata": map[string]any{"continue": "page2"}}}, nil
			}
			if fail {
				return true, nil, errors.New("second page failed")
			}
			pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "own", Name: "api"}, Status: corev1.PodStatus{PodIP: "10.42.1.2"}}
			m, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&pod)
			return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{Object: m}}}, nil
		})
		dyn.PrependReactor("list", "services", func(ktesting.Action) (bool, runtime.Object, error) {
			svc := corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"}, Spec: corev1.ServiceSpec{ClusterIP: "10.43.0.1"}}
			m, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&svc)
			return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{Object: m}}}, nil
		})
		dyn.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
			node := corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.10"}}}}
			m, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&node)
			return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{Object: m}}}, nil
		})
		ips, err := dependencyReader(dyn)(context.Background(), p)
		if fail {
			if err == nil {
				t.Fatal("partial snapshot accepted")
			}
			continue
		}
		if err != nil || len(ips) != 3 || calls != 2 {
			t.Fatalf("complete inventory: %v %v calls=%d", ips, err, calls)
		}
	}
}
