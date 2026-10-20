package netpolicyapply

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestProtectionAtKubernetesWriteBoundary(t *testing.T) {
	protection, err := NewProtection("custom-install", []string{"cnpg-system"})
	if err != nil {
		t.Fatal(err)
	}
	for _, flavor := range []Flavor{FlavorNative, FlavorCilium} {
		for _, ns := range []string{"custom-install", "kube-system", "kube-public", "kube-node-lease", "cnpg-system", "customer"} {
			t.Run(string(flavor)+"/"+ns, func(t *testing.T) {
				version, kind := "networking.k8s.io/v1", "NetworkPolicy"
				if flavor == FlavorCilium {
					version, kind = "cilium.io/v2", "CiliumNetworkPolicy"
				}
				resource, data, err := ParseManifest(flavor, "apiVersion: "+version+"\nkind: "+kind+"\nmetadata:\n  name: isolate\n  namespace: "+ns+"\nspec: {}")
				if err != nil {
					t.Fatal(err)
				}
				dyn := fake.NewSimpleDynamicClient(runtime.NewScheme())
				patches, deletes := 0, 0
				dyn.PrependReactor("patch", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
					patches++
					return true, &unstructured.Unstructured{}, nil
				})
				dyn.PrependReactor("delete", "*", func(a ktesting.Action) (bool, runtime.Object, error) { deletes++; return true, nil, nil })
				client := KubernetesResourceClient{Client: dyn, Protection: protection, Dependencies: fixtureDependencies}
				err = client.Apply(context.Background(), resource, data)
				if ns == "customer" {
					if err != nil || patches != 1 {
						t.Fatalf("application blocked: %v (%d writes)", err, patches)
					}
				} else if err == nil || patches != 0 {
					t.Fatalf("protected write reached Kubernetes: %v (%d writes)", err, patches)
				}
				if err := client.Delete(context.Background(), resource); err != nil || deletes != 1 {
					t.Fatalf("recovery delete blocked: %v", err)
				}
				client.Protection = nil
				before := patches
				if err := client.Apply(context.Background(), resource, data); err == nil || patches != before {
					t.Fatal("missing protection allowed write")
				}
			})
		}
	}
}

func TestGlobalPolicyProtectionPreservesApplicationSelector(t *testing.T) {
	t.Parallel()
	p, err := NewProtection("custom-install", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"", "team == 'payments' || team == 'orders'"} {
		obj := map[string]any{"apiVersion": "projectcalico.org/v3", "kind": "GlobalNetworkPolicy", "metadata": map[string]any{"name": "global"}, "spec": map[string]any{"selector": "app == 'api'", "namespaceSelector": selector, "ingress": []any{}}}
		raw, _ := json.Marshal(obj)
		resource, data, err := ParseManifest(FlavorCalico, string(raw))
		if err != nil {
			t.Fatal(err)
		}
		dyn := fake.NewSimpleDynamicClient(runtime.NewScheme())
		writes := 0
		dyn.PrependReactor("patch", "*", func(a ktesting.Action) (bool, runtime.Object, error) {
			writes++
			var got unstructured.Unstructured
			if err := json.Unmarshal(a.(ktesting.PatchAction).GetPatch(), &got.Object); err != nil {
				t.Fatal(err)
			}
			s, _, _ := unstructured.NestedString(got.Object, "spec", "namespaceSelector")
			for _, part := range []string{"has(kubernetes.io/metadata.name)", `"custom-install"`, `"kube-system"`, `"kube-public"`, `"kube-node-lease"`} {
				if !strings.Contains(s, part) {
					t.Fatalf("missing protection %s: %s", part, s)
				}
			}
			if selector != "" && !strings.HasPrefix(s, "("+selector+") && (") {
				t.Fatalf("original selector precedence lost: %s", s)
			}
			app, _, _ := unstructured.NestedString(got.Object, "spec", "selector")
			if app != "app == 'api'" {
				t.Fatal("application selector changed")
			}
			return true, &unstructured.Unstructured{}, nil
		})
		if err := (KubernetesResourceClient{Client: dyn, Protection: p, Dependencies: fixtureDependencies}).Apply(context.Background(), resource, data); err != nil || writes != 1 {
			t.Fatalf("global write: %v count %d", err, writes)
		}
	}
}

func TestProtectionRejectsInvalidConfigurationAndIdentity(t *testing.T) {
	t.Parallel()
	for _, own := range []string{"", "bad'name", "name with spaces"} {
		if _, err := NewProtection(own, nil); err == nil {
			t.Fatalf("accepted %q", own)
		}
	}
	if _, err := NewProtection("own", []string{"x' || all()"}); err == nil {
		t.Fatal("accepted invalid extra")
	}
	p, _ := NewProtection("own", nil)
	resource, data, _ := ParseManifest(FlavorNative, "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: isolate\n  namespace: own\nspec: {}")
	resource.Namespace = "customer"
	if _, err := p.Guard(resource, data); err == nil {
		t.Fatal("forged resource namespace bypassed protection")
	}
}

func TestGlobalPolicySelectorCannotEscapeProtection(t *testing.T) {
	t.Parallel()
	p, _ := NewProtection("own", nil)
	for _, selector := range []string{"all()) || all() || (all()", "name == 'unterminated", "name == 'a\\'"} {
		obj := map[string]any{"apiVersion": "projectcalico.org/v3", "kind": "GlobalNetworkPolicy", "metadata": map[string]any{"name": "global"}, "spec": map[string]any{"namespaceSelector": selector}}
		raw, _ := json.Marshal(obj)
		resource, data, _ := ParseManifest(FlavorCalico, string(raw))
		_, err := p.Guard(resource, data)
		if err == nil {
			t.Fatalf("accepted selector escape %q", selector)
		}
	}
}

func fixtureDependencies(context.Context, *Protection) (DependencySnapshot, error) {
	addresses := []netip.Addr{netip.MustParseAddr("10.43.0.1"), netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	return DependencySnapshot{Addresses: addresses, Services: []ServicePeer{{addresses[0], 443, "TCP", false}, {addresses[1], 6443, "TCP", true}, {addresses[2], 6443, "TCP", true}}}, nil
}
