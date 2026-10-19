package netpolicyapply

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Opt-in helper for the external dataplane probe. The caller creates uniquely
// labeled disposable namespaces and owns cleanup. Never accepts an installation
// namespace or a namespace without the test nonce.
func TestApplyNativeCommunicationLive(t *testing.T) {
	ns, own, nonce := os.Getenv("CONSTELLATION_POLICY_PROOF_NAMESPACE"), os.Getenv("CONSTELLATION_POLICY_PROOF_PROTECTED_NAMESPACE"), os.Getenv("CONSTELLATION_POLICY_PROOF_NONCE")
	if ns == "" {
		t.Skip("disposable live policy fixture not requested")
	}
	if !strings.HasPrefix(ns, "constellation-policy-proof-") || !strings.HasPrefix(own, "constellation-policy-proof-") || ns == own || nonce == "" {
		t.Fatal("invalid disposable fixture scope")
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixtureNSUID := ""
	for _, name := range []string{ns, own} {
		obj, err := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if name == ns {
			fixtureNSUID = string(obj.GetUID())
		}
		if obj.GetLabels()["constellation.alphabravo.io/protection-proof"] != nonce {
			t.Fatal("fixture ownership mismatch")
		}
	}
	p, err := NewProtection(own, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj := map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": "communication-proof", "namespace": ns}, "spec": map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"proof-role": "client"}}, "policyTypes": []any{"Ingress", "Egress"}, "ingress": []any{}, "egress": []any{}}}
	flavor, err := ParseFlavor(os.Getenv("CONSTELLATION_POLICY_PROOF_FLAVOR"))
	if err != nil {
		t.Fatal(err)
	}
	switch flavor {
	case FlavorCilium:
		obj["apiVersion"] = "cilium.io/v2"
		obj["kind"] = "CiliumNetworkPolicy"
		obj["spec"] = map[string]any{
			"endpointSelector":  map[string]any{"matchLabels": map[string]any{"proof-role": "client"}},
			"enableDefaultDeny": map[string]any{"ingress": true, "egress": true},
			"ingress":           []any{}, "egress": []any{},
		}
	case FlavorCalico:
		obj["apiVersion"] = "projectcalico.org/v3"
		obj["kind"] = "GlobalNetworkPolicy"
		obj["metadata"] = map[string]any{"name": "communication-proof-" + nonce,
			"labels":          map[string]any{"constellation.alphabravo.io/protection-proof": nonce},
			"ownerReferences": []any{map[string]any{"apiVersion": "v1", "kind": "Namespace", "name": ns, "uid": fixtureNSUID}}}
		obj["spec"] = map[string]any{
			"namespaceSelector": fmt.Sprintf("kubernetes.io/metadata.name in {%q,%q}", ns, own),
			"selector":          "proof-role in {'client','protected'}", "order": float64(100),
			"types":   []any{"Ingress", "Egress"},
			"ingress": []any{map[string]any{"action": "Deny"}},
			"egress":  []any{map[string]any{"action": "Deny"}},
		}
	case FlavorNative:
	default:
		t.Fatal("live fixture flavor not implemented")
	}
	action := os.Getenv("CONSTELLATION_POLICY_PROOF_ACTION")
	if action != "" && action != "delete" && action != "reapply" {
		t.Fatal("unexpected fixture action")
	}
	if action == "reapply" {
		obj["metadata"].(map[string]any)["annotations"] = map[string]any{"constellation.alphabravo.io/protection-proof-update": nonce}
	}
	raw, _ := json.Marshal(obj)
	resource, data, err := ParseManifest(flavor, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	applyClient := client
	if account := os.Getenv("CONSTELLATION_POLICY_PROOF_SERVICE_ACCOUNT"); account != "" {
		if account != "system:serviceaccount:constellation-policy-proof-auth:constellation-network-policy-applier" {
			t.Fatal("unexpected fixture service account")
		}
		scoped := rest.CopyConfig(config)
		scoped.Impersonate = rest.ImpersonationConfig{UserName: account}
		applyClient, err = dynamic.NewForConfig(scoped)
		if err != nil {
			t.Fatal(err)
		}
	}
	if flavor == FlavorCalico {
		existing, err := resourceInterface(client, resource).Get(ctx, resource.Name, metav1.GetOptions{})
		if action == "delete" || action == "reapply" {
			if err != nil || existing.GetLabels()["constellation.alphabravo.io/protection-proof"] != nonce {
				t.Fatalf("global fixture policy ownership unavailable: %v", err)
			}
		} else if !apierrors.IsNotFound(err) {
			t.Fatalf("global fixture policy name is not unused: %v", err)
		}
	}
	if action == "delete" {
		if err := (KubernetesResourceClient{Client: applyClient, Protection: p}).Delete(ctx, resource); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := (KubernetesResourceClient{Client: applyClient, Protection: p}).Apply(ctx, resource, data); err != nil {
		t.Fatal(err)
	}
	effective, err := resourceInterface(client, resource).Get(ctx, resource.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if effective.GetAnnotations()["constellation.alphabravo.io/system-communication"] != "preserved" {
		t.Fatal("effective protection annotation missing")
	}
	encoded, _ := json.Marshal(effective.Object)
	t.Log(string(encoded))
}
