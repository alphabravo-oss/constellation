package netpolicyapply

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
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
	for _, name := range []string{ns, own} {
		obj, err := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
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
	raw, _ := json.Marshal(obj)
	resource, data, err := ParseManifest(FlavorNative, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := (KubernetesResourceClient{Client: client, Protection: p}).Apply(ctx, resource, data); err != nil {
		t.Fatal(err)
	}
	effective, err := client.Resource(resource.GVR).Namespace(ns).Get(ctx, resource.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if effective.GetAnnotations()["constellation.alphabravo.io/system-communication"] != "preserved" {
		t.Fatal("effective protection annotation missing")
	}
	encoded, _ := json.Marshal(effective.Object)
	t.Log(string(encoded))
}
