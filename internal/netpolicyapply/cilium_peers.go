package netpolicyapply

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Default Cilium CIDRs do not select managed pods. Resolve required backend
// addresses through Cilium's actual security identities, not presentation labels.
// A selector must not grant its port to any other observed endpoint. All reads
// complete before writing; inventory failure leaves the policy unchanged.
func (p *Protection) ciliumPodPeers(ctx context.Context, client dynamic.Interface, snapshot DependencySnapshot) ([]any, error) {
	pods := map[netip.Addr]corev1.Pod{}
	for _, pod := range snapshot.Pods {
		for _, raw := range append([]corev1.PodIP{{IP: pod.Status.PodIP}}, pod.Status.PodIPs...) {
			ip, err := netip.ParseAddr(raw.IP)
			if err != nil {
				continue
			}
			pods[ip.Unmap()] = pod
		}
	}
	required := []ServicePeer{}
	allowed := map[ServicePeer]bool{}
	for _, peer := range snapshot.Services {
		allowed[peer] = true
		if _, ok := pods[peer.Address]; ok && !peer.Node {
			required = append(required, peer)
		}
	}
	if len(required) == 0 {
		return nil, nil
	}
	endpoints, err := listCiliumInventory(ctx, client, "ciliumendpoints")
	if err != nil {
		return nil, err
	}
	identities, err := listCiliumInventory(ctx, client, "ciliumidentities")
	if err != nil {
		return nil, err
	}
	labels := map[string]map[string]string{}
	for _, identity := range identities {
		values, _, err := unstructured.NestedStringMap(identity.Object, "security-labels")
		if err != nil {
			return nil, fmt.Errorf("cilium identity labels unavailable: %w", err)
		}
		labels[identity.GetName()] = values
	}
	byPod := map[string]unstructured.Unstructured{}
	for _, endpoint := range endpoints {
		byPod[endpoint.GetNamespace()+"/"+endpoint.GetName()] = endpoint
	}
	rules := []any{}
	for _, peer := range required {
		pod := pods[peer.Address]
		endpoint, ok := byPod[pod.Namespace+"/"+pod.Name]
		if !ok {
			return nil, fmt.Errorf("cilium protected backend identity unavailable for %s/%s", pod.Namespace, pod.Name)
		}
		owned := false
		for _, owner := range endpoint.GetOwnerReferences() {
			if owner.APIVersion == "v1" && owner.Kind == "Pod" && owner.Name == pod.Name && pod.UID != "" && owner.UID == pod.UID {
				owned = true
			}
		}
		if !owned || !ciliumEndpointHasIP(endpoint, peer.Address) {
			return nil, fmt.Errorf("cilium protected backend ownership/address mismatch for %s/%s", pod.Namespace, pod.Name)
		}
		id, _, _ := unstructured.NestedInt64(endpoint.Object, "status", "identity", "id")
		selected := labels[strconv.FormatInt(id, 10)]
		if id < 256 || len(selected) == 0 || selected["k8s:io.kubernetes.pod.namespace"] != pod.Namespace {
			return nil, fmt.Errorf("cilium protected backend security labels unavailable for %s/%s", pod.Namespace, pod.Name)
		}
		// Cilium selectors also match identities with a superset of these labels.
		// Check every endpoint, not just endpoints sharing the numeric identity.
		for _, other := range endpoints {
			otherID, _, _ := unstructured.NestedInt64(other.Object, "status", "identity", "id")
			otherLabels := labels[strconv.FormatInt(otherID, 10)]
			if len(otherLabels) == 0 {
				return nil, fmt.Errorf("cilium endpoint identity inventory incomplete")
			}
			if !containsLabels(otherLabels, selected) || p.communicationNamespaces[other.GetNamespace()] {
				continue
			}
			ips := ciliumEndpointIPs(other)
			if len(ips) == 0 {
				return nil, fmt.Errorf("cilium matching endpoint addresses unavailable")
			}
			for _, ip := range ips {
				if !allowed[ServicePeer{ip, peer.Port, peer.Protocol, false}] {
					return nil, fmt.Errorf("cilium required backend identity also selects unrelated endpoint %s/%s on %s/%d", other.GetNamespace(), other.GetName(), peer.Protocol, peer.Port)
				}
			}
		}
		match := map[string]any{}
		for key, value := range selected {
			match[key] = value
		}
		rules = append(rules, map[string]any{"toEndpoints": []any{map[string]any{"matchLabels": match}}, "toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": strconv.Itoa(int(peer.Port)), "protocol": peer.Protocol}}}}})
	}
	return rules, nil
}

func containsLabels(values, required map[string]string) bool {
	for key, value := range required {
		got, ok := values[key]
		if !ok || got != value {
			return false
		}
	}
	return true
}
func ciliumEndpointIPs(endpoint unstructured.Unstructured) []netip.Addr {
	list, _, _ := unstructured.NestedSlice(endpoint.Object, "status", "networking", "addressing")
	result := []netip.Addr{}
	for _, raw := range list {
		pair, _ := raw.(map[string]any)
		for _, family := range []string{"ipv4", "ipv6"} {
			value, _ := pair[family].(string)
			if ip, err := netip.ParseAddr(value); err == nil {
				result = append(result, ip.Unmap())
			}
		}
	}
	return result
}
func ciliumEndpointHasIP(endpoint unstructured.Unstructured, ip netip.Addr) bool {
	for _, candidate := range ciliumEndpointIPs(endpoint) {
		if candidate == ip {
			return true
		}
	}
	return false
}
func listCiliumInventory(ctx context.Context, client dynamic.Interface, resource string) ([]unstructured.Unstructured, error) {
	result := []unstructured.Unstructured{}
	seen := map[string]bool{}
	token := ""
	for {
		page, err := client.Resource(schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: resource}).List(ctx, metav1.ListOptions{Limit: 500, Continue: token})
		if err != nil {
			return nil, fmt.Errorf("cilium protection %s inventory unavailable: %w", resource, err)
		}
		result = append(result, page.Items...)
		token = page.GetContinue()
		if token == "" {
			return result, nil
		}
		if seen[token] || len(seen) >= 1000 {
			return nil, fmt.Errorf("cilium protection %s inventory incomplete", resource)
		}
		seen[token] = true
	}
}
