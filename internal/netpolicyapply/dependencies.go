package netpolicyapply

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// DependencyReader returns authoritative protected addresses immediately before a
// policy write. It must fail if inventory or protected service DNS is incomplete.
type DependencyReader func(context.Context, *Protection) ([]netip.Addr, error)

func dependencyReader(client dynamic.Interface) DependencyReader {
	return func(ctx context.Context, p *Protection) ([]netip.Addr, error) {
		addresses := map[netip.Addr]bool{}
		add := func(raw string) error {
			if raw == "" || raw == corev1.ClusterIPNone {
				return nil
			}
			ip, err := netip.ParseAddr(raw)
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("invalid protected endpoint address %q", raw)
			}
			addresses[ip.Unmap()] = true
			return nil
		}
		sawAPI, sawNode := false, false
		for _, kind := range []string{"pods", "services", "nodes"} {
			token := ""
			seen := map[string]bool{}
			for {
				list, err := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: kind}).List(ctx, metav1.ListOptions{Limit: 500, Continue: token})
				if err != nil {
					return nil, fmt.Errorf("network policy protection: %s inventory unavailable: %w", kind, err)
				}
				for _, obj := range list.Items {
					switch kind {
					case "pods":
						var pod corev1.Pod
						if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &pod); err != nil {
							return nil, err
						}
						if !p.namespaces[pod.Namespace] && !pod.Spec.HostNetwork {
							continue
						}
						if err := add(pod.Status.PodIP); err != nil {
							return nil, err
						}
						for _, ip := range pod.Status.PodIPs {
							if err := add(ip.IP); err != nil {
								return nil, err
							}
						}
					case "services":
						var svc corev1.Service
						if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &svc); err != nil {
							return nil, err
						}
						api := svc.Namespace == "default" && svc.Name == "kubernetes"
						if !p.namespaces[svc.Namespace] && !api {
							continue
						}
						if api && svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
							sawAPI = true
						}
						ips := append([]string{svc.Spec.ClusterIP}, svc.Spec.ClusterIPs...)
						ips = append(ips, svc.Spec.ExternalIPs...)
						hosts := []string{svc.Spec.ExternalName}
						for _, ingress := range svc.Status.LoadBalancer.Ingress {
							ips = append(ips, ingress.IP)
							hosts = append(hosts, ingress.Hostname)
						}
						for _, ip := range ips {
							if err := add(ip); err != nil {
								return nil, err
							}
						}
						for _, host := range hosts {
							if host == "" {
								continue
							}
							resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
							if err != nil || len(resolved) == 0 {
								return nil, fmt.Errorf("network policy protection: protected service DNS unavailable for %s/%s", svc.Namespace, svc.Name)
							}
							for _, ip := range resolved {
								if err := add(ip.String()); err != nil {
									return nil, err
								}
							}
						}
					case "nodes":
						var node corev1.Node
						if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &node); err != nil {
							return nil, err
						}
						for _, a := range node.Status.Addresses {
							if a.Type != corev1.NodeInternalIP && a.Type != corev1.NodeExternalIP {
								continue
							}
							if err := add(a.Address); err != nil {
								return nil, err
							}
							sawNode = true
						}
					}
				}
				token = list.GetContinue()
				if token == "" {
					break
				}
				if seen[token] || len(seen) >= 1000 {
					return nil, fmt.Errorf("network policy protection: incomplete %s pagination", kind)
				}
				seen[token] = true
			}
		}
		if !sawAPI || !sawNode {
			return nil, fmt.Errorf("network policy protection: Kubernetes API or node addresses unavailable")
		}
		result := make([]netip.Addr, 0, len(addresses))
		for ip := range addresses {
			result = append(result, ip)
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
		return result, nil
	}
}
