package netpolicyapply

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type ServicePeer struct {
	Address  netip.Addr
	Port     int32
	Protocol string
	Node     bool
}
type DependencySnapshot struct {
	Addresses []netip.Addr
	Services  []ServicePeer
}

// Addresses fence denies. Services grant only declared destination ports, never
// unrestricted access to all ports on a node/shared external address.
type DependencyReader func(context.Context, *Protection) (DependencySnapshot, error)

func dependencyReader(client dynamic.Interface) DependencyReader {
	return func(ctx context.Context, p *Protection) (DependencySnapshot, error) {
		empty := DependencySnapshot{}
		addresses, nodes := map[netip.Addr]bool{}, map[netip.Addr]bool{}
		peers := map[ServicePeer]bool{}
		services := map[string]corev1.Service{}
		add := func(raw string) (netip.Addr, error) {
			if raw == "" || raw == corev1.ClusterIPNone {
				return netip.Addr{}, nil
			}
			ip, err := netip.ParseAddr(raw)
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
				return netip.Addr{}, fmt.Errorf("invalid protected endpoint address %q", raw)
			}
			ip = ip.Unmap()
			addresses[ip] = true
			return ip, nil
		}
		peer := func(raw string, port int32, protocol string) error {
			ip, err := add(raw)
			if err != nil {
				return err
			}
			if !ip.IsValid() {
				return nil
			}
			if protocol == "" {
				protocol = "TCP"
			}
			if port < 1 || port > 65535 || (protocol != "TCP" && protocol != "UDP" && protocol != "SCTP") {
				return fmt.Errorf("invalid protected service port")
			}
			peers[ServicePeer{ip, port, protocol, nodes[ip]}] = true
			return nil
		}
		sawAPI := false
		for _, kind := range []string{"pods", "nodes", "services", "endpointslices"} {
			gvr := schema.GroupVersionResource{Version: "v1", Resource: kind}
			if kind == "endpointslices" {
				gvr.Group = "discovery.k8s.io"
			}
			token := ""
			seen := map[string]bool{}
			for {
				list, err := client.Resource(gvr).List(ctx, metav1.ListOptions{Limit: 500, Continue: token})
				if err != nil {
					return empty, fmt.Errorf("network policy protection: %s inventory unavailable: %w", kind, err)
				}
				for _, obj := range list.Items {
					switch kind {
					case "pods":
						var pod corev1.Pod
						if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &pod); err != nil {
							return empty, err
						}
						if !p.namespaces[pod.Namespace] && !pod.Spec.HostNetwork {
							continue
						}
						if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
							continue
						}
						if _, err := add(pod.Status.PodIP); err != nil {
							return empty, err
						}
						for _, ip := range pod.Status.PodIPs {
							if _, err := add(ip.IP); err != nil {
								return empty, err
							}
						}
					case "nodes":
						var node corev1.Node
						if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &node); err != nil {
							return empty, err
						}
						for _, a := range node.Status.Addresses {
							if a.Type != corev1.NodeInternalIP && a.Type != corev1.NodeExternalIP {
								continue
							}
							ip, err := add(a.Address)
							if err != nil {
								return empty, err
							}
							if ip.IsValid() {
								nodes[ip] = true
							}
						}
					case "services":
						var svc corev1.Service
						if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &svc); err != nil {
							return empty, err
						}
						api := svc.Namespace == "default" && svc.Name == "kubernetes"
						if !p.namespaces[svc.Namespace] && !api {
							continue
						}
						if api && svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
							sawAPI = true
						}
						services[svc.Namespace+"/"+svc.Name] = svc
						ips := append([]string{svc.Spec.ClusterIP}, svc.Spec.ClusterIPs...)
						ips = append(ips, svc.Spec.ExternalIPs...)
						hosts := []string{svc.Spec.ExternalName}
						for _, ingress := range svc.Status.LoadBalancer.Ingress {
							ips = append(ips, ingress.IP)
							hosts = append(hosts, ingress.Hostname)
						}
						for _, host := range hosts {
							if host == "" {
								continue
							}
							resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
							if err != nil || len(resolved) == 0 {
								return empty, fmt.Errorf("network policy protection: protected service DNS unavailable for %s/%s", svc.Namespace, svc.Name)
							}
							for _, ip := range resolved {
								ips = append(ips, ip.String())
							}
						}
						for _, ip := range ips {
							if _, err := add(ip); err != nil {
								return empty, err
							}
							for _, port := range svc.Spec.Ports {
								if err := peer(ip, port.Port, string(port.Protocol)); err != nil {
									return empty, err
								}
							}
						}
						for _, port := range svc.Spec.Ports {
							if port.NodePort != 0 {
								for ip := range nodes {
									if err := peer(ip.String(), port.NodePort, string(port.Protocol)); err != nil {
										return empty, err
									}
								}
							}
						}
					case "endpointslices":
						var slice discoveryv1.EndpointSlice
						if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &slice); err != nil {
							return empty, err
						}
						svc, selected := services[slice.Namespace+"/"+slice.Labels[discoveryv1.LabelServiceName]]
						if !selected {
							continue
						}
						if svc.Namespace == "default" && svc.Name == "kubernetes" {
							continue
						}
						// A freely supplied service-name label alone cannot grant an exception.
						// The special built-in API service is read by exact Endpoints identity below.
						owned := false
						for _, owner := range slice.OwnerReferences {
							if owner.APIVersion == "v1" && owner.Kind == "Service" && owner.Name == svc.Name && svc.UID != "" && owner.UID == svc.UID {
								owned = true
							}
						}
						if !owned {
							return empty, fmt.Errorf("network policy protection: protected service EndpointSlice ownership unavailable for %s/%s", slice.Namespace, slice.Name)
						}
						for _, endpoint := range slice.Endpoints {
							for _, ip := range endpoint.Addresses {
								for _, port := range slice.Ports {
									if port.Port == nil {
										return empty, fmt.Errorf("network policy protection: unresolved protected endpoint port")
									}
									protocol := "TCP"
									if port.Protocol != nil {
										protocol = string(*port.Protocol)
									}
									if err := peer(ip, *port.Port, protocol); err != nil {
										return empty, err
									}
								}
							}
						}
					}
				}
				token = list.GetContinue()
				if token == "" {
					break
				}
				if seen[token] || len(seen) >= 1000 {
					return empty, fmt.Errorf("network policy protection: incomplete %s pagination", kind)
				}
				seen[token] = true
			}
		}
		if !sawAPI || len(nodes) == 0 {
			return empty, fmt.Errorf("network policy protection: Kubernetes API or node addresses unavailable")
		}
		apiObject, err := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "endpoints"}).Namespace("default").Get(ctx, "kubernetes", metav1.GetOptions{})
		if err != nil {
			return empty, fmt.Errorf("network policy protection: Kubernetes API endpoints unavailable: %w", err)
		}
		var api corev1.Endpoints
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(apiObject.Object, &api); err != nil {
			return empty, err
		}
		apiEndpoints := 0
		for _, subset := range api.Subsets {
			for _, a := range subset.Addresses {
				for _, port := range subset.Ports {
					if err := peer(a.IP, port.Port, string(port.Protocol)); err != nil {
						return empty, err
					}
					apiEndpoints++
				}
			}
		}
		if apiEndpoints == 0 {
			return empty, fmt.Errorf("network policy protection: Kubernetes API endpoints empty")
		}
		result := DependencySnapshot{}
		for ip := range addresses {
			result.Addresses = append(result.Addresses, ip)
		}
		sort.Slice(result.Addresses, func(i, j int) bool { return result.Addresses[i].Less(result.Addresses[j]) })
		for endpoint := range peers {
			result.Services = append(result.Services, endpoint)
		}
		sort.Slice(result.Services, func(i, j int) bool {
			a, b := result.Services[i], result.Services[j]
			if a.Address != b.Address {
				return a.Address.Less(b.Address)
			}
			if a.Protocol != b.Protocol {
				return a.Protocol < b.Protocol
			}
			return a.Port < b.Port
		})
		return result, nil
	}
}
