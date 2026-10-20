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
	Addresses   []netip.Addr
	Services    []ServicePeer
	Pods        []corev1.Pod
	CiliumPeers []any
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
		pods := []corev1.Pod{}
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
						if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed && !pod.Spec.HostNetwork {
							pods = append(pods, pod)
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
								if !p.servicePortRequired(svc, port) {
									continue
								}
								if err := peer(ip, port.Port, string(port.Protocol)); err != nil {
									return empty, err
								}
							}
						}
						for _, port := range svc.Spec.Ports {
							if port.NodePort != 0 && p.servicePortRequired(svc, port) {
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
						// The special built-in API service is read by exact EndpointSlice identity below.
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
								if _, err := add(ip); err != nil {
									return empty, err
								}
								for _, port := range slice.Ports {
									if port.Port == nil {
										return empty, fmt.Errorf("network policy protection: unresolved protected endpoint port")
									}
									protocol := "TCP"
									if port.Protocol != nil {
										protocol = string(*port.Protocol)
									}
									if !p.backendPortRequired(svc, port) {
										continue
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
		// The API server publishes its own endpoints as the EndpointSlice named
		// "kubernetes" in "default" (the v1 Endpoints object is deprecated since 1.33).
		apiObject, err := client.Resource(schema.GroupVersionResource{Group: "discovery.k8s.io", Version: "v1", Resource: "endpointslices"}).Namespace("default").Get(ctx, "kubernetes", metav1.GetOptions{})
		if err != nil {
			return empty, fmt.Errorf("network policy protection: Kubernetes API endpoints unavailable: %w", err)
		}
		var api discoveryv1.EndpointSlice
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(apiObject.Object, &api); err != nil {
			return empty, err
		}
		apiEndpoints := 0
		for _, endpoint := range api.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			for _, address := range endpoint.Addresses {
				for _, port := range api.Ports {
					if port.Port == nil {
						continue
					}
					protocol := ""
					if port.Protocol != nil {
						protocol = string(*port.Protocol)
					}
					if err := peer(address, *port.Port, protocol); err != nil {
						return empty, err
					}
					apiEndpoints++
				}
			}
		}
		if apiEndpoints == 0 {
			return empty, fmt.Errorf("network policy protection: Kubernetes API endpoints empty")
		}
		result := DependencySnapshot{Pods: pods}
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

// Installation/admin-added service namespaces are explicit trust boundaries.
// Kubernetes core namespaces additionally expose DNS, not arbitrary proxy ports.
func (p *Protection) servicePortRequired(svc corev1.Service, port corev1.ServicePort) bool {
	if p.communicationNamespaces[svc.Namespace] || svc.Namespace == "default" && svc.Name == "kubernetes" {
		return true
	}
	return port.Port == 53 && (port.Protocol == "" || port.Protocol == corev1.ProtocolTCP || port.Protocol == corev1.ProtocolUDP)
}
func (p *Protection) backendPortRequired(svc corev1.Service, backend discoveryv1.EndpointPort) bool {
	if p.communicationNamespaces[svc.Namespace] {
		return true
	}
	for _, port := range svc.Spec.Ports {
		if !p.servicePortRequired(svc, port) {
			continue
		}
		protocol := corev1.ProtocolTCP
		if backend.Protocol != nil {
			protocol = *backend.Protocol
		}
		expected := port.Protocol
		if expected == "" {
			expected = corev1.ProtocolTCP
		}
		if protocol != expected {
			continue
		}
		name := ""
		if backend.Name != nil {
			name = *backend.Name
		}
		if name != "" && port.Name == name {
			return true
		}
		if name == "" && port.Name == "" && backend.Port != nil && port.TargetPort.StrVal == "" {
			target := port.TargetPort.IntVal
			if target == 0 {
				target = port.Port
			}
			if target == *backend.Port {
				return true
			}
		}
	}
	return false
}
