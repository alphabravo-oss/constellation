package main

import (
	"context"
	"net"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Read authoritative cluster inventory immediately before conntrack deletion.
// User-supplied workload labels and the action's workload string alone never
// authorize a destructive action. Any failed/incomplete list refuses the action.
func newSessionProtection(protected *protectedSet) (func(context.Context, responseAction) string, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return sessionProtectionReader(client, protected), nil
}

func sessionProtectionReader(client kubernetes.Interface, protected *protectedSet) func(context.Context, responseAction) string {
	return func(ctx context.Context, action responseAction) string {
		pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil || pods.Continue != "" {
			return "session pod inventory unavailable or incomplete"
		}
		services, err := client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
		if err != nil || services.Continue != "" {
			return "session service inventory unavailable or incomplete"
		}
		// ExternalName and hostname-only load balancers otherwise have no IP in
		// the Service object and could evade protected endpoint matching.
		for i := range services.Items {
			service := &services.Items[i]
			if protected == nil || !protected.protectsNamespace(service.Namespace) && !(service.Namespace == "default" && service.Name == "kubernetes") {
				continue
			}
			hosts := []string{service.Spec.ExternalName}
			for _, ingress := range service.Status.LoadBalancer.Ingress {
				hosts = append(hosts, ingress.Hostname)
			}
			for _, host := range hosts {
				if host == "" {
					continue
				}
				ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if err != nil || len(ips) == 0 {
					return "protected service address resolution unavailable"
				}
				for _, ip := range ips {
					service.Spec.ExternalIPs = append(service.Spec.ExternalIPs, ip.String())
				}
			}
		}
		nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil || nodes.Continue != "" {
			return "session node inventory unavailable or incomplete"
		}
		return sessionProtectionDecision(action, pods.Items, services.Items, nodes.Items, protected)
	}
}

func sessionProtectionDecision(action responseAction, pods []corev1.Pod, services []corev1.Service, nodes []corev1.Node, protected *protectedSet) string {
	if protected == nil {
		return "session workload protection unavailable"
	}
	address := func(raw string) netip.Addr { ip, _ := netip.ParseAddr(strings.TrimSpace(raw)); return ip.Unmap() }
	src, dst := address(action.SrcIP), address(action.DstIP)
	for _, ip := range []netip.Addr{src, dst} {
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			return "protected or invalid session endpoint"
		}
	}
	blocked := map[netip.Addr]bool{}
	block := func(raw string) {
		if ip := address(raw); ip.IsValid() {
			blocked[ip] = true
		}
	}
	containerID := normalizeContainerID(action.ContainerID)
	matched := false
	for _, pod := range pods {
		ips := append([]corev1.PodIP(nil), pod.Status.PodIPs...)
		ips = append(ips, corev1.PodIP{IP: pod.Status.PodIP})
		isProtected := protected.protectsNamespace(pod.Namespace) || pod.Spec.HostNetwork
		for _, ip := range ips {
			if isProtected {
				block(ip.IP)
			}
		}
		if isProtected || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.UID == "" || workloadIDFromPod(pod.Namespace, pod.Name) != action.WorkloadID || containerID == "" {
			continue
		}
		statuses := append([]corev1.ContainerStatus(nil), pod.Status.ContainerStatuses...)
		statuses = append(statuses, pod.Status.InitContainerStatuses...)
		statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
		for _, status := range statuses {
			if status.State.Running == nil || normalizeContainerID(status.ContainerID) != containerID {
				continue
			}
			for _, ip := range ips {
				if addr := address(ip.IP); addr.IsValid() && (addr == src || addr == dst) {
					matched = true
				}
			}
		}
	}
	for _, node := range nodes {
		known := false
		for _, addr := range node.Status.Addresses {
			block(addr.Address)
			known = known || address(addr.Address).IsValid()
		}
		if !known {
			return "session node address inventory incomplete"
		}
	}
	for _, service := range services {
		if !protected.protectsNamespace(service.Namespace) && !(service.Namespace == "default" && service.Name == "kubernetes") {
			continue
		}
		block(service.Spec.ClusterIP)
		for _, ip := range service.Spec.ClusterIPs {
			block(ip)
		}
		for _, ip := range service.Spec.ExternalIPs {
			block(ip)
		}
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			block(ingress.IP)
		}
	}
	if blocked[src] || blocked[dst] {
		return "protected workload or host session endpoint"
	}
	if !matched {
		return "session container/workload identity is unavailable or does not own an endpoint"
	}
	return ""
}
