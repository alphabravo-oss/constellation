package main

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestPlatformComponentsUseEachContainersImageIdentity(t *testing.T) {
	spec := corev1.PodSpec{Containers: []corev1.Container{
		{Name: "controller", Image: "registry.k8s.io/ingress-nginx/controller:v1.15.1@sha256:" + strings.Repeat("a", 64)},
		{Name: "helper", Image: "rancher/klipper-lb:v0.4.17"},
		{Name: "sidecar", Image: "busybox:1.37"},
	}, InitContainers: []corev1.Container{{Name: "init", Image: "busybox:1.36"}}}
	got := componentsFromPodSpec("ingress-nginx", "ingress-nginx-controller", spec, "deployment")
	if len(got) != 1 || got[0].Name != "ingress-nginx" || got[0].Version != "v1.15.1" || got[0].Source != "ingress-nginx/ingress-nginx-controller" {
		t.Fatalf("unexpected evidence: %+v", got)
	}
	helper := componentsFromPodSpec("kube-system", "svclb-ingress-nginx-controller", corev1.PodSpec{Containers: spec.Containers[1:]}, "daemonset")
	if len(helper) != 0 {
		t.Fatalf("helper misidentified: %+v", helper)
	}
}

func TestPlatformRepositoryIdentity(t *testing.T) {
	for _, tc := range []struct{ image, want string }{
		{"rancher/mirrored-coredns-coredns:1.14.3", "coredns"},
		{"docker.io/rancher/mirrored-metrics-server:v0.8.1", "metrics-server"},
		{"quay.io/jetstack/cert-manager-controller:v1.20.2", "cert-manager"},
		{"quay.io/jetstack/cert-manager-cainjector:v1.20.2", "cert-manager-cainjector"},
		{"quay.io/jetstack/cert-manager-webhook:v1.20.2", "cert-manager-webhook"},
		{"traefik:v3.0.0", "traefik"},
		{"quay.io/cilium/cilium:v1.17.0", "cilium"},
		{"calico/node:v3.29.0", "calico"},
		{"ghcr.io/flannel-io/flannel:v0.26.0", "flannel"},
		{"registry.k8s.io/ingress-nginx/controller-helper:v1.2.3", ""},
		{"registry.k8s.io/ingress-nginx/controller/sidecar:v1.2.3", ""},
		{"nginx/nginx-ingress:3.7.0", ""},
		{"example.com:5000/app:cert-manager-v1.0", ""},
		{"example.com/cilium/cilium:v1.0", ""},
		{"not a valid image", ""},
	} {
		t.Run(tc.image, func(t *testing.T) {
			if got := platformComponentName(tc.image); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestPlatformComponentsDoNotInventVersions(t *testing.T) {
	for _, image := range []string{"coredns/coredns", "coredns/coredns:latest", "coredns/coredns@sha256:" + strings.Repeat("a", 64)} {
		got := componentsFromPodSpec("kube-system", "coredns", corev1.PodSpec{Containers: []corev1.Container{{Image: image}}}, "deployment")
		if len(got) != 0 {
			t.Fatalf("invented version for %s: %+v", image, got)
		}
	}
}
