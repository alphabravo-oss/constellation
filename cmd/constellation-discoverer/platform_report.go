package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/imageid"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const defaultRuntimeTokenFile = "/var/run/constellation/runtime-agent-token/token"

type platformFactsReportBody struct {
	ClusterID            string                    `json:"cluster_id"`
	ClusterName          string                    `json:"cluster_name,omitempty"`
	ObservedAt           time.Time                 `json:"observed_at"`
	Distro               string                    `json:"distro,omitempty"`
	KubernetesGitVersion string                    `json:"kubernetes_git_version,omitempty"`
	KubernetesMajor      string                    `json:"kubernetes_major,omitempty"`
	KubernetesMinor      string                    `json:"kubernetes_minor,omitempty"`
	PlatformProvider     string                    `json:"platform_provider,omitempty"`
	PlatformVersion      string                    `json:"platform_version,omitempty"`
	NodeCount            int                       `json:"node_count,omitempty"`
	KubeletVersions      map[string]int            `json:"kubelet_versions,omitempty"`
	Components           []platformReportComponent `json:"components,omitempty"`
}

type platformReportComponent struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type,omitempty"`
	Source    string `json:"source,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

func (r *reconciler) reportPlatformFacts(ctx context.Context) error {
	apiURL, token := discovererAPIConfig()
	if apiURL == "" || token == "" {
		r.log.Debug("platform facts report disabled", slog.String("reason", "api url or token missing"))
		return nil
	}
	serverVersion, err := r.cs.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("server version: %w", err)
	}

	nodeCount, kubeletVersions, provider := r.nodePlatformFacts(ctx)
	components := []platformReportComponent{{
		Name:      "kubernetes",
		Version:   serverVersion.GitVersion,
		Type:      "control-plane",
		Source:    "kubernetes-version",
		Namespace: "kubernetes",
	}}
	distro := platformDistro(serverVersion.GitVersion)
	if distro == "k3s" {
		components = append(components, platformReportComponent{
			Name:      "k3s",
			Version:   serverVersion.GitVersion,
			Type:      "distribution",
			Source:    "kubernetes-version",
			Namespace: "k3s",
		})
	}
	components = append(components, r.knownPlatformComponents(ctx)...)

	body := platformFactsReportBody{
		ClusterID:            r.clusterID.String(),
		ClusterName:          r.clusterName,
		ObservedAt:           time.Now().UTC(),
		Distro:               distro,
		KubernetesGitVersion: serverVersion.GitVersion,
		KubernetesMajor:      serverVersion.Major,
		KubernetesMinor:      serverVersion.Minor,
		PlatformProvider:     provider,
		PlatformVersion:      serverVersion.GitVersion,
		NodeCount:            nodeCount,
		KubeletVersions:      kubeletVersions,
		Components:           components,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, strings.TrimRight(apiURL, "/")+"/api/v1/platform-facts:report", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("platform facts report status=%d body=%s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (r *reconciler) nodePlatformFacts(ctx context.Context) (int, map[string]int, string) {
	nodes, err := r.cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		r.log.Warn("platform nodes", slog.String("err", err.Error()))
		return 0, map[string]int{}, ""
	}
	kubeletVersions := map[string]int{}
	providers := map[string]int{}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if version := strings.TrimSpace(node.Status.NodeInfo.KubeletVersion); version != "" {
			kubeletVersions[version]++
		}
		if provider := providerFromNode(*node); provider != "" {
			providers[provider]++
		}
	}
	return len(nodes.Items), kubeletVersions, dominantProvider(providers)
}

func (r *reconciler) knownPlatformComponents(ctx context.Context) []platformReportComponent {
	seen := map[string]bool{}
	out := []platformReportComponent{}
	add := func(component platformReportComponent) {
		component.Name = strings.ToLower(strings.TrimSpace(component.Name))
		component.Version = strings.TrimSpace(component.Version)
		component.Namespace = strings.ToLower(strings.TrimSpace(component.Namespace))
		if component.Name == "" || component.Version == "" {
			return
		}
		if component.Namespace == "" {
			component.Namespace = "kubernetes"
		}
		key := component.Namespace + "/" + component.Name + "@" + component.Version
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, component)
	}

	if deployments, err := r.cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range deployments.Items {
			for _, component := range componentsFromPodSpec(deployments.Items[i].Namespace, deployments.Items[i].Name, deployments.Items[i].Spec.Template.Spec, "deployment") {
				add(component)
			}
		}
	} else {
		r.log.Warn("platform deployments", slog.String("err", err.Error()))
	}
	if daemonSets, err := r.cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range daemonSets.Items {
			for _, component := range componentsFromDaemonSet(daemonSets.Items[i]) {
				add(component)
			}
		}
	} else {
		r.log.Warn("platform daemonsets", slog.String("err", err.Error()))
	}
	return out
}

func componentsFromDaemonSet(ds appsv1.DaemonSet) []platformReportComponent {
	return componentsFromPodSpec(ds.Namespace, ds.Name, ds.Spec.Template.Spec, "daemonset")
}

func componentsFromPodSpec(namespace, workloadName string, spec corev1.PodSpec, kind string) []platformReportComponent {
	out := []platformReportComponent{}
	for _, image := range podSpecImages(spec) {
		name := platformComponentName(namespace, workloadName, image)
		if name == "" {
			continue
		}
		version := imageVersion(image)
		if version == "" {
			continue
		}
		out = append(out, platformReportComponent{
			Name:      name,
			Version:   version,
			Type:      kind,
			Source:    namespace + "/" + workloadName,
			Namespace: componentNamespace(name),
		})
	}
	return out
}

func platformComponentName(namespace, workloadName, image string) string {
	value := strings.ToLower(namespace + "/" + workloadName + " " + image)
	switch {
	case strings.Contains(value, "coredns"):
		return "coredns"
	case strings.Contains(value, "ingress-nginx") || strings.Contains(value, "nginx-ingress"):
		return "ingress-nginx"
	case strings.Contains(value, "cert-manager-cainjector"):
		return "cert-manager-cainjector"
	case strings.Contains(value, "cert-manager-webhook"):
		return "cert-manager-webhook"
	case strings.Contains(value, "cert-manager"):
		return "cert-manager"
	case strings.Contains(value, "metrics-server"):
		return "metrics-server"
	case strings.Contains(value, "cilium"):
		return "cilium"
	case strings.Contains(value, "calico"):
		return "calico"
	case strings.Contains(value, "flannel"):
		return "flannel"
	case strings.Contains(value, "traefik"):
		return "traefik"
	default:
		return ""
	}
}

func componentNamespace(name string) string {
	switch name {
	case "cert-manager", "cert-manager-cainjector", "cert-manager-webhook":
		return "cert-manager"
	case "ingress-nginx":
		return "ingress-nginx"
	default:
		return "kubernetes"
	}
}

func imageVersion(ref string) string {
	identity := imageid.Parse(ref)
	tag := strings.TrimSpace(identity.Tag)
	if tag == "" || tag == "latest" {
		return ""
	}
	return tag
}

func platformDistro(gitVersion string) string {
	if strings.Contains(strings.ToLower(gitVersion), "+k3s") {
		return "k3s"
	}
	return "kubernetes"
}

func providerFromNode(node corev1.Node) string {
	providerID := strings.ToLower(strings.TrimSpace(node.Spec.ProviderID))
	switch {
	case strings.HasPrefix(providerID, "aws://"):
		return "aws"
	case strings.HasPrefix(providerID, "gce://"):
		return "gcp"
	case strings.HasPrefix(providerID, "azure://"):
		return "azure"
	case providerID != "":
		return "onprem"
	default:
		return ""
	}
}

func dominantProvider(values map[string]int) string {
	bestProvider := ""
	bestCount := 0
	for provider, count := range values {
		if count > bestCount || (count == bestCount && provider < bestProvider) {
			bestProvider = provider
			bestCount = count
		}
	}
	return bestProvider
}

func discovererAPIConfig() (apiURL, token string) {
	apiURL = strings.TrimSpace(os.Getenv("CONSTELLATION_API_URL"))
	token = firstNonEmptyString(
		os.Getenv("CONSTELLATION_DISCOVERER_TOKEN"),
		os.Getenv("RUNTIME_AGENT_TOKEN"),
	)
	if token == "" {
		for _, path := range []string{
			os.Getenv("CONSTELLATION_DISCOVERER_TOKEN_FILE"),
			os.Getenv("RUNTIME_AGENT_TOKEN_FILE"),
			defaultRuntimeTokenFile,
		} {
			token = readTrimmedFile(path)
			if token != "" {
				break
			}
		}
	}
	return strings.TrimRight(apiURL, "/"), token
}

func readTrimmedFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
