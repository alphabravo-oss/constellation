package handler

import (
	"encoding/json"
	"strings"
)

var platformNamespaces = map[string]struct{}{
	"kube-system": {}, "kube-public": {}, "kube-node-lease": {},
	"constellation": {}, "constellation-system": {},
	"astronomer": {}, "astronomer-system": {}, "astronomer-delivery-system": {},
	"astronomer-monitoring": {}, "astronomer-trivy-system": {},
	"astronomer-logging": {}, "astronomer-ingress-nginx": {},
	"astronomer-cert-manager": {}, "astronomer-gatekeeper-system": {},
}

func PlatformRole(namespace string, labels map[string]string) string {
	if _, ok := platformNamespaces[strings.ToLower(strings.TrimSpace(namespace))]; ok {
		return "core"
	}
	partOf := strings.ToLower(strings.TrimSpace(labels["app.kubernetes.io/part-of"]))
	if partOf == "constellation" || partOf == "astronomer" || partOf == "astronomer-delivery" {
		return "core"
	}
	chart := strings.ToLower(strings.TrimSpace(labels["helm.sh/chart"]))
	if chart == "constellation" || strings.HasPrefix(chart, "constellation-") {
		return "core"
	}
	instance := strings.ToLower(strings.TrimSpace(labels["app.kubernetes.io/instance"]))
	managedBy := strings.ToLower(strings.TrimSpace(labels["app.kubernetes.io/managed-by"]))
	if managedBy == "helm" && (instance == "constellation" || instance == "astronomer") {
		return "core"
	}
	return ""
}

func PlatformRoleJSON(namespace string, labels json.RawMessage) string {
	var parsed map[string]string
	if err := json.Unmarshal(labels, &parsed); err != nil {
		return PlatformRole(namespace, nil)
	}
	return PlatformRole(namespace, parsed)
}
