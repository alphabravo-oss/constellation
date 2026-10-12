package handler

import (
	"encoding/json"
	"slices"
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

var platformPartOfValues = []string{"constellation", "astronomer", "astronomer-delivery"}
var platformInstanceValues = []string{"constellation", "astronomer"}

const platformChart = "constellation"
const platformManagedBy = "helm"

func PlatformRole(namespace string, labels map[string]string) string {
	if _, ok := platformNamespaces[strings.ToLower(strings.TrimSpace(namespace))]; ok {
		return "core"
	}
	partOf := strings.ToLower(strings.TrimSpace(labels["app.kubernetes.io/part-of"]))
	if slices.Contains(platformPartOfValues, partOf) {
		return "core"
	}
	chart := strings.ToLower(strings.TrimSpace(labels["helm.sh/chart"]))
	if chart == platformChart || strings.HasPrefix(chart, platformChart+"-") {
		return "core"
	}
	instance := strings.ToLower(strings.TrimSpace(labels["app.kubernetes.io/instance"]))
	managedBy := strings.ToLower(strings.TrimSpace(labels["app.kubernetes.io/managed-by"]))
	if managedBy == platformManagedBy && slices.Contains(platformInstanceValues, instance) {
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

// platformRoleSQL mirrors PlatformRoleJSON before list pagination. Expressions
// must be trusted SQL columns, never request values. Policy constants are shared
// with the Go classifier used by deployment details and other inventories.
func platformRoleSQL(namespaceColumn, labelsColumn string) string {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	list := func(values []string) string {
		quoted := make([]string, len(values))
		for i, value := range values {
			quoted[i] = quote(value)
		}
		return strings.Join(quoted, ",")
	}
	namespaces := make([]string, 0, len(platformNamespaces))
	for namespace := range platformNamespaces {
		namespaces = append(namespaces, namespace)
	}
	slices.Sort(namespaces)
	// These are precisely the Unicode whitespace characters used by Go TrimSpace.
	const whitespace = " \t\n\v\f\r\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
	normalized := func(column string) string {
		return "lower(btrim(COALESCE(" + column + ",'')," + quote(whitespace) + "))"
	}
	label := func(key string) string { return normalized(labelsColumn + "->>" + quote(key)) }
	// JSON decoding into map[string]string rejects non-string values (except
	// null), so malformed label maps must fall back to namespace classification.
	validLabels := "(CASE WHEN jsonb_typeof(" + labelsColumn + ")='object' THEN NOT EXISTS (SELECT 1 FROM jsonb_each(" + labelsColumn + ") AS platform_label WHERE jsonb_typeof(platform_label.value) NOT IN ('string','null')) ELSE false END)"
	return "CASE WHEN " + normalized(namespaceColumn) + " IN (" + list(namespaces) + ") OR (" + validLabels + " AND (" + label("app.kubernetes.io/part-of") + " IN (" + list(platformPartOfValues) + ") OR " + label("helm.sh/chart") + "=" + quote(platformChart) + " OR starts_with(" + label("helm.sh/chart") + "," + quote(platformChart+"-") + ") OR (" + label("app.kubernetes.io/managed-by") + "=" + quote(platformManagedBy) + " AND " + label("app.kubernetes.io/instance") + " IN (" + list(platformInstanceValues) + ")))) THEN 'core' ELSE '' END"
}
