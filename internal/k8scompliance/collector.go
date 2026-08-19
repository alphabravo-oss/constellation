// Package k8scompliance evaluates Kubernetes API objects into Constellation
// internal compliance controls. It is intentionally read-only and deterministic
// so it can run from a CronJob and write the resulting rows into
// compliance_checks.
package k8scompliance

import (
	"context"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/alphabravocompany/constellation/pkg/compliance"
)

const (
	CollectorName = "constellation-k8s-object"
)

// Options controls a single collection pass.
type Options struct {
	NamespaceFilter        []string
	IncludeSystemNamespace bool
	ObservedAt             time.Time
	// CustomChecks are user-supplied CEL compliance checks evaluated over the collected
	// objects (see customcheck.go). Empty in the common path; the collector loads them
	// per-org from custom_compliance_checks and passes them here.
	CustomChecks []CustomCheck
}

// Evidence is one raw Kubernetes object check before cross-framework expansion.
type Evidence struct {
	InternalID  string
	Status      string
	TargetKind  string
	Target      string
	Evidence    string
	Remediation string
	ObservedAt  time.Time

	// Custom marks an Evidence produced by a user-supplied CustomCheck. Such rows have no
	// CoreMappings entry, so Expand emits a single "Custom" framework Check carrying the
	// check's own title/severity instead of expanding InternalID through the mapping table.
	Custom   bool
	Title    string
	Severity string
}

// ReportEvidence returns the text stored in compliance_checks.evidence.
func (e Evidence) ReportEvidence() string {
	parts := []string{
		"collector=" + CollectorName,
		"target_kind=" + e.TargetKind,
		"target=" + e.Target,
		"status=" + e.Status,
	}
	if e.Evidence != "" {
		parts = append(parts, "evidence="+e.Evidence)
	}
	if e.Remediation != "" {
		parts = append(parts, "remediation="+e.Remediation)
	}
	return strings.Join(parts, "\n")
}

// Expand converts a raw object check into the framework rows persisted in
// compliance_checks.
func (e Evidence) Expand() []compliance.Check {
	if e.Custom {
		return []compliance.Check{{
			Framework: "Custom",
			ControlID: e.InternalID,
			Title:     e.Title,
			Status:    e.Status,
			Severity:  e.Severity,
			Evidence:  e.ReportEvidence(),
		}}
	}
	return compliance.ExpandInternal(e.InternalID, e.Status, e.ReportEvidence())
}

// Collect evaluates namespaces, RBAC, and common workload pod templates.
func Collect(ctx context.Context, client kubernetes.Interface, opts Options) ([]Evidence, error) {
	if opts.ObservedAt.IsZero() {
		opts.ObservedAt = time.Now().UTC()
	}
	if len(opts.NamespaceFilter) == 0 {
		opts.NamespaceFilter = []string{"*"}
	}
	out := []Evidence{}
	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	nsAllowed := map[string]bool{}
	for _, ns := range namespaces.Items {
		allowed := namespaceAllowed(ns.Name, opts)
		nsAllowed[ns.Name] = allowed
		if !allowed {
			continue
		}
		out = append(out, evaluateNamespace(ns, opts.ObservedAt))
	}
	out = append(out, summarizePass(out, "k8s.namespace.pod-security-enforce", "Namespace", "namespaces", "All included namespaces enforce Pod Security Admission", opts.ObservedAt)...)

	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}
	out = append(out, evaluateClusterRoles(clusterRoles.Items, opts.ObservedAt)...)

	deployments, err := client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	for _, item := range deployments.Items {
		if nsAllowed[item.Namespace] {
			out = append(out, evaluatePodTemplate("Deployment", item.Namespace, item.Name, item.Spec.Template.Spec, opts.ObservedAt)...)
		}
	}
	statefulSets, err := client.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	for _, item := range statefulSets.Items {
		if nsAllowed[item.Namespace] {
			out = append(out, evaluatePodTemplate("StatefulSet", item.Namespace, item.Name, item.Spec.Template.Spec, opts.ObservedAt)...)
		}
	}
	daemonSets, err := client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	for _, item := range daemonSets.Items {
		if nsAllowed[item.Namespace] {
			out = append(out, evaluatePodTemplate("DaemonSet", item.Namespace, item.Name, item.Spec.Template.Spec, opts.ObservedAt)...)
		}
	}

	workloadCount := len(deployments.Items) + len(statefulSets.Items) + len(daemonSets.Items)
	if workloadCount > 0 {
		out = append(out, summarizePass(out, "k8s.host-network-forbidden", "Workload", "workloads", "No included workload pod template uses hostNetwork", opts.ObservedAt)...)
		out = append(out, summarizePass(out, "k8s.privileged-containers-forbidden", "Workload", "workloads", "No included workload pod template has privileged containers", opts.ObservedAt)...)
		out = append(out, summarizePass(out, "k8s.read-only-root-filesystem", "Workload", "workloads", "Included workload containers use read-only root filesystems", opts.ObservedAt)...)
	}

	if len(opts.CustomChecks) > 0 {
		targets := gatherCustomTargets(namespaces.Items, nsAllowed, clusterRoles.Items,
			deployments.Items, statefulSets.Items, daemonSets.Items)
		out = append(out, evaluateCustomChecks(opts.CustomChecks, targets, opts.ObservedAt)...)
	}
	return out, nil
}

// gatherCustomTargets renders the already-listed objects into the generic form CEL custom
// checks evaluate against, honoring the same namespace-inclusion decisions the built-in checks
// use (cluster-scoped ClusterRoles are always included).
func gatherCustomTargets(namespaces []corev1.Namespace, nsAllowed map[string]bool, roles []rbacv1.ClusterRole, deployments []appsv1.Deployment, statefulSets []appsv1.StatefulSet, daemonSets []appsv1.DaemonSet) []customTarget {
	targets := []customTarget{}
	add := func(kind, ns, name string, obj any) {
		m, err := toUnstructured(obj)
		if err != nil {
			return
		}
		targets = append(targets, customTarget{kind: kind, namespace: ns, name: name, object: m})
	}
	for i := range namespaces {
		if nsAllowed[namespaces[i].Name] {
			add("Namespace", "", namespaces[i].Name, namespaces[i])
		}
	}
	for i := range roles {
		add("ClusterRole", "", roles[i].Name, roles[i])
	}
	for i := range deployments {
		if nsAllowed[deployments[i].Namespace] {
			add("Deployment", deployments[i].Namespace, deployments[i].Name, deployments[i])
		}
	}
	for i := range statefulSets {
		if nsAllowed[statefulSets[i].Namespace] {
			add("StatefulSet", statefulSets[i].Namespace, statefulSets[i].Name, statefulSets[i])
		}
	}
	for i := range daemonSets {
		if nsAllowed[daemonSets[i].Namespace] {
			add("DaemonSet", daemonSets[i].Namespace, daemonSets[i].Name, daemonSets[i])
		}
	}
	return targets
}

func evaluateNamespace(ns corev1.Namespace, observedAt time.Time) Evidence {
	enforce := strings.ToLower(strings.TrimSpace(ns.Labels["pod-security.kubernetes.io/enforce"]))
	status := "fail"
	evidence := "pod-security.kubernetes.io/enforce is not set"
	if enforce == "restricted" || enforce == "baseline" {
		status = "pass"
		evidence = "pod-security.kubernetes.io/enforce=" + enforce
	} else if enforce != "" {
		evidence = "pod-security.kubernetes.io/enforce=" + enforce
	}
	return Evidence{
		InternalID:  "k8s.namespace.pod-security-enforce",
		Status:      status,
		TargetKind:  "Namespace",
		Target:      ns.Name,
		Evidence:    evidence,
		Remediation: "Set pod-security.kubernetes.io/enforce to baseline or restricted, and pin the matching warn/audit versions.",
		ObservedAt:  observedAt,
	}
}

func evaluateClusterRoles(roles []rbacv1.ClusterRole, observedAt time.Time) []Evidence {
	out := []Evidence{}
	for _, role := range roles {
		for _, rule := range role.Rules {
			if contains(rule.Verbs, "*") && contains(rule.Resources, "*") {
				out = append(out, Evidence{
					InternalID:  "k8s.rbac.no-wildcard-roles",
					Status:      "fail",
					TargetKind:  "ClusterRole",
					Target:      role.Name,
					Evidence:    "rule grants verbs=* on resources=*",
					Remediation: "Replace wildcard verbs and resources with the minimum required RBAC rule set.",
					ObservedAt:  observedAt,
				})
				break
			}
		}
	}
	if len(out) == 0 {
		out = append(out, Evidence{
			InternalID: "k8s.rbac.no-wildcard-roles",
			Status:     "pass",
			TargetKind: "ClusterRole",
			Target:     "clusterroles",
			Evidence:   "no ClusterRole grants verbs=* on resources=*",
			ObservedAt: observedAt,
		})
	}
	return out
}

func evaluatePodTemplate(kind, namespace, name string, spec corev1.PodSpec, observedAt time.Time) []Evidence {
	target := namespace + "/" + name
	out := []Evidence{}
	if spec.HostNetwork {
		out = append(out, Evidence{
			InternalID:  "k8s.host-network-forbidden",
			Status:      "fail",
			TargetKind:  kind,
			Target:      target,
			Evidence:    "spec.template.spec.hostNetwork=true",
			Remediation: "Remove hostNetwork or document a narrow exception for workloads that genuinely need host networking.",
			ObservedAt:  observedAt,
		})
	}
	privileged := privilegedContainers(spec)
	if len(privileged) > 0 {
		out = append(out, Evidence{
			InternalID:  "k8s.privileged-containers-forbidden",
			Status:      "fail",
			TargetKind:  kind,
			Target:      target,
			Evidence:    "privileged containers: " + strings.Join(privileged, ", "),
			Remediation: "Set securityContext.privileged=false and grant only the specific Linux capabilities required.",
			ObservedAt:  observedAt,
		})
	}
	writable := writableRootFilesystemContainers(spec)
	if len(writable) > 0 {
		out = append(out, Evidence{
			InternalID:  "k8s.read-only-root-filesystem",
			Status:      "fail",
			TargetKind:  kind,
			Target:      target,
			Evidence:    "containers without readOnlyRootFilesystem=true: " + strings.Join(writable, ", "),
			Remediation: "Set readOnlyRootFilesystem=true and mount explicit writable emptyDir volumes for temp/cache paths.",
			ObservedAt:  observedAt,
		})
	}
	return out
}

func privilegedContainers(spec corev1.PodSpec) []string {
	out := []string{}
	for _, c := range spec.InitContainers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			out = append(out, "init/"+c.Name)
		}
	}
	for _, c := range spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			out = append(out, c.Name)
		}
	}
	for _, c := range spec.EphemeralContainers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			out = append(out, "ephemeral/"+c.Name)
		}
	}
	return out
}

func writableRootFilesystemContainers(spec corev1.PodSpec) []string {
	out := []string{}
	for _, c := range spec.InitContainers {
		if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			out = append(out, "init/"+c.Name)
		}
	}
	for _, c := range spec.Containers {
		if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			out = append(out, c.Name)
		}
	}
	return out
}

func summarizePass(items []Evidence, internalID, targetKind, target, evidence string, observedAt time.Time) []Evidence {
	for _, item := range items {
		if item.InternalID == internalID && item.Status == "fail" {
			return nil
		}
	}
	return []Evidence{{
		InternalID: internalID,
		Status:     "pass",
		TargetKind: targetKind,
		Target:     target,
		Evidence:   evidence,
		ObservedAt: observedAt,
	}}
}

func namespaceAllowed(ns string, opts Options) bool {
	if !opts.IncludeSystemNamespace && isSystemNamespace(ns) {
		return false
	}
	globs := opts.NamespaceFilter
	if len(globs) == 0 {
		return true
	}
	allow := false
	hasInclude := false
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		neg := strings.HasPrefix(g, "!")
		if neg {
			g = strings.TrimPrefix(g, "!")
		} else {
			hasInclude = true
		}
		if globMatch(g, ns) {
			if neg {
				return false
			}
			allow = true
		}
	}
	if !hasInclude {
		return true
	}
	return allow
}

func isSystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	default:
		return false
	}
}

func globMatch(pattern, value string) bool {
	if pattern == "*" || pattern == value {
		return true
	}
	if strings.Contains(pattern, "*") {
		parts := strings.SplitN(pattern, "*", 2)
		return strings.HasPrefix(value, parts[0]) && strings.HasSuffix(value, parts[1])
	}
	return false
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
