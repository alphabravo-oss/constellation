package k8scompliance

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/alphabravocompany/constellation/pkg/compliance"
)

func TestCollect_FindsKubernetesObjectFailures(t *testing.T) {
	yes := true
	no := false
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "wildcard-admin"},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"*"},
				Resources: []string{"*"},
			}},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				HostNetwork: true,
				Containers: []corev1.Container{{
					Name: "api",
					SecurityContext: &corev1.SecurityContext{
						Privileged:             &yes,
						ReadOnlyRootFilesystem: &no,
					},
				}},
			}}},
		},
	)
	items, err := Collect(context.Background(), client, Options{ObservedAt: time.Unix(1700000000, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	wantFails := map[string]bool{
		"k8s.namespace.pod-security-enforce":  false,
		"k8s.rbac.no-wildcard-roles":          false,
		"k8s.host-network-forbidden":          false,
		"k8s.privileged-containers-forbidden": false,
		"k8s.read-only-root-filesystem":       false,
	}
	for _, item := range items {
		if item.Status == "fail" {
			if _, ok := wantFails[item.InternalID]; ok {
				wantFails[item.InternalID] = true
			}
		}
		if item.InternalID == "k8s.rbac.no-wildcard-roles" {
			checks := item.Expand()
			if !hasFramework(checks, compliance.FrameworkCISK8s) {
				t.Fatalf("rbac evidence did not expand to CIS K8s: %+v", checks)
			}
		}
	}
	for id, found := range wantFails {
		if !found {
			t.Fatalf("missing failed evidence for %s in %+v", id, items)
		}
	}
}

func TestCollect_EmitsPassSummariesForCleanObjects(t *testing.T) {
	yes := true
	no := false
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   "apps",
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"},
		}},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "reader"},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"get", "list"},
				Resources: []string{"pods"},
			}},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "api",
					SecurityContext: &corev1.SecurityContext{
						Privileged:             &no,
						ReadOnlyRootFilesystem: &yes,
					},
				}},
			}}},
		},
	)
	items, err := Collect(context.Background(), client, Options{NamespaceFilter: []string{"apps"}})
	if err != nil {
		t.Fatal(err)
	}
	wantPass := map[string]bool{
		"k8s.namespace.pod-security-enforce":  false,
		"k8s.rbac.no-wildcard-roles":          false,
		"k8s.host-network-forbidden":          false,
		"k8s.privileged-containers-forbidden": false,
		"k8s.read-only-root-filesystem":       false,
	}
	for _, item := range items {
		if item.Status != "pass" {
			t.Fatalf("unexpected non-pass item in clean cluster: %+v", item)
		}
		if _, ok := wantPass[item.InternalID]; ok {
			wantPass[item.InternalID] = true
		}
	}
	for id, found := range wantPass {
		if !found {
			t.Fatalf("missing pass evidence for %s in %+v", id, items)
		}
	}
}

func hasFramework(checks []compliance.Check, framework string) bool {
	for _, check := range checks {
		if check.Framework == framework {
			return true
		}
	}
	return false
}
