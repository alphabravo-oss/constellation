package controllers

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cv1alpha1 "github.com/alphabravocompany/constellation/deploy/operator/api/v1alpha1"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(cv1alpha1.AddToScheme(s))
	return s
}

func TestReconcile_AllSubsystemsEnabled(t *testing.T) {
	scheme := newTestScheme()
	cc := &cv1alpha1.ConstellationCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Generation: 1},
		Spec: cv1alpha1.ConstellationClusterSpec{
			ControlPlaneURL:  "https://constellation.example",
			OrgID:            "00000000-0000-0000-0000-000000000000",
			ScannerEnabled:   true,
			AdmissionEnabled: true,
			RuntimeEnabled:   true,
		},
	}
	legacyArchiver := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "constellation-system", Name: "demo-audit-archiver"}}
	legacyImporter := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "constellation-system", Name: "demo-vulndb-importer"}}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc, legacyArchiver, legacyImporter).
		WithStatusSubresource(&cv1alpha1.ConstellationCluster{}).
		Build()

	r := &Reconciler{Client: c, Scheme: scheme, OperatorNamespace: "constellation-system"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "demo"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	ctx := context.Background()

	dep := &appsv1.Deployment{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-scanner"}, dep); err != nil {
		t.Fatalf("scanner deployment: %v", err)
	}
	if dep.Spec.Template.Spec.Containers[0].Image == "" {
		t.Fatalf("scanner image unset")
	}

	adep := &appsv1.Deployment{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-admission"}, adep); err != nil {
		t.Fatalf("admission deployment: %v", err)
	}

	asvc := &corev1.Service{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-admission"}, asvc); err != nil {
		t.Fatalf("admission service: %v", err)
	}
	if asvc.Spec.Ports[0].Port != 443 {
		t.Fatalf("admission service port: %d", asvc.Spec.Ports[0].Port)
	}

	ds := &appsv1.DaemonSet{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-runtime-agent"}, ds); err != nil {
		t.Fatalf("runtime agent daemonset: %v", err)
	}
	if !*ds.Spec.Template.Spec.Containers[0].SecurityContext.Privileged {
		t.Fatalf("runtime agent should be privileged")
	}
	if !hasEnvValue(ds.Spec.Template.Spec.Containers[0].Env, "CONSTELLATION_HOSTSCAN_ROOT", "/host") {
		t.Fatalf("runtime agent should set CONSTELLATION_HOSTSCAN_ROOT=/host")
	}
	if !hasVolumeMount(ds.Spec.Template.Spec.Containers[0].VolumeMounts, "host-run", "/host/run") ||
		!hasVolumeMount(ds.Spec.Template.Spec.Containers[0].VolumeMounts, "host-var-run", "/host/var/run") ||
		!hasVolumeMount(ds.Spec.Template.Spec.Containers[0].VolumeMounts, "proc", "/host/proc") {
		t.Fatalf("runtime agent should mount host proc and CRI socket roots: %+v", ds.Spec.Template.Spec.Containers[0].VolumeMounts)
	}

	archiver := &batchv1.CronJob{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-audit-archiver"}, archiver); !apierrors.IsNotFound(err) {
		t.Fatalf("audit-archiver cronjob should be Helm-managed and absent after cleanup, got err=%v", err)
	}

	imp := &batchv1.CronJob{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-vulndb-importer"}, imp); !apierrors.IsNotFound(err) {
		t.Fatalf("vulndb-importer cronjob should be Helm-managed and absent after cleanup, got err=%v", err)
	}

	updated := &cv1alpha1.ConstellationCluster{}
	if err := c.Get(ctx, types.NamespacedName{Name: "demo"}, updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.Phase != "Ready" {
		t.Fatalf("status phase: %q", updated.Status.Phase)
	}
}

func hasEnvValue(env []corev1.EnvVar, name, value string) bool {
	for _, item := range env {
		if item.Name == name && item.Value == value {
			return true
		}
	}
	return false
}

func hasVolumeMount(mounts []corev1.VolumeMount, name, path string) bool {
	for _, item := range mounts {
		if item.Name == name && item.MountPath == path {
			return true
		}
	}
	return false
}

func TestReconcile_RoleSpecificImagesAndHPA(t *testing.T) {
	scheme := newTestScheme()
	min := int32(3)
	max := int32(20)
	cc := &cv1alpha1.ConstellationCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
		Spec: cv1alpha1.ConstellationClusterSpec{
			ControlPlaneURL:   "https://example",
			OrgID:             "00000000-0000-0000-0000-000000000000",
			ScannerEnabled:    true,
			AdmissionEnabled:  true,
			RuntimeEnabled:    true,
			ScannerImage:      "registry.airgap/scanner:v1",
			AdmissionImage:    "registry.airgap/admission:v1",
			RuntimeAgentImage: "registry.airgap/runtime:v1",
			ScannerAutoscale: &cv1alpha1.ScannerAutoscale{
				Enabled: true, MinReplicas: min, MaxReplicas: max, TargetCPUUtilization: 60,
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cc).
		WithStatusSubresource(&cv1alpha1.ConstellationCluster{}).Build()
	r := &Reconciler{Client: c, Scheme: scheme, OperatorNamespace: "constellation-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "demo"}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Scanner image override picked up.
	sd := &appsv1.Deployment{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-scanner"}, sd); err != nil {
		t.Fatal(err)
	}
	if sd.Spec.Template.Spec.Containers[0].Image != "registry.airgap/scanner:v1" {
		t.Fatalf("scanner image: %q", sd.Spec.Template.Spec.Containers[0].Image)
	}
	// With autoscale enabled the HPA owns the replica count; the Deployment
	// reconcile must NOT set Spec.Replicas (otherwise it fights the HPA).
	if sd.Spec.Replicas != nil {
		t.Fatalf("scanner Spec.Replicas should be nil under autoscale, got %d", *sd.Spec.Replicas)
	}

	// Admission image override picked up.
	ad := &appsv1.Deployment{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-admission"}, ad); err != nil {
		t.Fatal(err)
	}
	if ad.Spec.Template.Spec.Containers[0].Image != "registry.airgap/admission:v1" {
		t.Fatalf("admission image: %q", ad.Spec.Template.Spec.Containers[0].Image)
	}
	// Admission has no autoscaler, so its replica count is managed explicitly.
	if ad.Spec.Replicas == nil {
		t.Fatal("admission Spec.Replicas should be set (no HPA)")
	}

	// Admission Service selector must carry the cluster label so two
	// ConstellationClusters in one namespace don't cross-route admission traffic.
	asvc := &corev1.Service{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-admission"}, asvc); err != nil {
		t.Fatal(err)
	}
	if asvc.Spec.Selector["constellation.alphabravo.io/cluster"] != "demo" {
		t.Fatalf("admission service selector missing cluster label: %v", asvc.Spec.Selector)
	}

	// HPA exists with the right bounds.
	hpa := &autoscalingv2.HorizontalPodAutoscaler{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-scanner"}, hpa); err != nil {
		t.Fatalf("hpa: %v", err)
	}
	if *hpa.Spec.MinReplicas != min || hpa.Spec.MaxReplicas != max {
		t.Fatalf("hpa bounds: min=%d max=%d", *hpa.Spec.MinReplicas, hpa.Spec.MaxReplicas)
	}
}

func TestReconcile_TogglesDeleteResources(t *testing.T) {
	scheme := newTestScheme()
	cc := &cv1alpha1.ConstellationCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
		Spec: cv1alpha1.ConstellationClusterSpec{
			ControlPlaneURL: "https://x",
			OrgID:           "00000000-0000-0000-0000-000000000000",
			ScannerEnabled:  true,
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc).
		WithStatusSubresource(&cv1alpha1.ConstellationCluster{}).
		Build()
	r := &Reconciler{Client: c, Scheme: scheme, OperatorNamespace: "constellation-system"}
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "demo"}}); err != nil {
		t.Fatal(err)
	}

	dep := &appsv1.Deployment{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-scanner"}, dep); err != nil {
		t.Fatalf("expected scanner deployment, got %v", err)
	}

	// Toggle off.
	updated := &cv1alpha1.ConstellationCluster{}
	if err := c.Get(ctx, types.NamespacedName{Name: "demo"}, updated); err != nil {
		t.Fatal(err)
	}
	updated.Spec.ScannerEnabled = false
	if err := c.Update(ctx, updated); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "demo"}}); err != nil {
		t.Fatal(err)
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: "constellation-system", Name: "demo-scanner"}, &appsv1.Deployment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected scanner deployment deleted, got err=%v", err)
	}
}
