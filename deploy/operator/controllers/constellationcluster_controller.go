// Package controllers implements the ConstellationCluster reconciler.
//
// The reconciler is intentionally narrow at v1: given a ConstellationCluster, it ensures
// the Kubernetes objects that match the Spec exist in the cluster, are owned by the CR,
// and reflect the right images + replica counts. Subsystems toggle independently:
//
//	ScannerEnabled    → a Deployment running the scanner aggregator gRPC service
//	AdmissionEnabled  → a Deployment + Service running the admission webhook
//	RuntimeEnabled    → a DaemonSet running the eBPF + L7 DPI + WAF/DLP/Falco agent
//
// Scheduled platform jobs such as audit archiving and VulnDB importing are Helm-managed
// so operator CR reconciliation cannot drift from chart values or image pins.
package controllers

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cv1alpha1 "github.com/alphabravocompany/constellation/deploy/operator/api/v1alpha1"
)

// Reconciler reconciles ConstellationCluster CRs.
type Reconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	OperatorNamespace string // namespace the operator and managed workloads live in

	// Default images per role. CR fields override these per cluster. Airgap deployments
	// set the operator's flags to mirrored registry paths.
	DefaultScannerImage      string
	DefaultAdmissionImage    string
	DefaultRuntimeAgentImage string
	DefaultAgentImage        string // legacy / fallback
}

// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=constellation.alphabravo.io,resources=constellationclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services;serviceaccounts;configmaps,verbs=get;list;watch;create;update;patch;delete

// Reconcile drives a ConstellationCluster to its desired state.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cc := &cv1alpha1.ConstellationCluster{}
	if err := r.Get(ctx, req.NamespacedName, cc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if cc.DeletionTimestamp != nil {
		// Owner references handle cascading deletion of managed children.
		return ctrl.Result{}, nil
	}

	ns := r.OperatorNamespace
	if ns == "" {
		ns = "constellation-system"
	}

	if err := r.reconcileScanner(ctx, cc, ns); err != nil {
		return ctrl.Result{}, fmt.Errorf("scanner: %w", err)
	}
	if err := r.reconcileAdmission(ctx, cc, ns); err != nil {
		return ctrl.Result{}, fmt.Errorf("admission: %w", err)
	}
	if err := r.reconcileRuntime(ctx, cc, ns); err != nil {
		return ctrl.Result{}, fmt.Errorf("runtime: %w", err)
	}
	if err := r.reconcileAuditArchiver(ctx, cc, ns); err != nil {
		return ctrl.Result{}, fmt.Errorf("audit-archiver cleanup: %w", err)
	}
	if err := r.reconcileVulnDBImporter(ctx, cc, ns); err != nil {
		return ctrl.Result{}, fmt.Errorf("vulndb-importer cleanup: %w", err)
	}

	// Status update — observed generation + phase.
	cc.Status.Phase = "Ready"
	cc.Status.ObservedGeneration = cc.Generation
	now := metav1.Now()
	cc.Status.LastHeartbeat = &now
	if err := r.Status().Update(ctx, cc); err != nil {
		logger.Error(err, "status update")
	}
	return ctrl.Result{}, nil
}

// imageForRole returns the resolved container image for a given role, in priority order:
//  1. per-role CR field          (cc.Spec.ScannerImage etc.)
//  2. legacy single CR field     (cc.Spec.AgentImage)
//  3. operator default flag      (r.DefaultScannerImage etc.)
//  4. hard-coded ghcr.io path
func (r *Reconciler) imageForRole(cc *cv1alpha1.ConstellationCluster, role string) string {
	var crImg, opImg, fallback string
	switch role {
	case "scanner":
		crImg, opImg, fallback = cc.Spec.ScannerImage, r.DefaultScannerImage, "ghcr.io/alphabravocompany/constellation-scanner:latest"
	case "admission":
		crImg, opImg, fallback = cc.Spec.AdmissionImage, r.DefaultAdmissionImage, "ghcr.io/alphabravocompany/constellation-admission:latest"
	case "runtime-agent":
		crImg, opImg, fallback = cc.Spec.RuntimeAgentImage, r.DefaultRuntimeAgentImage, "ghcr.io/alphabravocompany/constellation-runtime-agent:latest"
	}
	if crImg != "" {
		return crImg
	}
	if cc.Spec.AgentImage != "" {
		return cc.Spec.AgentImage
	}
	if opImg != "" {
		return opImg
	}
	// NOTE: r.DefaultAgentImage (the legacy combined-agent image) is intentionally
	// NOT used as a generic fallback here — doing so shadowed the per-role
	// fallbacks below, booting scanner/admission off the phantom combined-agent
	// binary. Per-role defaults (opImg) and the per-role hard-coded fallback win.
	return fallback
}

func (r *Reconciler) reconcileScanner(ctx context.Context, cc *cv1alpha1.ConstellationCluster, ns string) error {
	name := types.NamespacedName{Namespace: ns, Name: cc.Name + "-scanner"}
	hpaName := types.NamespacedName{Namespace: ns, Name: cc.Name + "-scanner"}
	if !cc.Spec.ScannerEnabled {
		if err := r.deleteIfExists(ctx, name, &appsv1.Deployment{}); err != nil {
			return err
		}
		return r.deleteIfExists(ctx, hpaName, &autoscalingv2.HorizontalPodAutoscaler{})
	}
	replicas := int32(2)
	if cc.Spec.ScannerReplicas != nil {
		replicas = *cc.Spec.ScannerReplicas
	}
	// When the scanner HPA is enabled it owns the replica count. Pass nil so the
	// Deployment reconcile leaves Spec.Replicas untouched; otherwise every HPA
	// scale event re-triggers reconcile and resets replicas, fighting the HPA.
	desiredReplicas := &replicas
	if cc.Spec.ScannerAutoscale != nil && cc.Spec.ScannerAutoscale.Enabled {
		desiredReplicas = nil
	}
	if err := r.ensureDeployment(ctx, cc, name, "scanner", r.imageForRole(cc, "scanner"), desiredReplicas, []corev1.EnvVar{
		{Name: "CONSTELLATION_CONTROL_PLANE_URL", Value: cc.Spec.ControlPlaneURL},
		{Name: "CONSTELLATION_ORG_ID", Value: cc.Spec.OrgID},
	}); err != nil {
		return err
	}
	return r.reconcileScannerHPA(ctx, cc, hpaName)
}

func (r *Reconciler) reconcileAdmission(ctx context.Context, cc *cv1alpha1.ConstellationCluster, ns string) error {
	name := types.NamespacedName{Namespace: ns, Name: cc.Name + "-admission"}
	if !cc.Spec.AdmissionEnabled {
		if err := r.deleteIfExists(ctx, name, &appsv1.Deployment{}); err != nil {
			return err
		}
		return r.deleteIfExists(ctx, name, &corev1.Service{})
	}
	replicas := int32(2)
	if cc.Spec.AdmissionReplicas != nil {
		replicas = *cc.Spec.AdmissionReplicas
	}
	if err := r.ensureDeployment(ctx, cc, name, "admission", r.imageForRole(cc, "admission"), &replicas, []corev1.EnvVar{
		{Name: "CONSTELLATION_CONTROL_PLANE_URL", Value: cc.Spec.ControlPlaneURL},
		{Name: "CONSTELLATION_ORG_ID", Value: cc.Spec.OrgID},
	}); err != nil {
		return err
	}
	return r.ensureWebhookService(ctx, cc, name)
}

func (r *Reconciler) reconcileRuntime(ctx context.Context, cc *cv1alpha1.ConstellationCluster, ns string) error {
	name := types.NamespacedName{Namespace: ns, Name: cc.Name + "-runtime-agent"}
	if !cc.Spec.RuntimeEnabled {
		return r.deleteIfExists(ctx, name, &appsv1.DaemonSet{})
	}
	return r.ensureAgentDaemonSet(ctx, cc, name)
}

// reconcileScannerHPA creates/updates the HorizontalPodAutoscaler when ScannerAutoscale.Enabled.
func (r *Reconciler) reconcileScannerHPA(ctx context.Context, cc *cv1alpha1.ConstellationCluster, name types.NamespacedName) error {
	if cc.Spec.ScannerAutoscale == nil || !cc.Spec.ScannerAutoscale.Enabled {
		return r.deleteIfExists(ctx, name, &autoscalingv2.HorizontalPodAutoscaler{})
	}
	minR := cc.Spec.ScannerAutoscale.MinReplicas
	if minR == 0 {
		minR = 2
	}
	maxR := cc.Spec.ScannerAutoscale.MaxReplicas
	if maxR == 0 {
		maxR = 10
	}
	target := cc.Spec.ScannerAutoscale.TargetCPUUtilization
	if target == 0 {
		target = 70
	}

	hpa := &autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Namespace: name.Namespace, Name: name.Name}}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, hpa, func() error {
		hpa.Spec.ScaleTargetRef = autoscalingv2.CrossVersionObjectReference{
			APIVersion: "apps/v1", Kind: "Deployment", Name: name.Name,
		}
		hpa.Spec.MinReplicas = &minR
		hpa.Spec.MaxReplicas = maxR
		hpa.Spec.Metrics = []autoscalingv2.MetricSpec{{
			Type: autoscalingv2.ResourceMetricSourceType,
			Resource: &autoscalingv2.ResourceMetricSource{
				Name: corev1.ResourceCPU,
				Target: autoscalingv2.MetricTarget{
					Type:               autoscalingv2.UtilizationMetricType,
					AverageUtilization: &target,
				},
			},
		}}
		return controllerutil.SetControllerReference(cc, hpa, r.Scheme)
	})
	if err != nil {
		return err
	}
	log.FromContext(ctx).Info("reconciled hpa", "name", name.Name, "op", op)
	return nil
}

func (r *Reconciler) reconcileAuditArchiver(ctx context.Context, cc *cv1alpha1.ConstellationCluster, ns string) error {
	name := types.NamespacedName{Namespace: ns, Name: cc.Name + "-audit-archiver"}
	return r.deleteIfExists(ctx, name, &batchv1.CronJob{})
}

func (r *Reconciler) reconcileVulnDBImporter(ctx context.Context, cc *cv1alpha1.ConstellationCluster, ns string) error {
	name := types.NamespacedName{Namespace: ns, Name: cc.Name + "-vulndb-importer"}
	return r.deleteIfExists(ctx, name, &batchv1.CronJob{})
}

func (r *Reconciler) ensureDeployment(
	ctx context.Context,
	cc *cv1alpha1.ConstellationCluster,
	name types.NamespacedName,
	role, image string,
	replicas *int32,
	env []corev1.EnvVar,
) error {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: name.Namespace, Name: name.Name}}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, dep, func() error {
		labels := map[string]string{
			"app.kubernetes.io/name":              "constellation",
			"app.kubernetes.io/component":         role,
			"constellation.alphabravo.io/cluster": cc.Name,
		}
		dep.Labels = labels
		// A nil replicas means an external controller (the scanner HPA) owns the
		// count; leave Spec.Replicas as-is so reconcile doesn't fight the HPA.
		if replicas != nil {
			dep.Spec.Replicas = replicas
		}
		dep.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
		dep.Spec.Template.ObjectMeta.Labels = labels
		dep.Spec.Template.Spec.Containers = []corev1.Container{{
			Name:  role,
			Image: image,
			// Each per-role image's ENTRYPOINT is the role binary; we only pass
			// role-specific bootstrap flags here. Cluster-managed TLS for the
			// admission webhook is not yet wired, so we boot it in insecure (plain
			// HTTP on :8443) mode for now — the ValidatingWebhookConfiguration is
			// created with caBundle skipped when this flag is set.
			Args:      roleArgs(role),
			Env:       env,
			Ports:     rolePorts(role),
			Resources: containerResources(cc.Spec.AgentResources),
			// Readiness probes are role-specific (admission listens on 8443 TLS,
			// scanner on 8090). Omitted at this layer so each role can register its
			// own probe via a future webhook/CRD field; today the pod becomes Ready
			// as soon as the process is up.
		}}
		return controllerutil.SetControllerReference(cc, dep, r.Scheme)
	})
	if err != nil {
		return err
	}
	log.FromContext(ctx).Info("reconciled deployment", "name", name.Name, "op", op)
	return nil
}

func (r *Reconciler) ensureAgentDaemonSet(
	ctx context.Context,
	cc *cv1alpha1.ConstellationCluster,
	name types.NamespacedName,
) error {
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: name.Namespace, Name: name.Name}}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, ds, func() error {
		labels := map[string]string{
			"app.kubernetes.io/name":              "constellation",
			"app.kubernetes.io/component":         "runtime-agent",
			"constellation.alphabravo.io/cluster": cc.Name,
		}
		ds.Labels = labels
		ds.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
		ds.Spec.Template.ObjectMeta.Labels = labels
		t := true
		hostPathDir := corev1.HostPathDirectory
		hostPathDirOrCreate := corev1.HostPathDirectoryOrCreate
		ds.Spec.Template.Spec.HostNetwork = true
		ds.Spec.Template.Spec.HostPID = true
		// hostPath mounts the runtime agent needs in order to actually attach BPF
		// programs to the node kernel:
		//   /sys/kernel/btf   — for CO-RE BTF resolution (read-only)
		//   /sys/fs/bpf       — for pinning BPF objects across restarts
		//   /sys              — full sysfs for tracepoint discovery
		//   /proc             — host PID namespace process metadata for cgroup ID lookup
		//   /etc,/lib/modules,/run,/var/run — host inventory and CRI socket discovery
		ds.Spec.Template.Spec.Volumes = []corev1.Volume{
			{Name: "sys", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys", Type: &hostPathDir}}},
			{Name: "bpf-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &hostPathDirOrCreate}}},
			{Name: "btf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/btf", Type: &hostPathDir}}},
			{Name: "proc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc", Type: &hostPathDir}}},
			{Name: "host-etc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc", Type: &hostPathDir}}},
			{Name: "host-lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules", Type: &hostPathDirOrCreate}}},
			{Name: "host-run", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run", Type: &hostPathDirOrCreate}}},
			{Name: "host-var-run", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run", Type: &hostPathDirOrCreate}}},
		}
		ds.Spec.Template.Spec.Containers = []corev1.Container{{
			Name:  "agent",
			Image: r.imageForRole(cc, "runtime-agent"),
			// See note in ensureDeployment: per-role images use their binary as the
			// ENTRYPOINT and don't accept a --role flag.
			//
			// Wave I4: also project the runtime-agent token (used to authenticate POSTs
			// to /api/v1/events:bulk). Convention: the cluster admin pre-creates a Secret
			// at <ns>/<cluster-name>-runtime-agent-token with key `token`. The DaemonSet
			// tolerates the secret being absent — `optional: true` means the env var is
			// simply not set, which puts the binary into stdout-only mode (no upload).
			Env: []corev1.EnvVar{
				{Name: "CONSTELLATION_CONTROL_PLANE_URL", Value: cc.Spec.ControlPlaneURL},
				{Name: "CONSTELLATION_API_URL", Value: cc.Spec.ControlPlaneURL},
				{Name: "CONSTELLATION_ORG_ID", Value: cc.Spec.OrgID},
				{Name: "CONSTELLATION_HOSTSCAN_ROOT", Value: "/host"},
				{Name: "CONSTELLATION_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
				{Name: "NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
				{Name: "RUNTIME_AGENT_TOKEN", ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: cc.Name + "-runtime-agent-token"},
						Key:                  "token",
						Optional:             func() *bool { b := true; return &b }(),
					},
				}},
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "sys", MountPath: "/sys", ReadOnly: true},
				{Name: "bpf-fs", MountPath: "/sys/fs/bpf"},
				{Name: "btf", MountPath: "/sys/kernel/btf", ReadOnly: true},
				{Name: "proc", MountPath: "/host/proc", ReadOnly: true},
				{Name: "host-etc", MountPath: "/host/etc", ReadOnly: true},
				{Name: "host-lib-modules", MountPath: "/host/lib/modules", ReadOnly: true},
				{Name: "host-run", MountPath: "/host/run", ReadOnly: true},
				{Name: "host-var-run", MountPath: "/host/var/run", ReadOnly: true},
			},
			SecurityContext: &corev1.SecurityContext{
				Privileged: &t,
				Capabilities: &corev1.Capabilities{Add: []corev1.Capability{
					"NET_ADMIN", "SYS_ADMIN", "BPF", "PERFMON", "NET_RAW", "SYS_PTRACE",
				}},
			},
			Resources: containerResources(cc.Spec.AgentResources),
		}}
		return controllerutil.SetControllerReference(cc, ds, r.Scheme)
	})
	if err != nil {
		return err
	}
	log.FromContext(ctx).Info("reconciled daemonset", "name", name.Name, "op", op)
	return nil
}

func (r *Reconciler) ensureWebhookService(
	ctx context.Context,
	cc *cv1alpha1.ConstellationCluster,
	name types.NamespacedName,
) error {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: name.Namespace, Name: name.Name}}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Spec.Selector = map[string]string{
			"app.kubernetes.io/name":              "constellation",
			"app.kubernetes.io/component":         "admission",
			"constellation.alphabravo.io/cluster": cc.Name,
		}
		svc.Spec.Ports = []corev1.ServicePort{{Port: 443, TargetPort: intstr.FromInt(8443), Name: "webhook"}}
		svc.Spec.Type = corev1.ServiceTypeClusterIP
		return controllerutil.SetControllerReference(cc, svc, r.Scheme)
	})
	if err != nil {
		return err
	}
	log.FromContext(ctx).Info("reconciled service", "name", name.Name, "op", op)
	return nil
}

func (r *Reconciler) deleteIfExists(ctx context.Context, name types.NamespacedName, obj client.Object) error {
	obj.SetNamespace(name.Namespace)
	obj.SetName(name.Name)
	if err := r.Get(ctx, name, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return client.IgnoreNotFound(r.Delete(ctx, obj))
}

// roleArgs returns the default boot args for a given role. These are minimal
// "make it boot" flags; production deployments override via a ConstellationCluster
// extension that has yet to land.
func roleArgs(role string) []string {
	switch role {
	case "admission":
		// No cert-manager wiring yet; run plain HTTP on :8443.
		return []string{"--insecure"}
	}
	return nil
}

// rolePorts returns the container ports for a given role, matching the listen
// addresses baked into each per-role binary.
func rolePorts(role string) []corev1.ContainerPort {
	switch role {
	case "admission":
		return []corev1.ContainerPort{{ContainerPort: 8443, Name: "webhook", Protocol: corev1.ProtocolTCP}}
	case "scanner":
		return []corev1.ContainerPort{{ContainerPort: 8090, Name: "http", Protocol: corev1.ProtocolTCP}}
	}
	return []corev1.ContainerPort{{ContainerPort: 8443, Name: "grpc"}}
}

func containerResources(in *cv1alpha1.AgentResources) corev1.ResourceRequirements {
	r := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
	if in == nil {
		return r
	}
	if in.CPULimit != "" {
		if q, err := resource.ParseQuantity(in.CPULimit); err == nil {
			r.Limits[corev1.ResourceCPU] = q
		}
	}
	if in.MemoryLimit != "" {
		if q, err := resource.ParseQuantity(in.MemoryLimit); err == nil {
			r.Limits[corev1.ResourceMemory] = q
		}
	}
	return r
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cv1alpha1.ConstellationCluster{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.Service{}).
		Owns(&batchv1.CronJob{}).
		Complete(r)
}
