package admission

// pss.go implements a real Kubernetes Pod Security Standards (PSS) engine as a
// pure pod-spec evaluator. It mirrors the upstream PSS control set
// (https://kubernetes.io/docs/concepts/security/pod-security-standards/) rather
// than the small ~3-5 control subset the original built-in profiles enforced.
//
// The engine evaluates a *corev1.Pod against a PSS level (baseline or
// restricted) and returns the list of human-readable control violations. Each
// control corresponds to a row in the upstream PSS tables:
//
//	Baseline (must NOT be present):
//	  - privileged containers
//	  - host namespaces (hostNetwork / hostPID / hostIPC)
//	  - hostPath volumes
//	  - host ports
//	  - non-default-or-NET_BIND_SERVICE added capabilities outside the baseline set
//	  - Unconfined AppArmor profile (annotation or appArmorProfile field)
//	  - SELinux options outside the allowed type/user/role set
//	  - Unconfined seccomp profile (when explicitly set)
//	  - procMount other than Default
//	  - sysctls outside the safe set
//
//	Restricted (baseline + these, must be set / constrained):
//	  - allowPrivilegeEscalation=false on every container
//	  - runAsNonRoot=true (pod or every container) and runAsUser != 0
//	  - seccompProfile RuntimeDefault or Localhost (required, not just non-Unconfined)
//	  - capabilities: drop ["ALL"]; only NET_BIND_SERVICE may be added
//	  - restricted volume types only
//
// This file is self-contained — it depends only on corev1 — so it can be unit
// tested without a cluster (TASK C1, "Cluster: partial").

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// PSSLevel is a Pod Security Standards enforcement level.
type PSSLevel string

const (
	// PSSLevelBaseline is the upstream "baseline" PSS level: it blocks known
	// privilege escalations while staying broadly compatible.
	PSSLevelBaseline PSSLevel = "baseline"
	// PSSLevelRestricted is the upstream "restricted" PSS level: baseline plus
	// the hardening controls (drop ALL caps, runAsNonRoot, seccomp required …).
	PSSLevelRestricted PSSLevel = "restricted"
)

// baselineAllowedCapabilities is the set of capabilities a baseline pod may add
// without violating the policy. Upstream PSS baseline restricts *added*
// capabilities to this list (it does not require dropping any). NET_BIND_SERVICE
// is the only capability the stricter restricted level allows.
var baselineAllowedCapabilities = map[string]struct{}{
	"AUDIT_WRITE":      {},
	"CHOWN":            {},
	"DAC_OVERRIDE":     {},
	"FOWNER":           {},
	"FSETID":           {},
	"KILL":             {},
	"MKNOD":            {},
	"NET_BIND_SERVICE": {},
	"SETFCAP":          {},
	"SETGID":           {},
	"SETPCAP":          {},
	"SETUID":           {},
	"SYS_CHROOT":       {},
}

// restrictedAllowedCapabilities is the set of capabilities a restricted pod may
// add. Upstream PSS restricted permits only NET_BIND_SERVICE (on top of an
// explicit drop of ALL).
var restrictedAllowedCapabilities = map[string]struct{}{
	"NET_BIND_SERVICE": {},
}

// safeSysctls is the upstream PSS "safe" sysctl set. Any sysctl outside this set
// is disallowed at baseline (and therefore at restricted).
var safeSysctls = map[string]struct{}{
	"kernel.shm_rmid_forced":              {},
	"net.ipv4.ip_local_port_range":        {},
	"net.ipv4.ip_unprivileged_port_start": {},
	"net.ipv4.tcp_syncookies":             {},
	"net.ipv4.ping_group_range":           {},
	"net.ipv4.ip_local_reserved_ports":    {},
}

// restrictedAllowedVolumeTypes is the upstream PSS restricted volume allowlist.
// A restricted pod may only mount these volume types.
var restrictedAllowedVolumeTypes = map[string]struct{}{
	"configMap":             {},
	"csi":                   {},
	"downwardAPI":           {},
	"emptyDir":              {},
	"ephemeral":             {},
	"persistentVolumeClaim": {},
	"projected":             {},
	"secret":                {},
}

// evaluatePSS returns the list of PSS control violations for pod at the given
// level. An empty slice means the pod is compliant. Restricted implies baseline:
// a restricted evaluation runs every baseline control plus the restricted ones.
func evaluatePSS(pod *corev1.Pod, level PSSLevel) []string {
	if pod == nil {
		return nil
	}
	var v []string
	v = append(v, pssBaselineViolations(pod)...)
	if level == PSSLevelRestricted {
		v = append(v, pssRestrictedViolations(pod)...)
	}
	return v
}

// pssContainer is a normalized view over regular/init/ephemeral containers so a
// single control loop covers all three. Ephemeral containers share the same
// SecurityContext type and are subject to the same PSS controls.
type pssContainer struct {
	role  string // "container" | "initContainer" | "ephemeralContainer"
	name  string
	sc    *corev1.SecurityContext
	ports []corev1.ContainerPort
}

func pssContainers(pod *corev1.Pod) []pssContainer {
	out := make([]pssContainer, 0,
		len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers))
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		out = append(out, pssContainer{role: "container", name: c.Name, sc: c.SecurityContext, ports: c.Ports})
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		out = append(out, pssContainer{role: "initContainer", name: c.Name, sc: c.SecurityContext, ports: c.Ports})
	}
	for i := range pod.Spec.EphemeralContainers {
		c := &pod.Spec.EphemeralContainers[i]
		out = append(out, pssContainer{role: "ephemeralContainer", name: c.Name, sc: c.SecurityContext, ports: c.Ports})
	}
	return out
}

func pssBaselineViolations(pod *corev1.Pod) []string {
	var v []string

	// --- Host namespaces ---
	if pod.Spec.HostNetwork {
		v = append(v, "hostNetwork=true is not allowed")
	}
	if pod.Spec.HostPID {
		v = append(v, "hostPID=true is not allowed")
	}
	if pod.Spec.HostIPC {
		v = append(v, "hostIPC=true is not allowed")
	}

	// --- hostPath volumes + restricted-but-baseline-irrelevant volumes ---
	for _, vol := range pod.Spec.Volumes {
		if vol.HostPath != nil {
			v = append(v, fmt.Sprintf("volume %q uses a hostPath", vol.Name))
		}
	}

	// --- sysctls (safe set) ---
	if pod.Spec.SecurityContext != nil {
		for _, s := range pod.Spec.SecurityContext.Sysctls {
			if _, ok := safeSysctls[s.Name]; !ok {
				v = append(v, fmt.Sprintf("sysctl %q is not in the safe set", s.Name))
			}
		}
	}

	// --- pod-level SELinux options ---
	if pod.Spec.SecurityContext != nil {
		v = append(v, pssSELinuxViolations("pod", pod.Spec.SecurityContext.SELinuxOptions)...)
	}

	// --- pod-level seccomp (Unconfined disallowed at baseline) ---
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
		if pod.Spec.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
			v = append(v, "pod seccompProfile is Unconfined")
		}
	}

	// --- pod-level AppArmor (legacy annotations) ---
	v = append(v, pssAppArmorAnnotationViolations(pod)...)

	// --- per-container controls ---
	for _, c := range pssContainers(pod) {
		label := fmt.Sprintf("%s %q", c.role, c.name)

		// privileged
		if c.sc != nil && c.sc.Privileged != nil && *c.sc.Privileged {
			v = append(v, fmt.Sprintf("%s is privileged", label))
		}

		// host ports
		for _, p := range c.ports {
			if p.HostPort != 0 {
				v = append(v, fmt.Sprintf("%s uses hostPort %d", label, p.HostPort))
			}
		}

		// capabilities (baseline: only the allowed add set)
		if c.sc != nil && c.sc.Capabilities != nil {
			for _, add := range c.sc.Capabilities.Add {
				name := strings.ToUpper(strings.TrimSpace(string(add)))
				if _, ok := baselineAllowedCapabilities[name]; !ok {
					v = append(v, fmt.Sprintf("%s adds disallowed capability %q", label, name))
				}
			}
		}

		// procMount other than Default
		if c.sc != nil && c.sc.ProcMount != nil && *c.sc.ProcMount != corev1.DefaultProcMount {
			v = append(v, fmt.Sprintf("%s sets procMount=%q (only Default allowed)", label, *c.sc.ProcMount))
		}

		// SELinux options
		if c.sc != nil {
			v = append(v, pssSELinuxViolations(label, c.sc.SELinuxOptions)...)
		}

		// seccomp Unconfined
		if c.sc != nil && c.sc.SeccompProfile != nil && c.sc.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
			v = append(v, fmt.Sprintf("%s seccompProfile is Unconfined", label))
		}

		// AppArmor field Unconfined
		if c.sc != nil && c.sc.AppArmorProfile != nil && c.sc.AppArmorProfile.Type == corev1.AppArmorProfileTypeUnconfined {
			v = append(v, fmt.Sprintf("%s appArmorProfile is Unconfined", label))
		}
	}

	sort.Strings(v)
	return v
}

func pssRestrictedViolations(pod *corev1.Pod) []string {
	var v []string

	// --- restricted volume types ---
	for _, vol := range pod.Spec.Volumes {
		if t := volumeTypeName(vol); t != "" {
			if _, ok := restrictedAllowedVolumeTypes[t]; !ok {
				v = append(v, fmt.Sprintf("volume %q has restricted-disallowed type %q", vol.Name, t))
			}
		}
	}

	// Pod-level seccomp must be RuntimeDefault/Localhost unless every container
	// sets its own compliant profile. We compute pod-level compliance once.
	podSeccompOK := seccompProfileRestrictedOK(podSeccompProfile(pod))

	for _, c := range pssContainers(pod) {
		label := fmt.Sprintf("%s %q", c.role, c.name)

		// allowPrivilegeEscalation must be explicitly false
		if c.sc == nil || c.sc.AllowPrivilegeEscalation == nil || *c.sc.AllowPrivilegeEscalation {
			v = append(v, fmt.Sprintf("%s must set allowPrivilegeEscalation=false", label))
		}

		// capabilities: must drop ALL, may add only NET_BIND_SERVICE
		v = append(v, pssRestrictedCapabilityViolations(label, c.sc)...)

		// runAsNonRoot
		if !runAsNonRootRestrictedOK(pod, c.sc) {
			v = append(v, fmt.Sprintf("%s must run as non-root (runAsNonRoot=true and runAsUser!=0)", label))
		}

		// seccomp must be explicitly RuntimeDefault/Localhost (container or pod)
		ctrSeccomp := c.sc != nil && c.sc.SeccompProfile != nil
		if ctrSeccomp {
			if !seccompProfileRestrictedOK(c.sc.SeccompProfile) {
				v = append(v, fmt.Sprintf("%s seccompProfile must be RuntimeDefault or Localhost", label))
			}
		} else if !podSeccompOK {
			v = append(v, fmt.Sprintf("%s has no compliant seccompProfile (set RuntimeDefault or Localhost)", label))
		}
	}

	sort.Strings(v)
	return v
}

func pssRestrictedCapabilityViolations(label string, sc *corev1.SecurityContext) []string {
	var v []string
	if sc == nil || sc.Capabilities == nil {
		return []string{fmt.Sprintf("%s must drop ALL capabilities", label)}
	}
	dropsAll := false
	for _, d := range sc.Capabilities.Drop {
		if strings.EqualFold(strings.TrimSpace(string(d)), "ALL") {
			dropsAll = true
			break
		}
	}
	if !dropsAll {
		v = append(v, fmt.Sprintf("%s must drop ALL capabilities", label))
	}
	for _, add := range sc.Capabilities.Add {
		name := strings.ToUpper(strings.TrimSpace(string(add)))
		if _, ok := restrictedAllowedCapabilities[name]; !ok {
			v = append(v, fmt.Sprintf("%s adds restricted-disallowed capability %q (only NET_BIND_SERVICE allowed)", label, name))
		}
	}
	return v
}

// runAsNonRootRestrictedOK reports whether the container satisfies the
// restricted runAsNonRoot control, honoring pod-level inheritance and the
// runAsUser!=0 requirement. The effective runAsNonRoot is true only when it is
// explicitly set true at the container or pod level; runAsUser must not be 0 at
// either level.
func runAsNonRootRestrictedOK(pod *corev1.Pod, sc *corev1.SecurityContext) bool {
	var podSC *corev1.PodSecurityContext
	if pod != nil {
		podSC = pod.Spec.SecurityContext
	}

	// runAsUser=0 anywhere fails outright.
	if sc != nil && sc.RunAsUser != nil && *sc.RunAsUser == 0 {
		return false
	}
	if podSC != nil && podSC.RunAsUser != nil && *podSC.RunAsUser == 0 {
		// A container-level non-zero runAsUser would override, but if the
		// container does not set one, the pod's 0 applies.
		if sc == nil || sc.RunAsUser == nil {
			return false
		}
	}

	// Effective runAsNonRoot: container value wins, else pod value, else unset.
	if sc != nil && sc.RunAsNonRoot != nil {
		return *sc.RunAsNonRoot
	}
	if podSC != nil && podSC.RunAsNonRoot != nil {
		return *podSC.RunAsNonRoot
	}
	return false
}

func podSeccompProfile(pod *corev1.Pod) *corev1.SeccompProfile {
	if pod != nil && pod.Spec.SecurityContext != nil {
		return pod.Spec.SecurityContext.SeccompProfile
	}
	return nil
}

func seccompProfileRestrictedOK(p *corev1.SeccompProfile) bool {
	if p == nil {
		return false
	}
	return p.Type == corev1.SeccompProfileTypeRuntimeDefault || p.Type == corev1.SeccompProfileTypeLocalhost
}

// pssSELinuxViolations checks SELinux options against the PSS allowed set.
// Baseline allows only type "" (unset), "container_t", "container_init_t", or
// "container_kvm_t", and forbids setting user or role at all.
func pssSELinuxViolations(label string, opts *corev1.SELinuxOptions) []string {
	if opts == nil {
		return nil
	}
	var v []string
	switch opts.Type {
	case "", "container_t", "container_init_t", "container_kvm_t":
	default:
		v = append(v, fmt.Sprintf("%s sets disallowed seLinuxOptions.type %q", label, opts.Type))
	}
	if opts.User != "" {
		v = append(v, fmt.Sprintf("%s sets seLinuxOptions.user (forbidden)", label))
	}
	if opts.Role != "" {
		v = append(v, fmt.Sprintf("%s sets seLinuxOptions.role (forbidden)", label))
	}
	return v
}

// pssAppArmorAnnotationViolations flags the deprecated AppArmor beta annotations
// when they request the unconfined profile. The field-based AppArmor profile is
// checked per-container in the main loop.
func pssAppArmorAnnotationViolations(pod *corev1.Pod) []string {
	var v []string
	for k, val := range pod.Annotations {
		if !strings.HasPrefix(k, corev1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix) {
			continue
		}
		if val == corev1.DeprecatedAppArmorBetaProfileNameUnconfined {
			ctr := strings.TrimPrefix(k, corev1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix)
			v = append(v, fmt.Sprintf("container %q AppArmor annotation requests Unconfined", ctr))
		}
	}
	return v
}

// volumeTypeName returns the populated volume-source field name for vol, or ""
// if none is set. Only the fields PSS restricts/allows need exact names; the
// rest fall through to the source's struct field name via the lookup table.
func volumeTypeName(vol corev1.Volume) string {
	switch {
	case vol.HostPath != nil:
		return "hostPath"
	case vol.EmptyDir != nil:
		return "emptyDir"
	case vol.Secret != nil:
		return "secret"
	case vol.ConfigMap != nil:
		return "configMap"
	case vol.DownwardAPI != nil:
		return "downwardAPI"
	case vol.Projected != nil:
		return "projected"
	case vol.PersistentVolumeClaim != nil:
		return "persistentVolumeClaim"
	case vol.CSI != nil:
		return "csi"
	case vol.Ephemeral != nil:
		return "ephemeral"
	case vol.GCEPersistentDisk != nil:
		return "gcePersistentDisk"
	case vol.AWSElasticBlockStore != nil:
		return "awsElasticBlockStore"
	case vol.NFS != nil:
		return "nfs"
	case vol.ISCSI != nil:
		return "iscsi"
	case vol.Glusterfs != nil:
		return "glusterfs"
	case vol.RBD != nil:
		return "rbd"
	case vol.FlexVolume != nil:
		return "flexVolume"
	case vol.Cinder != nil:
		return "cinder"
	case vol.CephFS != nil:
		return "cephfs"
	case vol.Flocker != nil:
		return "flocker"
	case vol.FC != nil:
		return "fc"
	case vol.AzureFile != nil:
		return "azureFile"
	case vol.VsphereVolume != nil:
		return "vsphereVolume"
	case vol.Quobyte != nil:
		return "quobyte"
	case vol.AzureDisk != nil:
		return "azureDisk"
	case vol.PhotonPersistentDisk != nil:
		return "photonPersistentDisk"
	case vol.PortworxVolume != nil:
		return "portworxVolume"
	case vol.ScaleIO != nil:
		return "scaleIO"
	case vol.StorageOS != nil:
		return "storageos"
	case vol.GitRepo != nil:
		return "gitRepo"
	case vol.Image != nil:
		return "image"
	default:
		return ""
	}
}
