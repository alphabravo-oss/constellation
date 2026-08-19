package admission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func pBool(b bool) *bool                                 { return &b }
func pInt64(i int64) *int64                              { return &i }
func pProc(p corev1.ProcMountType) *corev1.ProcMountType { return &p }

// compliantRestrictedSC returns a container SecurityContext that satisfies every
// restricted control, so individual tests can mutate exactly one field to prove
// that single control denies.
func compliantRestrictedSC() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: pBool(false),
		RunAsNonRoot:             pBool(true),
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
}

// compliantRestrictedPod returns a pod that passes both baseline and restricted.
func compliantRestrictedPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ok", Namespace: "default"},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   pBool(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
				SecurityContext: compliantRestrictedSC(),
			}},
		},
	}
}

// withContainerSC mutates the (single) container's security context via fn.
func withContainerSC(pod *corev1.Pod, fn func(*corev1.SecurityContext)) *corev1.Pod {
	out := pod.DeepCopy()
	if out.Spec.Containers[0].SecurityContext == nil {
		out.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{}
	}
	fn(out.Spec.Containers[0].SecurityContext)
	return out
}

// TestEvaluatePSS is the required table-driven test: (pod spec, profile) ->
// allow/deny across EVERY PSS control.
func TestEvaluatePSS(t *testing.T) {
	cases := []struct {
		name      string
		level     PSSLevel
		pod       *corev1.Pod
		wantDeny  bool
		wantMatch string // substring expected in the joined violations when denying
	}{
		// ---- compliant baselines ----
		{
			name:     "baseline/minimal compliant pod",
			level:    PSSLevelBaseline,
			pod:      &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "nginx"}}}},
			wantDeny: false,
		},
		{
			name:     "restricted/fully compliant pod",
			level:    PSSLevelRestricted,
			pod:      compliantRestrictedPod(),
			wantDeny: false,
		},

		// ---- privileged ----
		{
			name:  "baseline/privileged container denied",
			level: PSSLevelBaseline,
			pod: withContainerSC(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "x"}}}},
				func(sc *corev1.SecurityContext) { sc.Privileged = pBool(true) }),
			wantDeny:  true,
			wantMatch: "is privileged",
		},

		// ---- host namespaces ----
		{
			name:      "baseline/hostNetwork denied",
			level:     PSSLevelBaseline,
			pod:       &corev1.Pod{Spec: corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "c"}}}},
			wantDeny:  true,
			wantMatch: "hostNetwork",
		},
		{
			name:      "baseline/hostPID denied",
			level:     PSSLevelBaseline,
			pod:       &corev1.Pod{Spec: corev1.PodSpec{HostPID: true, Containers: []corev1.Container{{Name: "c"}}}},
			wantDeny:  true,
			wantMatch: "hostPID",
		},
		{
			name:      "baseline/hostIPC denied",
			level:     PSSLevelBaseline,
			pod:       &corev1.Pod{Spec: corev1.PodSpec{HostIPC: true, Containers: []corev1.Container{{Name: "c"}}}},
			wantDeny:  true,
			wantMatch: "hostIPC",
		},

		// ---- hostPath volumes ----
		{
			name:  "baseline/hostPath volume denied",
			level: PSSLevelBaseline,
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				Volumes:    []corev1.Volume{{Name: "h", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}}}},
				Containers: []corev1.Container{{Name: "c"}},
			}},
			wantDeny:  true,
			wantMatch: "hostPath",
		},

		// ---- host ports ----
		{
			name:  "baseline/hostPort denied",
			level: PSSLevelBaseline,
			pod: &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name:  "c",
				Ports: []corev1.ContainerPort{{HostPort: 8080, ContainerPort: 80}},
			}}}},
			wantDeny:  true,
			wantMatch: "hostPort",
		},

		// ---- capabilities (baseline disallowed set) ----
		{
			name:  "baseline/NET_ADMIN capability denied",
			level: PSSLevelBaseline,
			pod: withContainerSC(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
				func(sc *corev1.SecurityContext) {
					sc.Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}}
				}),
			wantDeny:  true,
			wantMatch: "disallowed capability",
		},
		{
			name:  "baseline/NET_BIND_SERVICE capability allowed",
			level: PSSLevelBaseline,
			pod: withContainerSC(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
				func(sc *corev1.SecurityContext) {
					sc.Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"NET_BIND_SERVICE"}}
				}),
			wantDeny: false,
		},

		// ---- AppArmor ----
		{
			name:  "baseline/AppArmor field Unconfined denied",
			level: PSSLevelBaseline,
			pod: withContainerSC(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
				func(sc *corev1.SecurityContext) {
					sc.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
				}),
			wantDeny:  true,
			wantMatch: "appArmorProfile is Unconfined",
		},
		{
			name:  "baseline/AppArmor annotation Unconfined denied",
			level: PSSLevelBaseline,
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
					corev1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix + "c": corev1.DeprecatedAppArmorBetaProfileNameUnconfined,
				}},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}},
			},
			wantDeny:  true,
			wantMatch: "AppArmor annotation requests Unconfined",
		},

		// ---- SELinux options ----
		{
			name:  "baseline/SELinux type override denied",
			level: PSSLevelBaseline,
			pod: withContainerSC(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
				func(sc *corev1.SecurityContext) {
					sc.SELinuxOptions = &corev1.SELinuxOptions{Type: "spc_t"}
				}),
			wantDeny:  true,
			wantMatch: "seLinuxOptions.type",
		},
		{
			name:  "baseline/SELinux user denied",
			level: PSSLevelBaseline,
			pod: withContainerSC(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
				func(sc *corev1.SecurityContext) {
					sc.SELinuxOptions = &corev1.SELinuxOptions{User: "system_u"}
				}),
			wantDeny:  true,
			wantMatch: "seLinuxOptions.user",
		},
		{
			name:  "baseline/SELinux container_t allowed",
			level: PSSLevelBaseline,
			pod: withContainerSC(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
				func(sc *corev1.SecurityContext) {
					sc.SELinuxOptions = &corev1.SELinuxOptions{Type: "container_t"}
				}),
			wantDeny: false,
		},

		// ---- seccomp ----
		{
			name:  "baseline/seccomp Unconfined denied",
			level: PSSLevelBaseline,
			pod: withContainerSC(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
				func(sc *corev1.SecurityContext) {
					sc.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
				}),
			wantDeny:  true,
			wantMatch: "seccompProfile is Unconfined",
		},

		// ---- procMount ----
		{
			name:  "baseline/procMount Unmasked denied",
			level: PSSLevelBaseline,
			pod: withContainerSC(&corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}},
				func(sc *corev1.SecurityContext) {
					sc.ProcMount = pProc(corev1.UnmaskedProcMount)
				}),
			wantDeny:  true,
			wantMatch: "procMount",
		},

		// ---- sysctls ----
		{
			name:  "baseline/unsafe sysctl denied",
			level: PSSLevelBaseline,
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{Sysctls: []corev1.Sysctl{{Name: "kernel.msgmax", Value: "1"}}},
				Containers:      []corev1.Container{{Name: "c"}},
			}},
			wantDeny:  true,
			wantMatch: "safe set",
		},
		{
			name:  "baseline/safe sysctl allowed",
			level: PSSLevelBaseline,
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{Sysctls: []corev1.Sysctl{{Name: "net.ipv4.tcp_syncookies", Value: "1"}}},
				Containers:      []corev1.Container{{Name: "c"}},
			}},
			wantDeny: false,
		},

		// ---- restricted: allowPrivilegeEscalation ----
		{
			name:  "restricted/allowPrivilegeEscalation unset denied",
			level: PSSLevelRestricted,
			pod: withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) {
				sc.AllowPrivilegeEscalation = nil
			}),
			wantDeny:  true,
			wantMatch: "allowPrivilegeEscalation=false",
		},
		{
			name:  "restricted/allowPrivilegeEscalation true denied",
			level: PSSLevelRestricted,
			pod: withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) {
				sc.AllowPrivilegeEscalation = pBool(true)
			}),
			wantDeny:  true,
			wantMatch: "allowPrivilegeEscalation=false",
		},

		// ---- restricted: runAsNonRoot ----
		{
			name:  "restricted/runAsNonRoot false denied",
			level: PSSLevelRestricted,
			pod: withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) {
				sc.RunAsNonRoot = pBool(false)
			}),
			wantDeny:  true,
			wantMatch: "non-root",
		},
		{
			name:  "restricted/runAsUser 0 denied",
			level: PSSLevelRestricted,
			pod: withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) {
				sc.RunAsUser = pInt64(0)
			}),
			wantDeny:  true,
			wantMatch: "non-root",
		},

		// ---- restricted: seccomp required ----
		{
			name:  "restricted/no seccomp denied",
			level: PSSLevelRestricted,
			pod: func() *corev1.Pod {
				p := withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) { sc.SeccompProfile = nil })
				p.Spec.SecurityContext.SeccompProfile = nil
				return p
			}(),
			wantDeny:  true,
			wantMatch: "seccompProfile",
		},
		{
			name:  "restricted/seccomp inherited from pod allowed",
			level: PSSLevelRestricted,
			pod: withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) {
				sc.SeccompProfile = nil // pod-level RuntimeDefault still applies
			}),
			wantDeny: false,
		},

		// ---- restricted: capabilities drop ALL ----
		{
			name:  "restricted/missing drop ALL denied",
			level: PSSLevelRestricted,
			pod: withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) {
				sc.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}}
			}),
			wantDeny:  true,
			wantMatch: "must drop ALL",
		},
		{
			name:  "restricted/add NET_BIND_SERVICE allowed",
			level: PSSLevelRestricted,
			pod: withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) {
				sc.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_BIND_SERVICE"}}
			}),
			wantDeny: false,
		},
		{
			name:  "restricted/add CHOWN denied (baseline allowed but restricted not)",
			level: PSSLevelRestricted,
			pod: withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) {
				sc.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"CHOWN"}}
			}),
			wantDeny:  true,
			wantMatch: "restricted-disallowed capability",
		},

		// ---- restricted: volume types ----
		{
			name:  "restricted/gitRepo volume denied",
			level: PSSLevelRestricted,
			pod: func() *corev1.Pod {
				p := compliantRestrictedPod()
				p.Spec.Volumes = []corev1.Volume{{Name: "g", VolumeSource: corev1.VolumeSource{GitRepo: &corev1.GitRepoVolumeSource{Repository: "x"}}}}
				return p
			}(),
			wantDeny:  true,
			wantMatch: "restricted-disallowed type",
		},
		{
			name:  "restricted/emptyDir volume allowed",
			level: PSSLevelRestricted,
			pod: func() *corev1.Pod {
				p := compliantRestrictedPod()
				p.Spec.Volumes = []corev1.Volume{{Name: "e", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
				return p
			}(),
			wantDeny: false,
		},

		// ---- restricted implies baseline ----
		{
			name:  "restricted/baseline privileged still denied",
			level: PSSLevelRestricted,
			pod: withContainerSC(compliantRestrictedPod(), func(sc *corev1.SecurityContext) {
				sc.Privileged = pBool(true)
			}),
			wantDeny:  true,
			wantMatch: "is privileged",
		},

		// ---- init / ephemeral containers are covered ----
		{
			name:  "baseline/privileged init container denied",
			level: PSSLevelBaseline,
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "init", SecurityContext: &corev1.SecurityContext{Privileged: pBool(true)}}},
				Containers:     []corev1.Container{{Name: "c"}},
			}},
			wantDeny:  true,
			wantMatch: "initContainer",
		},
		{
			name:  "baseline/privileged ephemeral container denied",
			level: PSSLevelBaseline,
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c"}},
				EphemeralContainers: []corev1.EphemeralContainer{{
					EphemeralContainerCommon: corev1.EphemeralContainerCommon{
						Name:            "debug",
						SecurityContext: &corev1.SecurityContext{Privileged: pBool(true)},
					},
				}},
			}},
			wantDeny:  true,
			wantMatch: "ephemeralContainer",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			violations := evaluatePSS(tc.pod, tc.level)
			gotDeny := len(violations) > 0
			joined := strings.Join(violations, "; ")
			if gotDeny != tc.wantDeny {
				t.Fatalf("deny=%v want %v; violations=%q", gotDeny, tc.wantDeny, joined)
			}
			if tc.wantDeny && tc.wantMatch != "" && !strings.Contains(joined, tc.wantMatch) {
				t.Fatalf("violations %q do not contain %q", joined, tc.wantMatch)
			}
		})
	}
}

// TestPSSProfilesDenyViaEngine proves the pss-baseline/pss-restricted built-in
// profiles map (YAML -> Rule -> PolicyEngine.Evaluate) onto the engine and deny
// a violating pod end-to-end.
func TestPSSProfilesDenyViaEngine(t *testing.T) {
	for _, profileID := range []string{"pss-baseline", "pss-restricted"} {
		t.Run(profileID, func(t *testing.T) {
			profile, ok := BuiltInAdmissionProfile(profileID)
			if !ok {
				t.Fatalf("profile %q missing", profileID)
			}
			if len(profile.Rules) != 1 {
				t.Fatalf("profile %q has %d rules, want 1", profileID, len(profile.Rules))
			}
			r := profile.Rules[0]
			rule, supported, err := RuleFromYAML(r.Name, r.Name, r.Description, r.Mode, r.SpecYAML)
			if err != nil {
				t.Fatalf("RuleFromYAML: %v", err)
			}
			if !supported {
				t.Fatalf("profile %q rule not supported by pod-spec engine", profileID)
			}
			wantLevel := strings.TrimPrefix(profileID, "pss-")
			if rule.Conditions.PSSLevel != wantLevel {
				t.Fatalf("PSSLevel=%q want %q", rule.Conditions.PSSLevel, wantLevel)
			}

			eng := &PolicyEngine{Rules: []Rule{rule}}

			// A privileged pod must be denied by both levels.
			bad := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "default"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "c", Image: "x", SecurityContext: &corev1.SecurityContext{Privileged: pBool(true)},
				}}},
			}
			if resp := evaluatePod(t, eng, bad); resp.Allowed {
				t.Fatalf("profile %q allowed a privileged pod", profileID)
			}

			// A compliant restricted pod must pass both levels.
			if resp := evaluatePod(t, eng, compliantRestrictedPod()); !resp.Allowed {
				t.Fatalf("profile %q denied a compliant pod: %s", profileID, resp.Result.Message)
			}
		})
	}
}

func evaluatePod(t *testing.T, eng *PolicyEngine, pod *corev1.Pod) *admissionv1.AdmissionResponse {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	req := &admissionv1.AdmissionRequest{
		UID:    "1",
		Kind:   metav1.GroupVersionKind{Kind: "Pod"},
		Object: runtime.RawExtension{Raw: raw},
	}
	return eng.Evaluate(context.Background(), req)
}
