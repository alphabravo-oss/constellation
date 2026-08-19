package admission

import (
	"log/slog"
	"sort"
)

// deprecatedProfileAliases maps retired, misleading profile IDs to their
// honest replacements. The original built-in profiles were named after the
// official Kubernetes Pod Security Standards ("baseline"/"restricted") even
// though they enforce only a small subset of those controls (~3-5 of ~15; see
// docs/admission-profiles.md). They were renamed to "basic-hardening" and
// "strict-hardening" so the names no longer imply full PSS conformance. The old
// IDs remain resolvable as aliases that log a deprecation warning.
var deprecatedProfileAliases = map[string]string{
	"baseline":   "basic-hardening",
	"restricted": "strict-hardening",
}

// resolveProfileID maps a possibly-deprecated profile ID to its canonical ID,
// logging a deprecation warning when an alias is used.
func resolveProfileID(id string) string {
	if canonical, ok := deprecatedProfileAliases[id]; ok {
		slog.Warn("admission profile name is deprecated",
			"requested", id,
			"use", canonical,
			"reason", "the old name implied full Pod Security Standards conformance; see docs/admission-profiles.md")
		return canonical
	}
	return id
}

// AdmissionProfile describes a curated admission policy bundle. Profiles are
// deterministic templates; importing one materializes its rules as rows in the
// existing policies table.
type AdmissionProfile struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	FailurePolicy     string                 `json:"failure_policy"`
	NamespaceSelector map[string]any         `json:"namespace_selector,omitempty"`
	Rules             []AdmissionProfileRule `json:"rules"`
}

// AdmissionProfileRule is one policy row template in a profile.
type AdmissionProfileRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Engine      string `json:"engine"`
	Category    string `json:"category"`
	Mode        string `json:"mode"`
	Enabled     bool   `json:"enabled"`
	SpecYAML    string `json:"spec_yaml"`
}

// AdmissionProfileBundle is the import/export envelope for admission rules.
type AdmissionProfileBundle struct {
	APIVersion string           `json:"api_version"`
	Kind       string           `json:"kind"`
	Profile    AdmissionProfile `json:"profile"`
}

const (
	AdmissionProfileAPIVersion = "constellation.alphabravo.io/v1alpha1"
	AdmissionProfileKind       = "AdmissionProfileBundle"
)

// BuiltInAdmissionProfiles returns all built-in admission profiles in stable order.
func BuiltInAdmissionProfiles() []AdmissionProfile {
	profiles := []AdmissionProfile{
		pssBaselineAdmissionProfile(),
		pssRestrictedAdmissionProfile(),
		basicHardeningAdmissionProfile(),
		strictHardeningAdmissionProfile(),
		imageProvenanceAdmissionProfile(),
		criticalVulnAdmissionProfile(),
		fixableVulnAdmissionProfile(),
		secretsMisconfigAdmissionProfile(),
		privilegedApprovalAdmissionProfile(),
		admissionExceptionAdmissionProfile(),
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return profiles
}

// BuiltInAdmissionProfile finds one built-in profile by id. Deprecated profile
// IDs ("baseline"/"restricted") resolve to their honest replacements and log a
// deprecation warning.
func BuiltInAdmissionProfile(id string) (AdmissionProfile, bool) {
	id = resolveProfileID(id)
	for _, profile := range BuiltInAdmissionProfiles() {
		if profile.ID == id {
			return profile, true
		}
	}
	return AdmissionProfile{}, false
}

// AdmissionProfileBundleFor wraps a profile in the stable import/export envelope.
func AdmissionProfileBundleFor(profile AdmissionProfile) AdmissionProfileBundle {
	return AdmissionProfileBundle{
		APIVersion: AdmissionProfileAPIVersion,
		Kind:       AdmissionProfileKind,
		Profile:    profile,
	}
}

// pssBaselineAdmissionProfile is the real Kubernetes Pod Security Standards
// "baseline" profile, backed by the pss.go engine. Unlike basic-hardening
// (which covers only a handful of controls), this enforces the full upstream
// baseline control set.
func pssBaselineAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:   "pss-baseline",
		Name: "Pod Security Standards: baseline",
		Description: "Enforces the full Kubernetes Pod Security Standards 'baseline' control set " +
			"(privileged, host namespaces, hostPath, hostPorts, capabilities allowlist, AppArmor, SELinux, seccomp, procMount, sysctls) " +
			"as pure pod-spec checks. See https://kubernetes.io/docs/concepts/security/pod-security-standards/.",
		FailurePolicy: "Fail",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/pss": "baseline"},
		},
		Rules: []AdmissionProfileRule{rulePodSecurityStandard("baseline", "enforce")},
	}
}

// pssRestrictedAdmissionProfile is the real Kubernetes Pod Security Standards
// "restricted" profile, backed by the pss.go engine. It enforces baseline plus
// the restricted hardening controls.
func pssRestrictedAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:   "pss-restricted",
		Name: "Pod Security Standards: restricted",
		Description: "Enforces the full Kubernetes Pod Security Standards 'restricted' control set: baseline plus " +
			"allowPrivilegeEscalation=false, runAsNonRoot, required RuntimeDefault/Localhost seccomp, drop-ALL capabilities " +
			"(only NET_BIND_SERVICE addable), and the restricted volume-type allowlist. " +
			"See https://kubernetes.io/docs/concepts/security/pod-security-standards/.",
		FailurePolicy: "Fail",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/pss": "restricted"},
		},
		Rules: []AdmissionProfileRule{rulePodSecurityStandard("restricted", "enforce")},
	}
}

func rulePodSecurityStandard(level, mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "pod-security-standards-" + level,
		Description: "Enforce the Kubernetes Pod Security Standards " + level + " control set.",
		Engine:      "constellation-admission",
		Category:    "pod-security-standards",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: pod-security-standards-` + level + `
spec:
  match:
    kinds: ["Pod"]
  podSecurityStandard:
    level: ` + level + `
  action: deny
`,
	}
}

func basicHardeningAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:   "basic-hardening",
		Name: "Basic hardening admission",
		Description: "Blocks the pod settings that most directly undermine node isolation (privileged, hostNetwork, hostPID) and reports image-provenance and read-only-root-filesystem gaps in monitor mode. " +
			"This is NOT the Kubernetes Pod Security Standards 'baseline' profile: it covers only a subset of those controls. See docs/admission-profiles.md.",
		FailurePolicy: "Ignore",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/admission": "basic-hardening"},
		},
		Rules: []AdmissionProfileRule{
			ruleBlockPrivileged("enforce"),
			ruleBlockHostNetwork("enforce"),
			ruleBlockHostPID("enforce"),
			ruleRequireImageSignature("monitor"),
			ruleRequireReadOnlyRootFS("monitor"),
		},
	}
}

func strictHardeningAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:   "strict-hardening",
		Name: "Strict hardening admission",
		Description: "Enforces the basic-hardening isolation controls plus read-only root filesystems, non-root execution, and immutable image references. " +
			"This is NOT the Kubernetes Pod Security Standards 'restricted' profile: it covers only a subset of those controls. See docs/admission-profiles.md.",
		FailurePolicy: "Fail",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/enforce": "true"},
		},
		Rules: []AdmissionProfileRule{
			ruleBlockPrivileged("enforce"),
			ruleBlockHostNetwork("enforce"),
			ruleBlockHostPID("enforce"),
			ruleRequireReadOnlyRootFS("enforce"),
			ruleRequireNonRoot("enforce"),
			ruleDisallowLatestTag("enforce"),
		},
	}
}

func imageProvenanceAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:            "image-provenance-required",
		Name:          "Image provenance required",
		Description:   "Requires digest-pinned images, manifest provenance, and trusted Constellation image-signature scan evidence before a pod can be admitted.",
		FailurePolicy: "Fail",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/enforce": "true"},
		},
		Rules: []AdmissionProfileRule{
			ruleRequireImageSignature("enforce"),
			ruleRequireTrustedImageScanSignature("enforce"),
			ruleRequireDigestPinnedImages("enforce"),
		},
	}
}

func criticalVulnAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:            "critical-vulnerabilities-blocked",
		Name:          "Critical vulnerabilities blocked",
		Description:   "Blocks workloads whose resolved image findings include critical vulnerabilities without an active exception.",
		FailurePolicy: "Fail",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/enforce": "true"},
		},
		Rules: []AdmissionProfileRule{
			{
				Name:        "block-critical-vulnerabilities",
				Description: "Deny images with unresolved critical vulnerabilities.",
				Engine:      "constellation-admission",
				Category:    "vulnerability-gating",
				Mode:        "enforce",
				Enabled:     true,
				SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-critical-vulnerabilities
spec:
  match:
    kinds: ["Pod"]
  scanEvidence:
    maxAge: 24h
    requireVulnDBBundle: true
    canonicalEngines: ["vulndb"]
  vulnerability:
    maxAllowedSeverity: high
    requireKnownScanResult: true
    honorActiveExceptions: true
  action: deny
`,
			},
		},
	}
}

func fixableVulnAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:            "fixable-vulnerabilities-blocked",
		Name:          "Fixable vulnerabilities blocked",
		Description:   "Blocks workloads whose fresh Constellation VulnDB scan evidence includes high or critical vulnerabilities with a known fixed version.",
		FailurePolicy: "Fail",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/enforce": "true"},
		},
		Rules: []AdmissionProfileRule{
			{
				Name:        "block-fixable-high-vulnerabilities",
				Description: "Deny images with fixable high or critical vulnerabilities from canonical VulnDB evidence.",
				Engine:      "constellation-admission",
				Category:    "vulnerability-gating",
				Mode:        "enforce",
				Enabled:     true,
				SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-fixable-high-vulnerabilities
spec:
  match:
    kinds: ["Pod"]
  scanEvidence:
    maxAge: 24h
    requireVulnDBBundle: true
    canonicalEngines: ["vulndb"]
  vulnerability:
    maxAllowedSeverity: medium
    requireKnownScanResult: true
    honorActiveExceptions: true
    requireFixAvailable: true
  action: deny
`,
			},
		},
	}
}

func secretsMisconfigAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:            "secrets-misconfig-blocked",
		Name:          "Secrets, image file risks, and misconfigurations blocked",
		Description:   "Blocks workloads with scanner-confirmed image secrets, dangerous image filesystem metadata, or critical Kubernetes misconfiguration findings.",
		FailurePolicy: "Fail",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/enforce": "true"},
		},
		Rules: []AdmissionProfileRule{
			{
				Name:        "block-secret-exposure",
				Description: "Deny workloads whose manifests or images contain high-confidence secrets.",
				Engine:      "constellation-admission",
				Category:    "secrets",
				Mode:        "enforce",
				Enabled:     true,
				SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-secret-exposure
spec:
  match:
    kinds: ["Pod"]
  imageArtifacts:
    secrets:
      maxAllowed: 0
      minimumSeverity: high
  action: deny
`,
			},
			{
				Name:        "block-dangerous-image-files",
				Description: "Deny images with setuid, setgid, world-writable, device-node, or FIFO filesystem risk evidence.",
				Engine:      "constellation-admission",
				Category:    "image-file-risk",
				Mode:        "enforce",
				Enabled:     true,
				SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-dangerous-image-files
spec:
  match:
    kinds: ["Pod"]
  imageArtifacts:
    fileRisks:
      maxAllowed: 0
      minimumSeverity: medium
      riskTypes: ["setuid", "setgid", "world-writable-file", "device-node", "fifo"]
  action: deny
`,
			},
			{
				Name:        "block-critical-misconfiguration",
				Description: "Deny workloads with critical Kubernetes misconfiguration findings.",
				Engine:      "constellation-admission",
				Category:    "misconfiguration",
				Mode:        "enforce",
				Enabled:     true,
				SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-critical-misconfiguration
spec:
  match:
    kinds: ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
  findings:
    kinds: ["misconfiguration"]
    minimumSeverity: critical
  action: deny
`,
			},
		},
	}
}

func privilegedApprovalAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:            "privileged-workload-approval-required",
		Name:          "Privileged workload approval required",
		Description:   "Requires an explicit approval annotation for privileged workloads and host namespace usage.",
		FailurePolicy: "Fail",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/enforce": "true"},
		},
		Rules: []AdmissionProfileRule{
			{
				Name:        "require-approval-for-privileged-workloads",
				Description: "Deny privileged or host-namespace workloads unless a Constellation approval is attached.",
				Engine:      "constellation-admission",
				Category:    "admission",
				Mode:        "enforce",
				Enabled:     true,
				SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: require-approval-for-privileged-workloads
spec:
  match:
    kinds: ["Pod"]
  conditions:
    any:
      - field: spec.containers[*].securityContext.privileged
        equals: true
      - field: spec.initContainers[*].securityContext.privileged
        equals: true
      - field: spec.ephemeralContainers[*].securityContext.privileged
        equals: true
      - field: spec.hostNetwork
        equals: true
      - field: spec.hostPID
        equals: true
  requireApproval:
    annotation: constellation.alphabravo.io/privileged-approval
    approvedValues: ["approved"]
  action: deny
`,
			},
		},
	}
}

// admissionExceptionAdmissionProfile seeds an ALLOW/except carve-out (P1-3).
// An allow rule takes precedence over deny rules: a request that matches it is
// admitted before any deny rule is evaluated (NeuVector exception-before-deny).
//
// SAFETY: this ships in MONITOR mode. A monitor-mode allow rule only OBSERVES —
// it records a warning ("would carve out of deny rules") and lets deny
// evaluation continue, so importing this profile never silently widens
// admission. An operator must flip the rule to enforce to activate the
// carve-out. The seeded example carves cluster-system service accounts out of
// the broad deny rules so platform controllers are not blocked.
func admissionExceptionAdmissionProfile() AdmissionProfile {
	return AdmissionProfile{
		ID:   "admission-exceptions",
		Name: "Admission allow/except carve-outs",
		Description: "Allow/except rules that take precedence over deny rules: a matching request is admitted before any deny rule is evaluated (NeuVector exception-before-deny). " +
			"Ships in monitor mode; the seeded rule carves cluster-system service accounts out of the broad deny rules once flipped to enforce.",
		FailurePolicy: "Ignore",
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/admission": "exceptions"},
		},
		Rules: []AdmissionProfileRule{
			ruleAllowSystemServiceAccounts("monitor"),
		},
	}
}

// ruleAllowSystemServiceAccounts is an ALLOW/except carve-out for the
// kube-system controllers (matched by their service-account username). It
// reuses the existing identity matcher; a match short-circuits admission to
// ADMIT, bypassing deny rules.
func ruleAllowSystemServiceAccounts(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "allow-system-service-accounts",
		Description: "Carve kube-system service accounts out of the deny rules (allow/except takes precedence over deny).",
		Engine:      "constellation-admission",
		Category:    "admission-exception",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: allow-system-service-accounts
spec:
  match:
    kinds: ["Pod"]
  identity:
    userMatch: system:serviceaccount:kube-system:.*
  action: allow
`,
	}
}

func ruleBlockPrivileged(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "block-privileged",
		Description: "Deny privileged regular, init, and ephemeral containers.",
		Engine:      "constellation-admission",
		Category:    "admission",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-privileged
spec:
  match:
    kinds: ["Pod"]
  conditions:
    any:
      - field: spec.containers[*].securityContext.privileged
        equals: true
      - field: spec.initContainers[*].securityContext.privileged
        equals: true
      - field: spec.ephemeralContainers[*].securityContext.privileged
        equals: true
  action: deny
`,
	}
}

func ruleBlockHostNetwork(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "block-host-network",
		Description: "Deny pods that join the node network namespace.",
		Engine:      "constellation-admission",
		Category:    "admission",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-host-network
spec:
  match:
    kinds: ["Pod"]
  conditions:
    any:
      - field: spec.hostNetwork
        equals: true
  action: deny
`,
	}
}

func ruleBlockHostPID(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "block-host-pid",
		Description: "Deny pods that join the node PID namespace.",
		Engine:      "constellation-admission",
		Category:    "admission",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-host-pid
spec:
  match:
    kinds: ["Pod"]
  conditions:
    any:
      - field: spec.hostPID
        equals: true
  action: deny
`,
	}
}

func ruleRequireImageSignature(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "require-image-signature",
		Description: "Require Constellation image provenance evidence.",
		Engine:      "constellation-admission",
		Category:    "signature-verification",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: require-image-signature
spec:
  match:
    kinds: ["Pod"]
  provenance:
    requireSignatureAnnotation: constellation.alphabravo.io/image-signed
  action: deny
`,
	}
}

func ruleRequireTrustedImageScanSignature(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "require-trusted-image-scan-signature",
		Description: "Require trusted signature evidence from the latest Constellation image scan result.",
		Engine:      "constellation-admission",
		Category:    "signature-verification",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: require-trusted-image-scan-signature
spec:
  match:
    kinds: ["Pod"]
  scanEvidence:
    maxAge: 24h
  imageArtifacts:
    signature:
      requireKnownScanResult: true
      requireTrusted: true
      requireVerifierIdentity: true
  action: deny
`,
	}
}

func ruleRequireReadOnlyRootFS(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "require-read-only-rootfs",
		Description: "Require readOnlyRootFilesystem=true on every container.",
		Engine:      "constellation-admission",
		Category:    "admission",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: require-read-only-rootfs
spec:
  match:
    kinds: ["Pod"]
  containers:
    requireReadOnlyRootFilesystem: true
  action: deny
`,
	}
}

func ruleRequireNonRoot(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "require-non-root",
		Description: "Require pod and container security contexts to avoid UID 0.",
		Engine:      "constellation-admission",
		Category:    "admission",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: require-non-root
spec:
  match:
    kinds: ["Pod"]
  containers:
    requireNonRoot: true
  action: deny
`,
	}
}

func ruleDisallowLatestTag(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "disallow-latest-tag",
		Description: "Require immutable image references rather than latest or implicit tags.",
		Engine:      "constellation-admission",
		Category:    "admission",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: disallow-latest-tag
spec:
  match:
    kinds: ["Pod"]
  images:
    disallowLatestTag: true
    disallowImplicitTag: true
  action: deny
`,
	}
}

func ruleRequireDigestPinnedImages(mode string) AdmissionProfileRule {
	return AdmissionProfileRule{
		Name:        "require-digest-pinned-images",
		Description: "Require each admitted image reference to include a digest.",
		Engine:      "constellation-admission",
		Category:    "signature-verification",
		Mode:        mode,
		Enabled:     true,
		SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: require-digest-pinned-images
spec:
  match:
    kinds: ["Pod"]
  images:
    requireDigest: true
  action: deny
`,
	}
}
