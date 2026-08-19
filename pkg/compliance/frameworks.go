// Package compliance is the framework registry + ingest pipeline for posture / compliance
// checks. Inputs come from kube-bench (CIS Kubernetes), kubescape (NSA-CISA), trivy
// config (CIS Docker), and our own internal checks; outputs are rows in compliance_checks.
//
// Frameworks supported at v1 (per spec FR-4 + Phase 3):
//
//	CIS Kubernetes (1.9), CIS Docker, NIST 800-53 rev5, NIST 800-190,
//	NSA-CISA K8s Hardening, PCI-DSS 4.0, HIPAA, SOC 2, STIG, FedRAMP Moderate,
//	NIS2 (EU), DORA (EU finance), ISO 27001/27017/27018, CSA CCM.
//
// Each framework lists its control IDs and provides a Mapping table from internal check
// IDs to control IDs. The same internal check often maps to multiple frameworks (e.g.,
// "host networking forbidden" maps to CIS K8s 5.2.4 + NIST AC-4 + PCI-DSS 1.3 + ...).
package compliance

import "sort"

// Framework names. Use these constants instead of literal strings; they're persisted in the
// compliance_checks.framework column and surface in audit logs.
const (
	FrameworkCISK8s     = "cis-k8s-1.9"
	FrameworkCISDocker  = "cis-docker-1.6"
	FrameworkCISLinux   = "cis-linux-2.0"
	FrameworkNIST80053  = "nist-800-53-rev5"
	FrameworkNIST800190 = "nist-800-190"
	FrameworkNSACISA    = "nsa-cisa-k8s"
	FrameworkPCIDSS4    = "pci-dss-4.0"
	FrameworkHIPAA      = "hipaa"
	FrameworkSOC2       = "soc-2"
	FrameworkSTIG       = "stig"
	FrameworkFedRAMP    = "fedramp-moderate"
	FrameworkNIS2       = "nis2-eu"
	FrameworkDORA       = "dora-eu"
	FrameworkISO27001   = "iso-27001"
	FrameworkISO27017   = "iso-27017"
	FrameworkISO27018   = "iso-27018"
	FrameworkCSACCM     = "csa-ccm"
)

// AllFrameworks returns the canonical framework list for the /compliance/frameworks
// endpoint. Order is the order Constellation's UI displays them.
func AllFrameworks() []Framework {
	return []Framework{
		{ID: FrameworkCISK8s, Name: "CIS Kubernetes 1.9", Category: "kubernetes"},
		{ID: FrameworkCISDocker, Name: "CIS Docker 1.6", Category: "container"},
		{ID: FrameworkCISLinux, Name: "CIS Distribution Independent Linux 2.0", Category: "host"},
		{ID: FrameworkNSACISA, Name: "NSA-CISA K8s Hardening Guide", Category: "kubernetes"},
		{ID: FrameworkNIST80053, Name: "NIST SP 800-53 rev5", Category: "general"},
		{ID: FrameworkNIST800190, Name: "NIST SP 800-190 (Container Security)", Category: "container"},
		{ID: FrameworkPCIDSS4, Name: "PCI-DSS 4.0", Category: "payments"},
		{ID: FrameworkHIPAA, Name: "HIPAA Security Rule", Category: "healthcare"},
		{ID: FrameworkSOC2, Name: "SOC 2 (Trust Services)", Category: "general"},
		{ID: FrameworkSTIG, Name: "DISA STIG", Category: "government"},
		{ID: FrameworkFedRAMP, Name: "FedRAMP Moderate", Category: "government"},
		{ID: FrameworkNIS2, Name: "NIS2 (EU)", Category: "regulatory-eu"},
		{ID: FrameworkDORA, Name: "DORA (EU Finance)", Category: "regulatory-eu"},
		{ID: FrameworkISO27001, Name: "ISO 27001", Category: "international"},
		{ID: FrameworkISO27017, Name: "ISO 27017 (Cloud)", Category: "international"},
		{ID: FrameworkISO27018, Name: "ISO 27018 (Cloud PII)", Category: "international"},
		{ID: FrameworkCSACCM, Name: "CSA Cloud Controls Matrix", Category: "cloud"},
	}
}

// Framework is the descriptor for a compliance/regulatory framework.
type Framework struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// Check is one persisted control evaluation.
type Check struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`   // pass | fail | manual | not_applicable
	Severity    string `json:"severity"` // info | low | medium | high | critical
	Evidence    string `json:"evidence,omitempty"`
}

// Mapping is the cross-framework mapping for one internal check ID. When an internal check
// fires, the ingest pipeline expands it into one Check per framework listed here.
type Mapping struct {
	InternalID string
	Controls   map[string]string // framework -> control_id
	Title      string
	Severity   string
}

// CoreMappings is the v1 cross-framework mapping table. Hand-curated; aspires to ~200
// internal checks at GA. Each entry's `Controls` keys are framework IDs from above.
var CoreMappings = []Mapping{
	{
		InternalID: "k8s.api.audit-logging",
		Title:      "Kubernetes API server audit logging enabled",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:    "1.2.22",
			FrameworkNSACISA:   "Logging.AuditLog",
			FrameworkNIST80053: "AU-2",
			FrameworkPCIDSS4:   "10.2",
			FrameworkSOC2:      "CC7.2",
			FrameworkFedRAMP:   "AU-2",
			FrameworkISO27001:  "A.12.4.1",
		},
	},
	{
		InternalID: "k8s.api.anonymous-auth",
		Title:      "Kubernetes API server anonymous auth disabled",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:    "1.2.1",
			FrameworkNSACISA:   "Authentication.AnonymousDisabled",
			FrameworkNIST80053: "AC-3",
			FrameworkPCIDSS4:   "8.2",
			FrameworkFedRAMP:   "AC-3",
		},
	},
	{
		InternalID: "k8s.host-network-forbidden",
		Title:      "Pods may not use hostNetwork",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.2.4",
			FrameworkNSACISA:    "PodSecurity.HostNamespaces",
			FrameworkNIST800190: "4.4.1",
			FrameworkPCIDSS4:    "1.3.1",
		},
	},
	{
		InternalID: "k8s.privileged-containers-forbidden",
		Title:      "Privileged containers are forbidden",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.2.1",
			FrameworkNSACISA:    "PodSecurity.Privileged",
			FrameworkNIST800190: "4.5.4",
			FrameworkPCIDSS4:    "2.2.1",
			FrameworkSTIG:       "V-242397",
		},
	},
	{
		InternalID: "k8s.read-only-root-filesystem",
		Title:      "Containers should run with read-only root filesystems",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.7.4",
			FrameworkNSACISA:    "PodSecurity.ReadOnlyRootFS",
			FrameworkNIST800190: "4.5.5",
		},
	},
	{
		InternalID: "k8s.encryption-at-rest",
		Title:      "etcd encryption at rest is configured",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:    "1.2.31",
			FrameworkNIST80053: "SC-28",
			FrameworkPCIDSS4:   "3.4",
			FrameworkHIPAA:     "§164.312(a)(2)(iv)",
			FrameworkSOC2:      "CC6.7",
			FrameworkISO27001:  "A.10.1.1",
			FrameworkFedRAMP:   "SC-28",
		},
	},
	{
		InternalID: "k8s.rbac.no-wildcard-roles",
		Title:      "No ClusterRole grants wildcard verbs on wildcard resources",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:    "5.1.3",
			FrameworkNSACISA:   "Authorization.LeastPrivilege",
			FrameworkNIST80053: "AC-6",
			FrameworkPCIDSS4:   "7.1",
		},
	},
	{
		InternalID: "k8s.namespace.pod-security-enforce",
		Title:      "Namespaces enforce Pod Security Admission at baseline or restricted",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.2.2",
			FrameworkNSACISA:    "PodSecurity.Admission",
			FrameworkNIST800190: "4.4.1",
			FrameworkPCIDSS4:    "2.2.1",
			FrameworkSTIG:       "V-242397",
		},
	},
	{
		InternalID: "container.image-signature-required",
		Title:      "Images must be signed by a trusted identity",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkNIST800190: "4.2.2",
			FrameworkNSACISA:    "SupplyChain.Verify",
			FrameworkFedRAMP:    "SI-7",
			FrameworkCSACCM:     "STA-09",
		},
	},
	{
		InternalID: "container.image-secrets-absent",
		Title:      "Images contain no embedded secret findings",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkNIST800190: "4.2.4",
			FrameworkNSACISA:    "SupplyChain.Secrets",
			FrameworkNIST80053:  "SI-7",
			FrameworkPCIDSS4:    "6.2.4",
			FrameworkSOC2:       "CC6.1",
			FrameworkFedRAMP:    "SI-7",
			FrameworkCSACCM:     "STA-09",
		},
	},
	{
		InternalID: "container.image-file-risks-absent",
		Title:      "Images contain no risky filesystem metadata",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkNIST800190: "4.2.4",
			FrameworkNSACISA:    "SupplyChain.Hardening",
			FrameworkNIST80053:  "CM-7",
			FrameworkPCIDSS4:    "2.2.5",
			FrameworkSOC2:       "CC6.8",
			FrameworkFedRAMP:    "CM-7",
			FrameworkCSACCM:     "IVS-06",
		},
	},
	{
		InternalID: "data.pii-redaction-enabled",
		Title:      "PII redaction is enabled on findings + audit payloads",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkISO27018: "A.4",
			FrameworkNIS2:     "Art.21.2(d)",
			FrameworkDORA:     "Art.9",
			FrameworkHIPAA:    "§164.312(e)",
		},
	},
	{
		InternalID: "host.fs.cramfs-disabled",
		Title:      "cramfs filesystem module is disabled",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISLinux:  "1.1.1.1",
			FrameworkNIST80053: "CM-7",
			FrameworkPCIDSS4:   "2.2.5",
		},
	},
	{
		InternalID: "host.fs.squashfs-disabled",
		Title:      "squashfs filesystem module is disabled",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISLinux:  "1.1.1.2",
			FrameworkNIST80053: "CM-7",
			FrameworkPCIDSS4:   "2.2.5",
		},
	},
	{
		InternalID: "host.net.source-route-disabled",
		Title:      "IPv4 source-routed packets are not accepted",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISLinux:  "3.2.1",
			FrameworkNIST80053: "SC-7",
			FrameworkPCIDSS4:   "1.2.1",
		},
	},
	{
		InternalID: "host.net.redirects-disabled",
		Title:      "IPv4 ICMP redirects are not accepted",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISLinux:  "3.2.2",
			FrameworkNIST80053: "SC-7",
			FrameworkPCIDSS4:   "1.2.1",
		},
	},
	{
		InternalID: "host.net.tcp-syncookies-enabled",
		Title:      "TCP SYN cookies are enabled",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISLinux:  "3.3.1",
			FrameworkNIST80053: "SC-5",
		},
	},
	{
		InternalID: "host.file.passwd-mode",
		Title:      "/etc/passwd permissions are 0644 or stricter",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISLinux:  "5.1.2",
			FrameworkNIST80053: "AC-6",
			FrameworkPCIDSS4:   "7.2.5",
		},
	},
	{
		InternalID: "host.file.shadow-mode",
		Title:      "/etc/shadow permissions are 0640 or stricter",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISLinux:  "5.1.3",
			FrameworkNIST80053: "AC-6",
			FrameworkPCIDSS4:   "7.2.5",
		},
	},
	{
		InternalID: "host.ssh.root-login-disabled",
		Title:      "SSH root login is disabled",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISLinux:  "5.2.5",
			FrameworkNIST80053: "AC-2",
			FrameworkPCIDSS4:   "8.2.2",
		},
	},
	{
		InternalID: "host.ssh.password-auth-disabled",
		Title:      "SSH password authentication is disabled",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISLinux:  "5.2.10",
			FrameworkNIST80053: "IA-5",
			FrameworkPCIDSS4:   "8.3.1",
		},
	},
	{
		InternalID: "host.file.sshd-config-mode",
		Title:      "/etc/ssh/sshd_config permissions are 0600 or stricter",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISLinux:  "6.1.2",
			FrameworkNIST80053: "AC-6",
		},
	},
	{
		InternalID: "k8s.api.kubelet-cert-authority",
		Title:      "API server verifies kubelet certificate authority",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:    "1.2.6",
			FrameworkNSACISA:   "Authentication.KubeletCA",
			FrameworkNIST80053: "SC-8",
			FrameworkPCIDSS4:   "4.2.1",
			FrameworkFedRAMP:   "SC-8",
		},
	},
	{
		InternalID: "k8s.api.always-pull-images",
		Title:      "API server enables AlwaysPullImages admission controller",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:     "1.2.11",
			FrameworkNIST800190: "4.2.2",
			FrameworkNSACISA:    "SupplyChain.PullPolicy",
		},
	},
	{
		InternalID: "k8s.api.namespace-lifecycle",
		Title:      "API server enables NamespaceLifecycle admission controller",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:    "1.2.13",
			FrameworkNIST80053: "CM-7",
		},
	},
	{
		InternalID: "k8s.controller-manager.profiling-disabled",
		Title:      "Controller manager profiling is disabled",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:    "1.3.2",
			FrameworkNIST80053: "CM-7",
			FrameworkPCIDSS4:   "2.2.5",
		},
	},
	{
		InternalID: "k8s.scheduler.profiling-disabled",
		Title:      "Scheduler profiling is disabled",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:    "1.4.1",
			FrameworkNIST80053: "CM-7",
			FrameworkPCIDSS4:   "2.2.5",
		},
	},
	{
		InternalID: "k8s.etcd.client-cert-auth",
		Title:      "etcd is configured for client certificate authentication",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:    "2.2",
			FrameworkNIST80053: "IA-2",
			FrameworkPCIDSS4:   "8.2",
			FrameworkSOC2:      "CC6.1",
			FrameworkFedRAMP:   "IA-2",
		},
	},
	{
		InternalID: "k8s.etcd.peer-tls",
		Title:      "etcd peer communication is encrypted with TLS",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:    "2.5",
			FrameworkNIST80053: "SC-8",
			FrameworkPCIDSS4:   "4.2.1",
			FrameworkFedRAMP:   "SC-8",
		},
	},
	{
		InternalID: "k8s.rbac.default-service-account-unused",
		Title:      "Default service accounts are not actively used",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:    "5.1.5",
			FrameworkNSACISA:   "Authorization.LeastPrivilege",
			FrameworkNIST80053: "AC-6",
			FrameworkPCIDSS4:   "7.1",
		},
	},
	{
		InternalID: "k8s.rbac.service-account-token-opt-in",
		Title:      "Service account tokens are mounted only where required",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:    "5.1.6",
			FrameworkNSACISA:   "Authorization.LeastPrivilege",
			FrameworkNIST80053: "AC-6",
		},
	},
	{
		InternalID: "k8s.host-pid-forbidden",
		Title:      "Pods may not share the host process ID namespace",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.2.3",
			FrameworkNSACISA:    "PodSecurity.HostNamespaces",
			FrameworkNIST800190: "4.4.1",
			FrameworkPCIDSS4:    "1.3.1",
		},
	},
	{
		InternalID: "k8s.host-ipc-forbidden",
		Title:      "Pods may not share the host IPC namespace",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.2.5",
			FrameworkNSACISA:    "PodSecurity.HostNamespaces",
			FrameworkNIST800190: "4.4.1",
			FrameworkPCIDSS4:    "1.3.1",
		},
	},
	{
		InternalID: "k8s.privilege-escalation-forbidden",
		Title:      "Containers may not allow privilege escalation",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.2.6",
			FrameworkNSACISA:    "PodSecurity.NoPrivilegeEscalation",
			FrameworkNIST800190: "4.5.4",
			FrameworkPCIDSS4:    "2.2.1",
		},
	},
	{
		InternalID: "k8s.run-as-non-root",
		Title:      "Containers must run as a non-root user",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.2.7",
			FrameworkNSACISA:    "PodSecurity.RunAsNonRoot",
			FrameworkNIST800190: "4.5.1",
			FrameworkPCIDSS4:    "2.2.1",
		},
	},
	{
		InternalID: "k8s.capabilities-dropped",
		Title:      "Containers drop NET_RAW and other unneeded capabilities",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.2.9",
			FrameworkNSACISA:    "PodSecurity.Capabilities",
			FrameworkNIST800190: "4.5.3",
		},
	},
	{
		InternalID: "k8s.default-deny-network-policy",
		Title:      "Every namespace has a default-deny network policy",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:    "5.3.1",
			FrameworkNSACISA:   "Network.Segmentation",
			FrameworkNIST80053: "AC-4",
			FrameworkPCIDSS4:   "1.3.1",
			FrameworkSOC2:      "CC6.6",
		},
	},
	{
		InternalID: "k8s.secrets-as-files",
		Title:      "Secrets are mounted as files rather than environment variables",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:    "5.4.1",
			FrameworkNIST80053: "SC-28",
			FrameworkPCIDSS4:   "3.4",
		},
	},
	{
		InternalID: "k8s.default-namespace-unused",
		Title:      "The default namespace is not used for workloads",
		Severity:   "low",
		Controls: map[string]string{
			FrameworkCISK8s:    "5.7.1",
			FrameworkNSACISA:   "PodSecurity.Namespaces",
			FrameworkNIST80053: "CM-7",
		},
	},
	{
		InternalID: "k8s.seccomp-profile-set",
		Title:      "Pods set a seccomp profile (RuntimeDefault or stricter)",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.7.2",
			FrameworkNSACISA:    "PodSecurity.Seccomp",
			FrameworkNIST800190: "4.5.3",
		},
	},
	{
		InternalID: "k8s.security-context-applied",
		Title:      "Pods and containers apply a security context",
		Severity:   "medium",
		Controls: map[string]string{
			FrameworkCISK8s:     "5.7.3",
			FrameworkNSACISA:    "PodSecurity.SecurityContext",
			FrameworkNIST800190: "4.5.1",
		},
	},
	{
		InternalID: "workload.network-policy-enforced",
		Title:      "Workload traffic is governed by an applied network policy",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCISK8s:    "5.3.2",
			FrameworkNSACISA:   "Network.Segmentation",
			FrameworkNIST80053: "AC-4",
			FrameworkPCIDSS4:   "1.3.1",
			FrameworkSOC2:      "CC6.6",
		},
	},
	{
		InternalID: "workload.high-critical-vulnerabilities",
		Title:      "Workload has no unresolved high or critical findings",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkNIST800190: "4.2.4",
			FrameworkPCIDSS4:    "6.3.3",
			FrameworkSOC2:       "CC7.1",
			FrameworkFedRAMP:    "SI-2",
		},
	},
	{
		InternalID: "cloud.posture.open-findings",
		Title:      "Cloud resource posture findings are remediated",
		Severity:   "high",
		Controls: map[string]string{
			FrameworkCSACCM:    "DSP-03",
			FrameworkISO27017:  "CLD.6.3",
			FrameworkNIST80053: "CA-7",
			FrameworkSOC2:      "CC7.1",
		},
	},
}

// ControlIDsByFramework returns the union of control IDs per framework across the mapping
// table, sorted, dedup'd. Used to render the framework drill-down view.
func ControlIDsByFramework(framework string) []string {
	seen := map[string]struct{}{}
	for _, m := range CoreMappings {
		if id, ok := m.Controls[framework]; ok {
			seen[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// cisK8sToInternal is the reverse index of CoreMappings: a CIS Kubernetes control
// number (the FrameworkCISK8s value of each mapping) -> internal check id. It is the
// data-driven replacement for the old hand-maintained switch in kubebench.go, so
// adding a CIS K8s control to CoreMappings automatically wires its cross-framework
// expansion. Built once at init; a control number declared by two mappings is a
// table bug and panics here rather than silently shadowing.
//
// ponytail: a global init map rather than a per-call scan; the upgrade path is a
// full benchmark-aware registry (distro + version keyed) once managed profiles need
// their own mappings.
var cisK8sToInternal = buildCISK8sIndex()

func buildCISK8sIndex() map[string]string {
	idx := make(map[string]string)
	for _, m := range CoreMappings {
		ctrl, ok := m.Controls[FrameworkCISK8s]
		if !ok {
			continue
		}
		if prev, dup := idx[ctrl]; dup {
			panic("compliance: CIS K8s control " + ctrl + " mapped by both " + prev + " and " + m.InternalID)
		}
		idx[ctrl] = m.InternalID
	}
	return idx
}

// InternalIDForCISK8s returns the Constellation internal check id mapped to a CIS
// Kubernetes control number, or "" if none is registered in CoreMappings.
func InternalIDForCISK8s(controlID string) string {
	return cisK8sToInternal[controlID]
}

// MappingByInternalID returns the registered cross-framework mapping for an
// internal check id.
func MappingByInternalID(internalID string) (Mapping, bool) {
	for _, m := range CoreMappings {
		if m.InternalID == internalID {
			return m, true
		}
	}
	return Mapping{}, false
}

// ExpandInternal returns one Check per (framework, control) pair this internal check maps
// to. Used by the ingest pipeline to convert an engine result into compliance rows.
func ExpandInternal(internalID, status, evidence string) []Check {
	for _, m := range CoreMappings {
		if m.InternalID != internalID {
			continue
		}
		out := make([]Check, 0, len(m.Controls))
		for fw, controlID := range m.Controls {
			out = append(out, Check{
				Framework: fw,
				ControlID: controlID,
				Title:     m.Title,
				Status:    status,
				Severity:  m.Severity,
				Evidence:  evidence,
			})
		}
		return out
	}
	return nil
}
