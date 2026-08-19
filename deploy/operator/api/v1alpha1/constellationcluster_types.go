// Package v1alpha1 defines the ConstellationCluster CRD.
//
// ConstellationCluster owns the lifecycle of in-cluster Constellation components on a single
// Kubernetes cluster. The operator reconciles its Spec into Deployments (scanner aggregator,
// admission webhook) and DaemonSets (eBPF + L7 DPI + WAF + DLP + Falco agent).
// Scheduled platform jobs such as audit archiving and VulnDB importing are Helm-managed.
//
// Pluggable subsystems (scanner / admission / runtime) can each be independently enabled,
// matching the spec's "every pillar individually installable" goal.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConstellationClusterSpec is the desired state of a Constellation install.
type ConstellationClusterSpec struct {
	// ControlPlaneURL is the Constellation control-plane API base URL.
	// Required even in Astronomer-mode, because the agent dials this directly when not
	// riding the Astronomer multiplex.
	ControlPlaneURL string `json:"controlPlaneURL"`

	// OrgID is the Constellation org this cluster reports to.
	OrgID string `json:"orgID"`

	// ScannerEnabled toggles the scanner aggregator (ClairCore + Syft + Trivy + Grype + IaC).
	ScannerEnabled bool `json:"scannerEnabled"`

	// AdmissionEnabled toggles the Kyverno-fronted admission webhook.
	AdmissionEnabled bool `json:"admissionEnabled"`

	// RuntimeEnabled toggles the eBPF + L7 DPI + WAF + DLP + Falco agent DaemonSet.
	RuntimeEnabled bool `json:"runtimeEnabled"`

	// AgentImage overrides the legacy single-image agent (kept for compatibility; the four
	// scaling-unit images below are preferred and override AgentImage when both are set).
	AgentImage string `json:"agentImage,omitempty"`

	// ScannerImage / AdmissionImage / RuntimeAgentImage override the role-specific images.
	// Airgap deployments mirror these into the customer registry and point the CR at them.
	ScannerImage      string `json:"scannerImage,omitempty"`
	AdmissionImage    string `json:"admissionImage,omitempty"`
	RuntimeAgentImage string `json:"runtimeAgentImage,omitempty"`

	// ScannerReplicas / AdmissionReplicas tune horizontal scaling for those Deployments.
	// Defaults: 2 scanner replicas, 2 admission replicas.
	ScannerReplicas   *int32 `json:"scannerReplicas,omitempty"`
	AdmissionReplicas *int32 `json:"admissionReplicas,omitempty"`

	// ScannerAutoscale toggles HorizontalPodAutoscaler creation for the scanner Deployment.
	ScannerAutoscale *ScannerAutoscale `json:"scannerAutoscale,omitempty"`

	// AgentResources caps the per-node agent resource requests.
	AgentResources *AgentResources `json:"agentResources,omitempty"`
}

// AgentResources caps the per-node agent CPU + memory.
type AgentResources struct {
	CPULimit    string `json:"cpuLimit,omitempty"`
	MemoryLimit string `json:"memoryLimit,omitempty"`
}

// ScannerAutoscale configures the scanner Deployment's HorizontalPodAutoscaler.
type ScannerAutoscale struct {
	Enabled              bool  `json:"enabled"`
	MinReplicas          int32 `json:"minReplicas,omitempty"`
	MaxReplicas          int32 `json:"maxReplicas,omitempty"`
	TargetCPUUtilization int32 `json:"targetCPUUtilization,omitempty"`
}

// ConstellationClusterStatus is the observed state.
type ConstellationClusterStatus struct {
	Phase              string             `json:"phase"`
	AgentVersion       string             `json:"agentVersion,omitempty"`
	LastHeartbeat      *metav1.Time       `json:"lastHeartbeat,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cc
// +kubebuilder:printcolumn:name="Scanner",type=boolean,JSONPath=`.spec.scannerEnabled`
// +kubebuilder:printcolumn:name="Admission",type=boolean,JSONPath=`.spec.admissionEnabled`
// +kubebuilder:printcolumn:name="Runtime",type=boolean,JSONPath=`.spec.runtimeEnabled`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// ConstellationCluster is the Schema for the constellationclusters API.
type ConstellationCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConstellationClusterSpec   `json:"spec,omitempty"`
	Status            ConstellationClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ConstellationClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstellationCluster `json:"items"`
}

// DeepCopy / DeepCopyInto / DeepCopyObject implementations live in zz_generated_deepcopy.go.
// (Written manually rather than controller-gen-emitted, but follow the same conventions so a
// future controller-gen run can overwrite cleanly.)
