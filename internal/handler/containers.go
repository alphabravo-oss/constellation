package handler

import (
	"time"
)

// containerRow is one running container in the cluster, aggregated across every node's
// runtime-agent container inventory and enriched with its workload's security posture.
// This is the per-running-container view NeuVector's Assets → Containers page shows;
// Constellation previously only aggregated to the deployment level.
type containerRow struct {
	RowID        string    `json:"row_id"`
	Node         string    `json:"node"`
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Namespace    string    `json:"namespace"`
	PlatformRole string    `json:"platform_role,omitempty"`
	PodName      string    `json:"pod_name"`
	Image        string    `json:"image"`
	State        string    `json:"state"`
	Workload     string    `json:"workload,omitempty"`
	Privileged   bool      `json:"privileged"`
	RunAsRoot    bool      `json:"run_as_root"`
	RiskScore    int       `json:"risk_score"`
	Critical     int       `json:"critical"`
	High         int       `json:"high"`
	ObservedAt   time.Time `json:"observed_at"`
}

// Containers returns the cluster's running containers by unnesting each node's
// host_containers inventory, best-effort mapped to their owning deployment (pod name
// starts with the deployment name) for privileged/root/risk enrichment.
//
//	GET /api/v1/clusters/{id}/containers
