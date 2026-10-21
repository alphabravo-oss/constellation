package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/alphabravocompany/constellation/internal/nodeinventory"
)

// Nodes aggregates NeuVector-style host posture around a Kubernetes node:
// host facts, package evidence, scanner status, host CVEs, CIS, containers,
// processes, and runtime-agent freshness.
type Nodes struct {
	db *db.DB
}

func NewNodes(d *db.DB) *Nodes {
	return &Nodes{db: d}
}

type NodeSummary struct {
	Node                   string     `json:"node"`
	ClusterID              uuid.UUID  `json:"cluster_id"`
	OSID                   string     `json:"os_id,omitempty"`
	OSVersionID            string     `json:"os_version_id,omitempty"`
	KernelRelease          string     `json:"kernel_release,omitempty"`
	Arch                   string     `json:"arch,omitempty"`
	CNIName                string     `json:"cni_name,omitempty"`
	CRIRuntime             string     `json:"cri_runtime,omitempty"`
	BTFPresent             *bool      `json:"btf_present,omitempty"`
	NFQueueCapable         *bool      `json:"nfqueue_capable,omitempty"`
	CPUCount               int        `json:"cpu_count,omitempty"`
	MemoryBytes            int64      `json:"memory_bytes,omitempty"`
	PackageCount           int        `json:"package_count"`
	PackageSource          string     `json:"package_source,omitempty"`
	ContainerCount         int        `json:"container_count"`
	ProcessCount           int        `json:"process_count"`
	CISProfile             string     `json:"cis_profile,omitempty"`
	CISPassed              int        `json:"cis_passed"`
	CISFailed              int        `json:"cis_failed"`
	CISWarned              int        `json:"cis_warned"`
	CISSkipped             int        `json:"cis_skipped"`
	CriticalVulns          int        `json:"critical_vulns"`
	HighVulns              int        `json:"high_vulns"`
	MediumVulns            int        `json:"medium_vulns"`
	LowVulns               int        `json:"low_vulns"`
	OpenVulns              int        `json:"open_vulns"`
	RuntimeAgentStatus     string     `json:"runtime_agent_status"`
	RuntimeAgentVersion    string     `json:"runtime_agent_version,omitempty"`
	RuntimeAgentLastSeenAt *time.Time `json:"runtime_agent_last_seen_at,omitempty"`
	ScanTargetID           *uuid.UUID `json:"scan_target_id,omitempty"`
	ScanStatus             string     `json:"scan_status"`
	InventoryHash          string     `json:"inventory_hash,omitempty"`
	LastScannedAt          *time.Time `json:"last_scanned_at,omitempty"`
	HostFactsObservedAt    *time.Time `json:"host_facts_observed_at,omitempty"`
	PackagesObservedAt     *time.Time `json:"packages_observed_at,omitempty"`
	ContainersObservedAt   *time.Time `json:"containers_observed_at,omitempty"`
	ProcessesObservedAt    *time.Time `json:"processes_observed_at,omitempty"`
	CISObservedAt          *time.Time `json:"cis_observed_at,omitempty"`
	LastSeenAt             time.Time  `json:"last_seen_at"`
	CoverageGaps           []string   `json:"coverage_gaps,omitempty"`
}

type NodeDetail struct {
	Node                   NodeSummary            `json:"node"`
	Facts                  json.RawMessage        `json:"facts,omitempty"`
	Packages               json.RawMessage        `json:"packages,omitempty"`
	Containers             json.RawMessage        `json:"containers,omitempty"`
	Processes              json.RawMessage        `json:"processes,omitempty"`
	CIS                    json.RawMessage        `json:"cis,omitempty"`
	Vulnerabilities        []NodeVulnerabilityRow `json:"vulnerabilities"`
	VulnerabilitiesTotal   int64                  `json:"vulnerabilities_total"`
	VulnerabilitiesLimit   int                    `json:"vulnerabilities_limit"`
	VulnerabilitiesHasMore bool                   `json:"vulnerabilities_has_more"`
}

func (h *Nodes) List(w http.ResponseWriter, r *http.Request) { h.writeNodeInventory(w, r, false) }

func (h *Nodes) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterID, ok := h.clusterIDFromRoute(w, r, subj.OrgID)
	if !ok {
		return
	}
	node := strings.TrimSpace(chi.URLParam(r, "node"))
	if node == "" {
		jsonError(w, http.StatusBadRequest, "node required")
		return
	}

	nodes, err := h.nodeSummaries(r, subj.OrgID, clusterID, node, false, 1, 0)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query node: "+err.Error())
		return
	}
	if len(nodes) == 0 {
		jsonError(w, http.StatusNotFound, "node not found")
		return
	}
	detail := NodeDetail{Node: nodes[0]}
	if detail.Facts, err = h.nodePayload(r, subj.OrgID, clusterID, node, "host_facts", "facts"); err != nil {
		jsonError(w, http.StatusInternalServerError, "host facts: "+err.Error())
		return
	}
	if detail.Packages, err = h.nodePayload(r, subj.OrgID, clusterID, node, "host_packages", "payload"); err != nil {
		jsonError(w, http.StatusInternalServerError, "host packages: "+err.Error())
		return
	}
	if detail.Containers, err = h.nodePayload(r, subj.OrgID, clusterID, node, "host_containers", "payload"); err != nil {
		jsonError(w, http.StatusInternalServerError, "host containers: "+err.Error())
		return
	}
	if detail.Processes, err = h.nodePayload(r, subj.OrgID, clusterID, node, "host_processes", "payload"); err != nil {
		jsonError(w, http.StatusInternalServerError, "host processes: "+err.Error())
		return
	}
	if detail.CIS, err = h.nodePayload(r, subj.OrgID, clusterID, node, "host_cis", "payload"); err != nil {
		jsonError(w, http.StatusInternalServerError, "host cis: "+err.Error())
		return
	}
	var vulnerabilityMeta inventorylist.Metadata
	detail.Vulnerabilities, vulnerabilityMeta, err = h.nodeVulnerabilities(r, subj.OrgID, clusterID, node)
	detail.VulnerabilitiesTotal = vulnerabilityMeta.Total
	detail.VulnerabilitiesLimit = 2000
	detail.VulnerabilitiesHasMore = vulnerabilityMeta.HasMore
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "host vulnerabilities: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *Nodes) clusterIDFromRoute(w http.ResponseWriter, r *http.Request, orgID uuid.UUID) (uuid.UUID, bool) {
	raw := strings.TrimSpace(chi.URLParam(r, "id"))
	clusterID, err := uuid.Parse(raw)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid cluster id")
		return uuid.Nil, false
	}
	var exists bool
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id = $1 AND id = $2)`,
		orgID, clusterID).Scan(&exists); err != nil {
		jsonError(w, http.StatusInternalServerError, "cluster lookup: "+err.Error())
		return uuid.Nil, false
	}
	if !exists {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return uuid.Nil, false
	}
	return clusterID, true
}

const nodeSummarySQL = nodeinventory.SummarySQL

func (h *Nodes) nodeSummaries(r *http.Request, orgID, clusterID uuid.UUID, nodeFilter string, hostCVEs bool, limit, offset int) ([]NodeSummary, error) {
	rows, err := h.db.Pool().Query(r.Context(), nodeSummarySQL+` ORDER BY node_last_seen_at DESC, n.node LIMIT $5 OFFSET $6`, orgID, clusterID, nodeFilter, hostCVEs, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]NodeSummary, 0)
	for rows.Next() {
		var item NodeSummary
		item.ClusterID = clusterID
		if err := rows.Scan(
			&item.Node,
			&item.OSID, &item.OSVersionID, &item.KernelRelease,
			&item.Arch, &item.CNIName, &item.CRIRuntime,
			&item.BTFPresent, &item.NFQueueCapable,
			&item.CPUCount, &item.MemoryBytes,
			&item.PackageCount, &item.PackageSource,
			&item.ContainerCount, &item.ProcessCount,
			&item.CISProfile, &item.CISPassed, &item.CISFailed,
			&item.CISWarned, &item.CISSkipped,
			&item.CriticalVulns, &item.HighVulns, &item.MediumVulns, &item.LowVulns, &item.OpenVulns,
			&item.RuntimeAgentVersion, &item.RuntimeAgentLastSeenAt,
			&item.ScanTargetID, &item.InventoryHash, &item.ScanStatus, &item.LastScannedAt,
			&item.HostFactsObservedAt, &item.PackagesObservedAt, &item.ContainersObservedAt, &item.ProcessesObservedAt, &item.CISObservedAt,
			&item.LastSeenAt,
		); err != nil {
			return nil, err
		}
		normalizeNodeSummary(&item)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeNodeSummary(item *NodeSummary) {
	if item.LastSeenAt.IsZero() || item.LastSeenAt.Equal(time.Unix(0, 0).UTC()) {
		item.LastSeenAt = time.Now().UTC()
	}
	if item.RuntimeAgentLastSeenAt != nil && time.Since(*item.RuntimeAgentLastSeenAt) <= 2*time.Minute {
		item.RuntimeAgentStatus = "healthy"
	} else if item.HostFactsObservedAt != nil || item.PackagesObservedAt != nil || item.ContainersObservedAt != nil ||
		item.ProcessesObservedAt != nil || item.CISObservedAt != nil {
		item.RuntimeAgentStatus = "stale"
	} else {
		item.RuntimeAgentStatus = "missing"
	}
	if item.ScanStatus == "" {
		if item.ScanTargetID != nil {
			item.ScanStatus = "targeted"
		} else {
			item.ScanStatus = "missing"
		}
	}
	if item.HostFactsObservedAt == nil {
		item.CoverageGaps = append(item.CoverageGaps, "host_facts")
	}
	if item.PackagesObservedAt == nil {
		item.CoverageGaps = append(item.CoverageGaps, "host_packages")
	}
	if item.ScanStatus != "completed" {
		item.CoverageGaps = append(item.CoverageGaps, "host_vulnerability_scan")
	}
	if item.CISObservedAt == nil {
		item.CoverageGaps = append(item.CoverageGaps, "host_cis")
	}
}

func (h *Nodes) nodePayload(r *http.Request, orgID, clusterID uuid.UUID, node, table, column string) (json.RawMessage, error) {
	switch table {
	case "host_facts", "host_packages", "host_containers", "host_processes", "host_cis":
	default:
		return nil, errors.New("unsupported node payload table")
	}
	switch column {
	case "facts", "payload":
	default:
		return nil, errors.New("unsupported node payload column")
	}
	var raw []byte
	query := "SELECT " + column + " FROM " + table + " WHERE org_id = $1 AND cluster_id = $2 AND node = $3 ORDER BY observed_at DESC LIMIT 1"
	err := h.db.Pool().QueryRow(r.Context(), query, orgID, clusterID, node).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

func (h *Nodes) nodeVulnerabilities(r *http.Request, orgID, clusterID uuid.UUID, node string) ([]NodeVulnerabilityRow, inventorylist.Metadata, error) {
	return inventorylist.Read(r.Context(), h.db.Pool(), nodeVulnerabilityDefinition(orgID, clusterID, node), inventorylist.Options{Limit: 2000, OrderSQL: "risk_score DESC NULLS LAST, observed_at DESC, id ASC"}, scanNodeVulnerability)
}
