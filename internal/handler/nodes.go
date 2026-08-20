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
	Node            NodeSummary     `json:"node"`
	Facts           json.RawMessage `json:"facts,omitempty"`
	Packages        json.RawMessage `json:"packages,omitempty"`
	Containers      json.RawMessage `json:"containers,omitempty"`
	Processes       json.RawMessage `json:"processes,omitempty"`
	CIS             json.RawMessage `json:"cis,omitempty"`
	Vulnerabilities []HostVulnRow   `json:"vulnerabilities"`
}

func (h *Nodes) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterID, ok := h.clusterIDFromRoute(w, r, subj.OrgID)
	if !ok {
		return
	}
	nodes, err := h.nodeSummaries(r, subj.OrgID, clusterID, "")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query nodes: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id": clusterID,
		"items":      nodes,
		"summary":    summarizeNodes(nodes),
	})
}

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

	nodes, err := h.nodeSummaries(r, subj.OrgID, clusterID, node)
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
	detail.Vulnerabilities, err = h.nodeVulnerabilities(r, subj.OrgID, clusterID, node)
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

func (h *Nodes) nodeSummaries(r *http.Request, orgID, clusterID uuid.UUID, nodeFilter string) ([]NodeSummary, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
WITH node_names AS (
    SELECT node FROM host_facts WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT node FROM host_packages WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT node FROM host_cis WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT node FROM host_containers WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT node FROM host_processes WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT ref AS node FROM scan_targets WHERE org_id = $1 AND cluster_id = $2 AND type = 'host'
    UNION SELECT target_ref AS node FROM findings WHERE org_id = $1 AND COALESCE(target_cluster_id, cluster_id) = $2 AND target_type = 'host'
)
SELECT n.node,
       COALESCE(hf.os_id, ''), COALESCE(hf.os_version_id, ''), COALESCE(hf.kernel_release, ''),
       COALESCE(hf.arch, ''), COALESCE(hf.cni_name, ''), COALESCE(hf.cri_runtime, ''),
       hf.btf_present, hf.nfqueue_capable,
       COALESCE(hf.cpu_count, 0), COALESCE(hf.memory_bytes, 0),
       COALESCE(hp.package_count, 0), COALESCE(hp.source, ''),
       COALESCE(hc.container_count, 0), COALESCE(hpr.process_count, 0),
       COALESCE(cis.profile, ''), COALESCE(cis.passed, 0), COALESCE(cis.failed, 0),
       COALESCE(cis.warned, 0), COALESCE(cis.skipped, 0),
       COALESCE(v.critical, 0), COALESCE(v.high, 0), COALESCE(v.medium, 0), COALESCE(v.low, 0), COALESCE(v.total, 0),
       COALESCE(hb.version, ''), hb.last_seen_at,
       st.id, COALESCE(st.inventory_hash, ''), COALESCE(sj.status, ''), sj.finished_at,
       hf.observed_at, hp.observed_at, hc.observed_at, hpr.observed_at, cis.observed_at,
       GREATEST(
           COALESCE(hf.observed_at, 'epoch'::timestamptz),
           COALESCE(hp.observed_at, 'epoch'::timestamptz),
           COALESCE(hc.observed_at, 'epoch'::timestamptz),
           COALESCE(hpr.observed_at, 'epoch'::timestamptz),
           COALESCE(cis.observed_at, 'epoch'::timestamptz),
           COALESCE(hb.last_seen_at, 'epoch'::timestamptz),
           COALESCE(sj.finished_at, 'epoch'::timestamptz)
       ) AS node_last_seen_at
  FROM node_names n
  LEFT JOIN LATERAL (
      SELECT os_id, os_version_id, kernel_release, arch, btf_present, nfqueue_capable,
             cni_name, cri_runtime, observed_at,
             (facts->'hardware'->>'cpu_count')::int      AS cpu_count,
             (facts->'hardware'->>'memory_bytes')::bigint AS memory_bytes
        FROM host_facts
       WHERE org_id = $1 AND cluster_id = $2 AND node = n.node
       ORDER BY observed_at DESC LIMIT 1
  ) hf ON true
  LEFT JOIN LATERAL (
      SELECT package_count, source, observed_at
        FROM host_packages
       WHERE org_id = $1 AND cluster_id = $2 AND node = n.node
       ORDER BY observed_at DESC LIMIT 1
  ) hp ON true
  LEFT JOIN LATERAL (
      SELECT container_count, observed_at
        FROM host_containers
       WHERE org_id = $1 AND cluster_id = $2 AND node = n.node
       ORDER BY observed_at DESC LIMIT 1
  ) hc ON true
  LEFT JOIN LATERAL (
      SELECT process_count, observed_at
        FROM host_processes
       WHERE org_id = $1 AND cluster_id = $2 AND node = n.node
       ORDER BY observed_at DESC LIMIT 1
  ) hpr ON true
  LEFT JOIN LATERAL (
      SELECT profile, passed, failed, warned, skipped, observed_at
        FROM host_cis
       WHERE org_id = $1 AND cluster_id = $2 AND node = n.node
       ORDER BY observed_at DESC LIMIT 1
  ) cis ON true
  LEFT JOIN LATERAL (
      SELECT COUNT(*)::int AS total,
             COUNT(*) FILTER (WHERE severity = 'critical')::int AS critical,
             COUNT(*) FILTER (WHERE severity = 'high')::int AS high,
             COUNT(*) FILTER (WHERE severity = 'medium')::int AS medium,
             COUNT(*) FILTER (WHERE severity = 'low')::int AS low
        FROM findings
       WHERE org_id = $1
         AND target_type = 'host'
         AND target_ref = n.node
         AND lifecycle = 'open'
         AND COALESCE(target_cluster_id, cluster_id) = $2
  ) v ON true
  LEFT JOIN LATERAL (
      SELECT version, last_seen_at
        FROM component_heartbeats
       WHERE org_id = $1
         AND cluster_id = $2
         AND component = 'runtime-agent'
         AND hostname = n.node
       ORDER BY last_seen_at DESC LIMIT 1
  ) hb ON true
  LEFT JOIN LATERAL (
      SELECT id, inventory_hash
        FROM scan_targets
       WHERE org_id = $1 AND cluster_id = $2 AND type = 'host' AND ref = n.node
       ORDER BY last_seen_at DESC LIMIT 1
  ) st ON true
  LEFT JOIN LATERAL (
      SELECT status, finished_at
        FROM scan_jobs
       WHERE org_id = $1 AND target_id = st.id
       ORDER BY requested_at DESC LIMIT 1
  ) sj ON true
 WHERE ($3 = '' OR n.node = $3)
 ORDER BY node_last_seen_at DESC, n.node
 LIMIT 500`, orgID, clusterID, nodeFilter)
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

func summarizeNodes(nodes []NodeSummary) map[string]any {
	summary := map[string]any{
		"nodes":                 len(nodes),
		"runtime_agent_healthy": 0,
		"runtime_agent_stale":   0,
		"runtime_agent_missing": 0,
		"scan_completed":        0,
		"scan_gaps":             0,
		"critical_vulns":        0,
		"high_vulns":            0,
		"cis_failed":            0,
	}
	for _, node := range nodes {
		switch node.RuntimeAgentStatus {
		case "healthy":
			summary["runtime_agent_healthy"] = summary["runtime_agent_healthy"].(int) + 1
		case "stale":
			summary["runtime_agent_stale"] = summary["runtime_agent_stale"].(int) + 1
		default:
			summary["runtime_agent_missing"] = summary["runtime_agent_missing"].(int) + 1
		}
		if node.ScanStatus == "completed" {
			summary["scan_completed"] = summary["scan_completed"].(int) + 1
		} else {
			summary["scan_gaps"] = summary["scan_gaps"].(int) + 1
		}
		summary["critical_vulns"] = summary["critical_vulns"].(int) + node.CriticalVulns
		summary["high_vulns"] = summary["high_vulns"].(int) + node.HighVulns
		summary["cis_failed"] = summary["cis_failed"].(int) + node.CISFailed
	}
	return summary
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

func (h *Nodes) nodeVulnerabilities(r *http.Request, orgID, clusterID uuid.UUID, node string) ([]HostVulnRow, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT COALESCE(NULLIF(f.target_ref, ''), a.name, ''),
       COALESCE(f.target_cluster_id, f.cluster_id),
       COALESCE(f.detail_json->'package'->>'name', ''),
       COALESCE(f.detail_json->'package'->>'version', ''),
       COALESCE(f.external_id, ''),
       COALESCE(f.detail_json->'aliases', '[]'::jsonb),
       COALESCE(f.severity, ''),
       COALESCE(NULLIF(f.description, ''), f.title, ''),
       COALESCE(f.detail_json->'references', '[]'::jsonb),
       COALESCE(f.detail_json->>'fixed', ''),
       COALESCE(NULLIF(f.source_type, ''), NULLIF(f.canonical_engine, ''), 'scanner'),
       f.last_seen_at
  FROM findings f
  LEFT JOIN assets a ON a.id = f.asset_id
 WHERE f.org_id = $1
   AND f.kind = 'vulnerability'
   AND f.lifecycle = 'open'
   AND f.target_type = 'host'
   AND f.target_ref = $2
   AND COALESCE(f.target_cluster_id, f.cluster_id) = $3
 ORDER BY f.risk_score DESC NULLS LAST, f.last_seen_at DESC
 LIMIT 2000`, orgID, node, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostVulnRow{}
	for rows.Next() {
		var item HostVulnRow
		var aliasesRaw, refsRaw []byte
		if err := rows.Scan(
			&item.Node, &item.ClusterID, &item.PackageName, &item.PackageVersion,
			&item.VulnID, &aliasesRaw, &item.Severity, &item.Summary, &refsRaw,
			&item.FixedVersion, &item.Source, &item.ObservedAt,
		); err != nil {
			return nil, err
		}
		item.Aliases = decodeStringList(aliasesRaw)
		item.References = strings.Join(decodeStringList(refsRaw), ",")
		out = append(out, item)
	}
	return out, rows.Err()
}
