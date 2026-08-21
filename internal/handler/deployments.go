// Deployments + violations endpoints (StackRox Risk + Violations parity).
//
//	GET /api/v1/deployments?cluster=&namespace=&limit=         risk-ranked list
//	GET /api/v1/deployments/{id}                               detail incl. findings + risk factors
//	GET /api/v1/deployments/{id}/violations                    per-deployment timeline
//	GET /api/v1/violations?limit=                              global timeline
package handler

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/complianceevidence"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type Deployments struct {
	db    *db.DB
	audit *audit.Logger
	// netPolicy resolves the network-policy lifecycle entry for one workload.
	// Injected by the server so the deployments handler need not import the
	// handler/netpolicy sub-package (which imports this package back). Nil when
	// not wired — the detail view then omits the network_policy field.
	netPolicy NetworkPolicyLifecycleLookup
}

// NetworkPolicyLifecycleLookup is the seam the netpolicy sub-package satisfies
// (netpolicy.NetworkPolicies.LifecycleForWorkload). It returns the lifecycle
// entry for a workload as an opaque any (the concrete DTO lives in the
// sub-package) or nil when none is found.
type NetworkPolicyLifecycleLookup func(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadID string) (any, error)

func NewDeployments(d *db.DB, a *audit.Logger) *Deployments { return &Deployments{db: d, audit: a} }

// WithNetworkPolicyLookup wires the network-policy lifecycle read-path seam.
// Returns the receiver for chaining at construction time.
func (h *Deployments) WithNetworkPolicyLookup(fn NetworkPolicyLifecycleLookup) *Deployments {
	h.netPolicy = fn
	return h
}

type deploymentDetailDTO struct {
	ID              string                         `json:"id"`
	ClusterID       string                         `json:"cluster_id,omitempty"`
	Namespace       string                         `json:"namespace"`
	Name            string                         `json:"name"`
	Kind            string                         `json:"kind"`
	Labels          json.RawMessage                `json:"labels"`
	RiskScore       int                            `json:"risk_score"`
	RiskFactors     json.RawMessage                `json:"risk_factors"`
	FindingCount    int                            `json:"finding_count"`
	CriticalCount   int                            `json:"critical_count"`
	HighCount       int                            `json:"high_count"`
	ImageRefs       []string                       `json:"image_refs"`
	WorkloadIDs     []string                       `json:"workload_ids"`
	FirstSeenAt     time.Time                      `json:"first_seen_at"`
	LastSeenAt      time.Time                      `json:"last_seen_at"`
	Images          []deploymentImageDTO           `json:"images"`
	PackageEvidence []deploymentPackageEvidenceDTO `json:"package_evidence"`
	Findings        []deploymentFindingDTO         `json:"findings"`
	RuntimeEvents   []EventDTO                     `json:"runtime_events"`
	ThreatPivots    []deploymentThreatPivotDTO     `json:"threat_pivots"`
	FileRisks       []deploymentFileRiskDTO        `json:"file_risks"`
	NetworkFlows    []deploymentNetworkFlowDTO     `json:"network_flows"`
	NetworkPolicy   any                            `json:"network_policy,omitempty"`
	Quarantine      *quarantineDTO                 `json:"quarantine,omitempty"`
	ProcessBaseline *deploymentProcessBaselineDTO  `json:"process_baseline,omitempty"`
	FileProfile     *deploymentFileProfileDTO      `json:"file_profile,omitempty"`
	Compliance      []deploymentComplianceDTO      `json:"compliance_evidence"`
	Violations      []deploymentViolationDTO       `json:"violations"`
}

type deploymentImageDTO struct {
	ImageRef           string     `json:"image_ref"`
	ImageRefNormalized string     `json:"image_ref_normalized"`
	ImageRepository    string     `json:"image_repository,omitempty"`
	ImageTag           string     `json:"image_tag,omitempty"`
	ImageDigest        string     `json:"image_digest,omitempty"`
	ImageScanResultID  string     `json:"image_scan_result_id,omitempty"`
	ScannerProfile     string     `json:"scanner_profile,omitempty"`
	VulnDBBundle       string     `json:"vulndb_bundle_version,omitempty"`
	PackageCount       int        `json:"package_count"`
	FindingCount       int        `json:"finding_count"`
	CriticalCount      int        `json:"critical_count"`
	HighCount          int        `json:"high_count"`
	MaxRiskScore       int        `json:"max_risk_score"`
	LastScannedAt      *time.Time `json:"last_scanned_at,omitempty"`
	LastSeenAt         time.Time  `json:"last_seen_at"`
}

type deploymentPackageEvidenceDTO struct {
	ID             string          `json:"id"`
	ScanTargetID   string          `json:"scan_target_id"`
	TargetRef      string          `json:"target_ref"`
	WorkloadID     string          `json:"workload_id"`
	Node           string          `json:"node,omitempty"`
	Namespace      string          `json:"namespace,omitempty"`
	PodName        string          `json:"pod_name,omitempty"`
	PodUID         string          `json:"pod_uid,omitempty"`
	Runtime        string          `json:"runtime,omitempty"`
	Distro         string          `json:"distro,omitempty"`
	DistroVersion  string          `json:"distro_version,omitempty"`
	Source         string          `json:"source,omitempty"`
	InventoryHash  string          `json:"inventory_hash"`
	PackageCount   int             `json:"package_count"`
	ContainerCount int             `json:"container_count"`
	Payload        json.RawMessage `json:"payload"`
	ObservedAt     time.Time       `json:"observed_at"`
}

type deploymentFindingDTO struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	ExternalID     string    `json:"external_id,omitempty"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	RiskScore      int       `json:"risk_score"`
	Lifecycle      string    `json:"lifecycle"`
	TargetType     string    `json:"target_type,omitempty"`
	TargetRef      string    `json:"target_ref,omitempty"`
	PackageName    string    `json:"package_name,omitempty"`
	PackageVersion string    `json:"package_version,omitempty"`
	FixedVersion   string    `json:"fixed_version,omitempty"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

type deploymentThreatPivotDTO struct {
	ID               string                      `json:"id"`
	Kind             string                      `json:"kind"`
	At               time.Time                   `json:"at"`
	Severity         string                      `json:"severity"`
	Verdict          string                      `json:"verdict"`
	Title            string                      `json:"title"`
	Message          string                      `json:"message,omitempty"`
	WorkloadID       string                      `json:"workload_id"`
	NodeID           string                      `json:"node_id,omitempty"`
	Namespace        string                      `json:"namespace,omitempty"`
	ContainerID      string                      `json:"container_id,omitempty"`
	AttackTechniques []string                    `json:"attack_techniques"`
	SourceEventID    string                      `json:"source_event_id,omitempty"`
	RuntimeThreatID  string                      `json:"runtime_threat_id,omitempty"`
	Rule             *deploymentThreatRuleRefDTO `json:"rule,omitempty"`
	File             *deploymentFileThreatDTO    `json:"file,omitempty"`
	Network          *deploymentThreatNetworkDTO `json:"network,omitempty"`
	HasPacket        bool                        `json:"has_packet"`
}

type deploymentThreatRuleRefDTO struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Category string `json:"category"`
	Mode     string `json:"mode,omitempty"`
	Group    string `json:"group,omitempty"`
	DPRuleID int64  `json:"dp_rule_id,omitempty"`
}

type deploymentFileThreatDTO struct {
	Path      string `json:"path,omitempty"`
	Flags     uint32 `json:"flags,omitempty"`
	Mode      uint32 `json:"mode,omitempty"`
	PID       uint32 `json:"pid,omitempty"`
	Comm      string `json:"comm,omitempty"`
	Operation string `json:"operation,omitempty"`
}

type deploymentThreatNetworkDTO struct {
	SrcIP     string `json:"src_ip,omitempty"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Direction string `json:"direction,omitempty"`
}

type deploymentFileRiskDTO struct {
	ImageScanResultID  string                         `json:"image_scan_result_id"`
	ImageRef           string                         `json:"image_ref,omitempty"`
	ImageRefNormalized string                         `json:"image_ref_normalized,omitempty"`
	ImageDigest        string                         `json:"image_digest,omitempty"`
	ArtifactID         string                         `json:"artifact_id"`
	Format             string                         `json:"format"`
	SHA256             string                         `json:"sha256"`
	Status             string                         `json:"status,omitempty"`
	Reason             string                         `json:"reason,omitempty"`
	Error              string                         `json:"error,omitempty"`
	FileRiskCount      int                            `json:"file_risk_count"`
	Truncated          bool                           `json:"truncated"`
	CreatedAt          time.Time                      `json:"created_at"`
	Findings           []deploymentFileRiskFindingDTO `json:"findings"`
}

type deploymentFileRiskFindingDTO struct {
	Path        string   `json:"path"`
	Type        string   `json:"type,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	UID         int      `json:"uid,omitempty"`
	GID         int      `json:"gid,omitempty"`
	SizeBytes   int64    `json:"size_bytes,omitempty"`
	LayerIndex  int      `json:"layer_index,omitempty"`
	LayerDigest string   `json:"layer_digest,omitempty"`
	LinkName    string   `json:"link_name,omitempty"`
	RiskTypes   []string `json:"risk_types,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

type deploymentNetworkFlowDTO struct {
	ID         string    `json:"id"`
	Src        string    `json:"src"`
	Dst        string    `json:"dst"`
	SrcAddr    string    `json:"src_addr,omitempty"`
	DstAddr    string    `json:"dst_addr,omitempty"`
	SrcPort    int       `json:"src_port,omitempty"`
	DstPort    int       `json:"dst_port,omitempty"`
	Protocol   string    `json:"protocol"`
	L7Protocol string    `json:"l7_protocol,omitempty"`
	Verdict    string    `json:"verdict"`
	Source     string    `json:"source,omitempty"`
	Bytes      int64     `json:"bytes"`
	Packets    int64     `json:"packets"`
	Sessions   int64     `json:"sessions,omitempty"`
	ThreatID   int       `json:"threat_id,omitempty"`
	Severity   int       `json:"severity,omitempty"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

type deploymentProcessBaselineDTO struct {
	WorkloadID            string                         `json:"workload_id"`
	ControlWorkloadID     string                         `json:"control_workload_id"`
	ClusterID             string                         `json:"cluster_id,omitempty"`
	Mode                  string                         `json:"mode"`
	LearnedProcessesCount int                            `json:"learned_processes_count"`
	MonitoredAlerts24h    int                            `json:"monitored_alerts_24h"`
	EnforcedBlocks24h     int                            `json:"enforced_blocks_24h"`
	LastNewProcessAt      *time.Time                     `json:"last_new_process_at,omitempty"`
	LearnStartedAt        *time.Time                     `json:"learn_started_at,omitempty"`
	MonitorStartedAt      *time.Time                     `json:"monitor_started_at,omitempty"`
	EnforceStartedAt      *time.Time                     `json:"enforce_started_at,omitempty"`
	Transitions           []deploymentBaselineTransition `json:"transitions,omitempty"`
	Processes             []deploymentProcessBaselineRow `json:"processes"`
}

type deploymentBaselineTransition struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	Reason string    `json:"reason"`
}

type deploymentProcessBaselineRow struct {
	Name          string    `json:"name"`
	Args          []string  `json:"args"`
	Path          string    `json:"path"`
	ObservedCount int       `json:"observed_count"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

type deploymentFileProfileDTO struct {
	WorkloadID         string                         `json:"workload_id"`
	ControlWorkloadID  string                         `json:"control_workload_id"`
	ClusterID          string                         `json:"cluster_id,omitempty"`
	Mode               string                         `json:"mode"`
	LearnedPathsCount  int                            `json:"learned_paths_count"`
	SensitivePathCount int                            `json:"sensitive_path_count"`
	RuleCount          int                            `json:"rule_count"`
	WatchedFileCount   int                            `json:"watched_file_count"`
	MonitoredAlerts24h int                            `json:"monitored_alerts_24h"`
	EnforcedBlocks24h  int                            `json:"enforced_blocks_24h"`
	LastNewPathAt      *time.Time                     `json:"last_new_path_at,omitempty"`
	LearnStartedAt     *time.Time                     `json:"learn_started_at,omitempty"`
	MonitorStartedAt   *time.Time                     `json:"monitor_started_at,omitempty"`
	EnforceStartedAt   *time.Time                     `json:"enforce_started_at,omitempty"`
	Transitions        []deploymentBaselineTransition `json:"transitions,omitempty"`
	Files              []deploymentFileProfileRow     `json:"files"`
	Rules              []fileProfileRuleDTO           `json:"rules"`
	Exceptions         []fileProfileExceptionDTO      `json:"exceptions"`
	WatchedFiles       []fileProfileWatchDTO          `json:"watched_files"`
}

type deploymentFileProfileRow struct {
	Path          string    `json:"path"`
	Operation     string    `json:"operation"`
	Comm          string    `json:"comm,omitempty"`
	Flags         uint32    `json:"flags"`
	Mode          uint32    `json:"mode"`
	ObservedCount int       `json:"observed_count"`
	Sensitive     bool      `json:"sensitive"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

type deploymentComplianceDTO struct {
	ID              string    `json:"id"`
	Source          string    `json:"source"`
	Framework       string    `json:"framework"`
	ControlID       string    `json:"control_id"`
	InternalID      string    `json:"internal_id,omitempty"`
	Title           string    `json:"title"`
	Severity        string    `json:"severity"`
	Status          string    `json:"status"`
	EffectiveStatus string    `json:"effective_status"`
	TargetKind      string    `json:"target_kind"`
	Target          string    `json:"target"`
	Evidence        string    `json:"evidence,omitempty"`
	Remediation     string    `json:"remediation,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
	Exemption       *string   `json:"exemption,omitempty"`
}

type deploymentViolationDTO struct {
	ID         string    `json:"id"`
	PolicyName string    `json:"policy_name"`
	Severity   string    `json:"severity"`
	Kind       string    `json:"kind"`
	Message    string    `json:"message"`
	At         time.Time `json:"at"`
}

// List returns deployments ranked by risk_score desc.
func (h *Deployments) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	namespace := r.URL.Query().Get("namespace")
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// RBAC-NS-24 row filtering: a namespace-restricted subject (set by requireVerbNS on
	// the route) sees only its granted namespaces. nil ⇒ no restriction. NULL::text[]
	// disables the ANY() clause, so an unrestricted caller is unaffected.
	var nsFilter []string
	if allowed, ok := NamespaceFilterFrom(r.Context()); ok {
		nsFilter = allowed
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, namespace, name, kind, COALESCE(labels,'{}'::jsonb), risk_score, COALESCE(risk_factors,'{}'::jsonb),
       finding_count, critical_count, high_count, first_seen_at, last_seen_at
  FROM deployments
 WHERE org_id = $1
   AND ($2::text = '' OR namespace = $2)
   AND ($3::uuid IS NULL OR cluster_id = $3)
   AND ($5::text[] IS NULL OR namespace = ANY($5))
 ORDER BY risk_score DESC, last_seen_at DESC
 LIMIT $4`, subj.OrgID, namespace, clusterArg, limit, nsFilter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var (
			id                  uuid.UUID
			ns, name, kind      string
			labels              []byte
			risk                int
			factors             []byte
			fc, cc, hc          int
			firstSeen, lastSeen time.Time
		)
		if err := rows.Scan(&id, &ns, &name, &kind, &labels, &risk, &factors, &fc, &cc, &hc, &firstSeen, &lastSeen); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan: " + err.Error()})
			return
		}
		out = append(out, map[string]any{
			"id": id, "namespace": ns, "name": name, "kind": kind,
			"labels":         json.RawMessage(labels),
			"risk_score":     risk,
			"risk_factors":   json.RawMessage(factors),
			"finding_count":  fc,
			"critical_count": cc,
			"high_count":     hc,
			"first_seen_at":  firstSeen.UTC().Format(time.RFC3339),
			"last_seen_at":   lastSeen.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, 200, map[string]any{"deployments": out, "limit": limit})
}

// Get returns one deployment with the workload evidence needed for the
// NeuVector-style workload drilldown: image exposure, package evidence, runtime
// events, network flows, policy lifecycle, direct findings, and violations.
func (h *Deployments) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, _ := SubjectFrom(r.Context())

	var detail deploymentDetailDTO
	var labels, factors []byte
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT id::text, COALESCE(cluster_id::text, ''), namespace, name, kind,
       COALESCE(labels,'{}'::jsonb), risk_score, COALESCE(risk_factors,'{}'::jsonb),
       finding_count, critical_count, high_count, COALESCE(image_refs, '{}'::text[]),
       first_seen_at, last_seen_at
  FROM deployments WHERE id = $1 AND org_id = $2`, id, subj.OrgID).
		Scan(&detail.ID, &detail.ClusterID, &detail.Namespace, &detail.Name, &detail.Kind,
			&labels, &detail.RiskScore, &factors, &detail.FindingCount, &detail.CriticalCount, &detail.HighCount,
			&detail.ImageRefs, &detail.FirstSeenAt, &detail.LastSeenAt)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	detail.Labels = json.RawMessage(labels)
	detail.RiskFactors = json.RawMessage(factors)

	clusterID := parseOptionalUUID(detail.ClusterID)
	baseWorkloadID := deploymentWorkloadID(detail.Namespace, detail.Name)
	detail.WorkloadIDs = h.deploymentOwnedWorkloadIDs(r, subj.OrgID, id, clusterID, detail.Namespace, detail.Name)

	if detail.Images, err = h.deploymentImages(r, subj.OrgID, id); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment images: "+err.Error())
		return
	}
	if detail.PackageEvidence, err = h.deploymentPackageEvidence(r, subj.OrgID, clusterID, detail.WorkloadIDs); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment package evidence: "+err.Error())
		return
	}
	if detail.Findings, err = h.deploymentFindings(r, subj.OrgID, clusterID, detail.WorkloadIDs); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment findings: "+err.Error())
		return
	}
	if detail.RuntimeEvents, err = h.deploymentRuntimeEvents(r, subj.OrgID, clusterID, detail.WorkloadIDs); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment runtime events: "+err.Error())
		return
	}
	if detail.ThreatPivots, err = h.deploymentThreatPivots(r, subj.OrgID, clusterID, detail.WorkloadIDs); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment threat pivots: "+err.Error())
		return
	}
	if detail.FileRisks, err = h.deploymentFileRisks(r, subj.OrgID, id); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment file risks: "+err.Error())
		return
	}
	if detail.NetworkFlows, err = h.deploymentNetworkFlows(r, subj.OrgID, clusterID, detail.WorkloadIDs); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment network flows: "+err.Error())
		return
	}
	if detail.NetworkPolicy, err = h.deploymentNetworkPolicyLifecycle(r, subj.OrgID, clusterID, baseWorkloadID); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment network policy: "+err.Error())
		return
	}
	if detail.Quarantine, err = h.deploymentActiveQuarantine(r, subj.OrgID, clusterID, baseWorkloadID); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment quarantine: "+err.Error())
		return
	}
	if detail.ProcessBaseline, err = h.deploymentProcessBaseline(r, subj.OrgID, clusterID, detail.WorkloadIDs, detail.Namespace, detail.Name); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment process baseline: "+err.Error())
		return
	}
	if detail.FileProfile, err = h.deploymentFileProfile(r, subj.OrgID, clusterID, detail.WorkloadIDs, detail.Namespace, detail.Name); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment file profile: "+err.Error())
		return
	}
	if detail.Compliance, err = h.deploymentCompliance(r, subj.OrgID, clusterID, detail.WorkloadIDs, detail.Namespace, detail.Name); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment compliance: "+err.Error())
		return
	}
	if detail.Violations, err = h.deploymentViolations(r, subj.OrgID, id); err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment violations: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, detail)
}

func (h *Deployments) deploymentOwnedWorkloadIDs(r *http.Request, orgID, deploymentID uuid.UUID, clusterID *uuid.UUID, namespace, name string) []string {
	baseWorkloadID := deploymentWorkloadID(namespace, name)
	out := []string{baseWorkloadID}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT DISTINCT workload_id
  FROM image_workload_links
 WHERE org_id = $1 AND deployment_id = $2
 ORDER BY workload_id`, orgID, deploymentID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var workloadID string
			if err := rows.Scan(&workloadID); err == nil && strings.TrimSpace(workloadID) != "" {
				out = append(out, strings.TrimSpace(workloadID))
			}
		}
	}

	if clusterID != nil {
		podRows, err := h.db.Pool().Query(r.Context(), `
SELECT DISTINCT pod_workload_id
  FROM pod_workload_links
 WHERE org_id = $1
   AND cluster_id = $2
   AND deployment_id = $3
   AND pod_workload_id <> ''
 ORDER BY pod_workload_id`, orgID, clusterID, deploymentID)
		if err == nil {
			defer podRows.Close()
			for podRows.Next() {
				var workloadID string
				if err := podRows.Scan(&workloadID); err == nil && strings.TrimSpace(workloadID) != "" {
					out = append(out, strings.TrimSpace(workloadID))
				}
			}
		}
	}

	return uniqueStrings(out)
}

func (h *Deployments) deploymentImages(r *http.Request, orgID, deploymentID uuid.UUID) ([]deploymentImageDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT l.image_ref,
       l.image_ref_normalized,
       COALESCE(l.image_repository, ''),
       COALESCE(l.image_tag, ''),
       COALESCE(l.image_digest, ''),
       COALESCE(sr.id::text, ''),
       COALESCE(sr.scanner_profile, ''),
       COALESCE(sr.vulndb_bundle_version, ''),
       COALESCE(sr.package_count, 0),
       COALESCE(sr.finding_count, 0),
       COALESCE(sr.critical_count, 0),
       COALESCE(sr.high_count, 0),
       COALESCE(sr.max_risk_score, 0),
       sr.last_scanned_at,
       l.last_seen_at
  FROM image_workload_links l
  LEFT JOIN LATERAL (
      -- ponytail: severity rollups are computed from image_scan_findings (the
      -- source of truth) rather than denormalized columns on image_scan_results,
      -- which never existed. Three correlated counts are fine for a per-deployment
      -- detail query; fold into one GROUP BY only if this shows up in profiling.
      SELECT r.*,
             (SELECT count(*) FROM image_scan_findings f
               WHERE f.image_scan_result_id = r.id AND lower(f.severity) = 'critical') AS critical_count,
             (SELECT count(*) FROM image_scan_findings f
               WHERE f.image_scan_result_id = r.id AND lower(f.severity) = 'high') AS high_count,
             (SELECT COALESCE(max(f.risk_score), 0) FROM image_scan_findings f
               WHERE f.image_scan_result_id = r.id) AS max_risk_score
        FROM image_scan_results r
       WHERE r.org_id = l.org_id
         AND (
              (l.image_digest IS NOT NULL AND l.image_digest <> '' AND r.image_digest = l.image_digest)
           OR (l.image_ref <> '' AND r.image_ref = l.image_ref)
           OR (l.image_ref_normalized <> '' AND r.image_ref_normalized = l.image_ref_normalized)
           OR (l.image_repository IS NOT NULL AND l.image_repository <> ''
               AND r.image_repository = l.image_repository
               AND l.image_tag IS NOT NULL AND l.image_tag <> ''
               AND r.image_tag = l.image_tag)
         )
       ORDER BY r.last_scanned_at DESC
       LIMIT 1
  ) sr ON true
 WHERE l.org_id = $1 AND l.deployment_id = $2
 ORDER BY l.image_ref`, orgID, deploymentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []deploymentImageDTO{}
	for rows.Next() {
		var item deploymentImageDTO
		if err := rows.Scan(&item.ImageRef, &item.ImageRefNormalized, &item.ImageRepository, &item.ImageTag,
			&item.ImageDigest, &item.ImageScanResultID, &item.ScannerProfile, &item.VulnDBBundle,
			&item.PackageCount, &item.FindingCount, &item.CriticalCount, &item.HighCount, &item.MaxRiskScore,
			&item.LastScannedAt, &item.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentPackageEvidence(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string) ([]deploymentPackageEvidenceDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT se.id::text,
       se.scan_target_id::text,
       se.target_ref,
       COALESCE(se.payload->>'workload_id', se.target_ref),
       COALESCE(se.payload->>'node', ''),
       COALESCE(se.payload->>'namespace', ''),
       COALESCE(se.payload->>'pod_name', ''),
       COALESCE(se.payload->>'pod_uid', ''),
       COALESCE(se.payload->>'runtime', ''),
       COALESCE(se.payload->>'distro', ''),
       COALESCE(se.payload->>'distro_version', ''),
       COALESCE(se.payload->>'source', ''),
       se.inventory_hash,
       se.package_count,
       COALESCE(jsonb_array_length(se.payload->'containers'), 0),
       se.payload,
       se.observed_at
  FROM scan_evidence se
 WHERE se.org_id = $1
   AND se.target_type = 'workload'
   AND se.evidence_type = 'package-inventory'
   AND ($2::uuid IS NULL OR se.cluster_id = $2)
   AND (
        se.target_ref = ANY($3::text[])
     OR COALESCE(se.payload->>'workload_id', '') = ANY($3::text[])
   )
 ORDER BY se.observed_at DESC
 LIMIT 20`, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []deploymentPackageEvidenceDTO{}
	for rows.Next() {
		var item deploymentPackageEvidenceDTO
		var payload []byte
		if err := rows.Scan(&item.ID, &item.ScanTargetID, &item.TargetRef, &item.WorkloadID, &item.Node,
			&item.Namespace, &item.PodName, &item.PodUID, &item.Runtime, &item.Distro, &item.DistroVersion,
			&item.Source, &item.InventoryHash, &item.PackageCount, &item.ContainerCount, &payload, &item.ObservedAt); err != nil {
			return nil, err
		}
		item.Payload = json.RawMessage(payload)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentFindings(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string) ([]deploymentFindingDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT f.id::text,
       f.kind,
       COALESCE(f.external_id, ''),
       f.title,
       f.severity,
       f.risk_score,
       f.lifecycle,
       COALESCE(f.target_type, ''),
       COALESCE(f.target_ref, ''),
       COALESCE(f.detail_json->'package'->>'name', ''),
       COALESCE(f.detail_json->'package'->>'version', ''),
       COALESCE(f.detail_json->>'fixed', ''),
       f.last_seen_at
  FROM findings f
 WHERE f.org_id = $1
   AND f.lifecycle = 'open'
   AND ($2::uuid IS NULL OR COALESCE(f.target_cluster_id, f.cluster_id) = $2)
   AND f.target_type = 'workload'
   AND f.target_ref = ANY($3::text[])
 ORDER BY f.risk_score DESC, f.last_seen_at DESC
 LIMIT 100`, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []deploymentFindingDTO{}
	for rows.Next() {
		var item deploymentFindingDTO
		if err := rows.Scan(&item.ID, &item.Kind, &item.ExternalID, &item.Title, &item.Severity,
			&item.RiskScore, &item.Lifecycle, &item.TargetType, &item.TargetRef, &item.PackageName,
			&item.PackageVersion, &item.FixedVersion, &item.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentRuntimeEvents(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string) ([]EventDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, at, kind, source, severity, verdict, node_id, workload_id,
       COALESCE(namespace,''), COALESCE(container_id,''), attack_techniques, payload
  FROM events
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND workload_id = ANY($3::text[])
 ORDER BY at DESC
 LIMIT 50`, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventDTO{}
	for rows.Next() {
		var item EventDTO
		var payload []byte
		if err := rows.Scan(&item.ID, &item.At, &item.Kind, &item.Source, &item.Severity, &item.Verdict,
			&item.NodeID, &item.WorkloadID, &item.Namespace, &item.ContainerID, &item.AttackTechniques, &payload); err != nil {
			return nil, err
		}
		item.Payload = payload
		if item.AttackTechniques == nil {
			item.AttackTechniques = []string{}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentThreatPivots(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string) ([]deploymentThreatPivotDTO, error) {
	filePivots, err := h.deploymentFileThreatPivots(r, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	runtimePivots, err := h.deploymentRuntimeThreatPivots(r, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	out := append(filePivots, runtimePivots...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].At.After(out[j].At)
	})
	if len(out) > 60 {
		out = out[:60]
	}
	return out, nil
}

func (h *Deployments) deploymentFileThreatPivots(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string) ([]deploymentThreatPivotDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, at, severity, verdict, node_id, workload_id,
       COALESCE(namespace,''), COALESCE(container_id,''), attack_techniques, payload
  FROM events
 WHERE org_id = $1
   AND kind = 'file_open'
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND workload_id = ANY($3::text[])
 ORDER BY at DESC
 LIMIT 30`, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []deploymentThreatPivotDTO{}
	for rows.Next() {
		var id, severity, verdict, nodeID, workloadID, rowNamespace, containerID string
		var at time.Time
		var techniques []string
		var payloadRaw []byte
		if err := rows.Scan(&id, &at, &severity, &verdict, &nodeID, &workloadID, &rowNamespace, &containerID, &techniques, &payloadRaw); err != nil {
			return nil, err
		}
		var payload struct {
			PID   uint32 `json:"pid"`
			Comm  string `json:"comm"`
			Path  string `json:"path"`
			Flags uint32 `json:"flags"`
			Mode  uint32 `json:"mode"`
		}
		_ = json.Unmarshal(payloadRaw, &payload)
		title := "File open"
		if len(techniques) > 0 || isSensitivePath(payload.Path) {
			title = "Sensitive file access"
		}
		out = append(out, deploymentThreatPivotDTO{
			ID:               "event:" + id,
			Kind:             "file",
			At:               at,
			Severity:         severity,
			Verdict:          verdict,
			Title:            title,
			Message:          payload.Path,
			WorkloadID:       workloadID,
			NodeID:           nodeID,
			Namespace:        rowNamespace,
			ContainerID:      containerID,
			AttackTechniques: nonNilStrings(techniques),
			SourceEventID:    id,
			File: &deploymentFileThreatDTO{
				Path:      payload.Path,
				Flags:     payload.Flags,
				Mode:      payload.Mode,
				PID:       payload.PID,
				Comm:      payload.Comm,
				Operation: "open",
			},
		})
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentRuntimeThreatPivots(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string) ([]deploymentThreatPivotDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text,
       cluster_id::text,
       COALESCE(workload_id,''),
       COALESCE(namespace,''),
       COALESCE(pod_name,''),
       COALESCE(node,''),
       COALESCE(ep_mac,''),
       threat_id,
       severity,
       action,
       COALESCE(application,0),
       COALESCE(msg,''),
       COALESCE(dlp_name_hash,0),
       COALESCE(ip_proto,0::smallint),
       COALESCE(src_ip,''),
       COALESCE(src_port,0),
       COALESCE(dst_ip,''),
       COALESCE(dst_port,0),
       COALESCE(pkt_len,0),
       COALESCE(cap_len,0),
       pkt_ingress,
       sess_ingress,
       reported_at,
       at
  FROM runtime_threats
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND workload_id = ANY($3::text[])
 ORDER BY at DESC
 LIMIT 50`, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []deploymentThreatPivotDTO{}
	for rows.Next() {
		var id, rowClusterID, workloadID, rowNamespace, podName, node, epmac, msg string
		var threatID, application int32
		var severity, action, ipProto int16
		var dlpNameHash int64
		var srcIP, dstIP string
		var srcPort, dstPort, pktLen, capLen int
		var pktIngress, sessIngress bool
		var reportedAt, at time.Time
		if err := rows.Scan(&id, &rowClusterID, &workloadID, &rowNamespace, &podName, &node, &epmac,
			&threatID, &severity, &action, &application, &msg, &dlpNameHash, &ipProto,
			&srcIP, &srcPort, &dstIP, &dstPort, &pktLen, &capLen, &pktIngress, &sessIngress, &reportedAt, &at); err != nil {
			return nil, err
		}
		kind := "waf"
		if dlpNameHash > 0 {
			kind = "dlp"
		}
		threatName := NeuVectorThreatName(uint32(threatID))
		title := threatName
		if kind == "dlp" {
			title = "DLP " + title
		} else {
			title = "WAF " + title
		}
		if strings.TrimSpace(msg) != "" {
			title = strings.TrimSpace(msg)
		}
		out = append(out, deploymentThreatPivotDTO{
			ID:              "threat:" + id,
			Kind:            kind,
			At:              at,
			Severity:        runtimeThreatSeverityLabel(severity),
			Verdict:         runtimeThreatVerdict(action),
			Title:           title,
			Message:         msg,
			WorkloadID:      workloadID,
			NodeID:          node,
			Namespace:       rowNamespace,
			RuntimeThreatID: id,
			Rule: &deploymentThreatRuleRefDTO{
				ID:       threatName,
				Name:     threatName,
				Category: kind,
				DPRuleID: dlpNameHash,
			},
			Network: &deploymentThreatNetworkDTO{
				SrcIP:     srcIP,
				SrcPort:   srcPort,
				DstIP:     dstIP,
				DstPort:   dstPort,
				Protocol:  ipProtoLabel(ipProto),
				Direction: runtimeThreatDirection(sessIngress),
			},
			HasPacket: pktLen > 0 || capLen > 0,
		})
		_ = rowClusterID
		_ = podName
		_ = epmac
		_ = reportedAt
		_ = pktIngress
		_ = application
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentFileRisks(r *http.Request, orgID, deploymentID uuid.UUID) ([]deploymentFileRiskDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT DISTINCT ON (sr.id, a.id)
       sr.id::text,
       COALESCE(l.image_ref, ''),
       COALESCE(l.image_ref_normalized, ''),
       COALESCE(sr.image_digest, ''),
       a.id::text,
       a.format,
       a.sha256,
       a.package_count,
       a.payload,
       a.created_at
  FROM image_workload_links l
  JOIN LATERAL (
      SELECT r.*
        FROM image_scan_results r
       WHERE r.org_id = l.org_id
         AND (
              (l.image_digest IS NOT NULL AND l.image_digest <> '' AND r.image_digest = l.image_digest)
           OR (l.image_ref <> '' AND r.image_ref = l.image_ref)
           OR (l.image_ref_normalized <> '' AND r.image_ref_normalized = l.image_ref_normalized)
           OR (l.image_repository IS NOT NULL AND l.image_repository <> ''
               AND r.image_repository = l.image_repository
               AND l.image_tag IS NOT NULL AND l.image_tag <> ''
               AND r.image_tag = l.image_tag)
         )
       ORDER BY r.last_scanned_at DESC
       LIMIT 1
  ) sr ON true
  JOIN image_scan_artifacts a
    ON a.org_id = sr.org_id
   AND a.image_scan_result_id = sr.id
   AND a.artifact_type = 'file-risk'
   AND a.format = 'constellation-image-file-risk-v1'
 WHERE l.org_id = $1
   AND l.deployment_id = $2
 ORDER BY sr.id, a.id, l.last_seen_at DESC
 LIMIT 20`, orgID, deploymentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []deploymentFileRiskDTO{}
	for rows.Next() {
		var item deploymentFileRiskDTO
		var payloadRaw []byte
		if err := rows.Scan(&item.ImageScanResultID, &item.ImageRef, &item.ImageRefNormalized, &item.ImageDigest,
			&item.ArtifactID, &item.Format, &item.SHA256, &item.FileRiskCount, &payloadRaw, &item.CreatedAt); err != nil {
			return nil, err
		}
		var payload struct {
			Status        string                         `json:"status"`
			Reason        string                         `json:"reason"`
			Error         string                         `json:"error"`
			FileRiskCount int                            `json:"file_risk_count"`
			FindingCount  int                            `json:"finding_count"`
			Truncated     bool                           `json:"truncated"`
			Findings      []deploymentFileRiskFindingDTO `json:"findings"`
		}
		_ = json.Unmarshal(payloadRaw, &payload)
		item.Status = payload.Status
		item.Reason = payload.Reason
		item.Error = payload.Error
		item.Truncated = payload.Truncated
		if payload.FileRiskCount > 0 {
			item.FileRiskCount = payload.FileRiskCount
		} else if payload.FindingCount > 0 {
			item.FileRiskCount = payload.FindingCount
		}
		item.Findings = payload.Findings
		if len(item.Findings) > 20 {
			item.Findings = item.Findings[:20]
		}
		if item.Findings == nil {
			item.Findings = []deploymentFileRiskFindingDTO{}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentNetworkFlows(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string) ([]deploymentNetworkFlowDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text,
       src_workload,
       dst_workload,
       COALESCE(src_addr, ''),
       COALESCE(dst_addr, ''),
       COALESCE(src_port, 0),
       COALESCE(dst_port, 0),
       protocol,
       COALESCE(l7_protocol, ''),
       verdict,
       COALESCE(source, ''),
       bytes,
       packets,
       COALESCE(sessions, 0),
       COALESCE(threat_id, 0),
       COALESCE(severity, 0),
       at
  FROM network_flows
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND (
        src_workload = ANY($3::text[])
     OR dst_workload = ANY($3::text[])
   )
 ORDER BY at DESC
 LIMIT 50`, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []deploymentNetworkFlowDTO{}
	for rows.Next() {
		var item deploymentNetworkFlowDTO
		if err := rows.Scan(&item.ID, &item.Src, &item.Dst, &item.SrcAddr, &item.DstAddr,
			&item.SrcPort, &item.DstPort, &item.Protocol, &item.L7Protocol, &item.Verdict, &item.Source,
			&item.Bytes, &item.Packets, &item.Sessions, &item.ThreatID, &item.Severity, &item.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentNetworkPolicyLifecycle(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadID string) (any, error) {
	if h.netPolicy == nil {
		return nil, nil
	}
	return h.netPolicy(r, orgID, clusterID, workloadID)
}

func (h *Deployments) deploymentActiveQuarantine(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadID string) (*quarantineDTO, error) {
	workloadID = strings.TrimSpace(workloadID)
	if h.db == nil || clusterID == nil || workloadID == "" {
		return nil, nil
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, org_id, cluster_id, scope, match_key, reason, origin,
       COALESCE(source_kind, ''), source_id, created_by, created_at,
       expires_at, lifted_at, lifted_by, COALESCE(lifted_reason, '')
  FROM quarantine_entries
 WHERE org_id = $1
   AND cluster_id = $2
   AND scope = 'workload'
   AND match_key = $3
   AND lifted_at IS NULL
   AND (expires_at IS NULL OR expires_at > NOW())
 ORDER BY created_at DESC
 LIMIT 1`, orgID, *clusterID, workloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var d quarantineDTO
	if err := rows.Scan(&d.ID, &d.OrgID, &d.ClusterID, &d.Scope, &d.MatchKey,
		&d.Reason, &d.Origin, &d.SourceKind, &d.SourceID, &d.CreatedBy,
		&d.CreatedAt, &d.ExpiresAt, &d.LiftedAt, &d.LiftedBy, &d.LiftedReason); err != nil {
		return nil, err
	}
	return &d, rows.Err()
}

func (h *Deployments) deploymentProcessBaseline(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string, namespace, name string) (*deploymentProcessBaselineDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT workload_id,
       severity,
       verdict,
       payload,
       at
  FROM events
 WHERE org_id = $1
   AND kind = 'process_exec'
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND workload_id = ANY($3::text[])
 ORDER BY at DESC
 LIMIT 1000`, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type processPayload struct {
		Comm     string   `json:"comm"`
		Filename string   `json:"filename"`
		Args     []string `json:"args"`
	}
	processes := map[string]*deploymentProcessBaselineRow{}
	var workloadID string
	var alerts24h, blocks24h int
	var lastNewProcessAt *time.Time
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	for rows.Next() {
		var rowWorkloadID, severity, verdict string
		var payloadRaw []byte
		var at time.Time
		if err := rows.Scan(&rowWorkloadID, &severity, &verdict, &payloadRaw, &at); err != nil {
			return nil, err
		}
		if workloadID == "" {
			workloadID = rowWorkloadID
		}
		if at.After(cutoff) && (severity == "high" || severity == "critical" || verdict == "alert") {
			alerts24h++
		}
		if at.After(cutoff) && (verdict == "block" || verdict == "deny") {
			blocks24h++
		}
		var payload processPayload
		_ = json.Unmarshal(payloadRaw, &payload)
		processName := strings.TrimSpace(commBasename(payload.Comm, payload.Filename))
		if processName == "" {
			continue
		}
		key := processName + "\x00" + strings.TrimSpace(payload.Filename)
		item, ok := processes[key]
		if !ok {
			item = &deploymentProcessBaselineRow{
				Name:      processName,
				Args:      append([]string(nil), payload.Args...),
				Path:      strings.TrimSpace(payload.Filename),
				FirstSeen: at,
				LastSeen:  at,
			}
			processes[key] = item
			observed := at.UTC()
			if lastNewProcessAt == nil || observed.After(*lastNewProcessAt) {
				lastNewProcessAt = &observed
			}
		}
		item.ObservedCount++
		if at.Before(item.FirstSeen) {
			item.FirstSeen = at
		}
		if at.After(item.LastSeen) {
			item.LastSeen = at
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if workloadID == "" {
		workloadID = deploymentWorkloadID(namespace, name)
	}
	controlWorkloadID := deploymentWorkloadID(namespace, name)
	out := &deploymentProcessBaselineDTO{
		WorkloadID:         workloadID,
		ControlWorkloadID:  controlWorkloadID,
		Mode:               "learn",
		MonitoredAlerts24h: alerts24h,
		EnforcedBlocks24h:  blocks24h,
		LastNewProcessAt:   lastNewProcessAt,
		Processes:          make([]deploymentProcessBaselineRow, 0, len(processes)),
	}
	if clusterID != nil {
		out.ClusterID = clusterID.String()
		_ = h.db.Pool().QueryRow(r.Context(), `
SELECT mode,
       learn_started_at,
       monitor_started_at,
       enforce_started_at
  FROM process_baseline_states
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3`,
			orgID, *clusterID, controlWorkloadID).Scan(&out.Mode, &out.LearnStartedAt, &out.MonitorStartedAt, &out.EnforceStartedAt)
		transitionRows, err := h.db.Pool().Query(r.Context(), `
SELECT created_at,
       COALESCE(actor_id::text, ''),
       from_mode,
       to_mode,
       reason
  FROM process_baseline_transitions
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
 ORDER BY created_at ASC
 LIMIT 50`, orgID, *clusterID, controlWorkloadID)
		if err == nil {
			defer transitionRows.Close()
			for transitionRows.Next() {
				var transition deploymentBaselineTransition
				if err := transitionRows.Scan(&transition.At, &transition.Actor, &transition.From, &transition.To, &transition.Reason); err == nil {
					out.Transitions = append(out.Transitions, transition)
				}
			}
		}
	}
	for _, process := range processes {
		out.Processes = append(out.Processes, *process)
	}
	sort.SliceStable(out.Processes, func(i, j int) bool {
		if out.Processes[i].ObservedCount != out.Processes[j].ObservedCount {
			return out.Processes[i].ObservedCount > out.Processes[j].ObservedCount
		}
		return out.Processes[i].Name < out.Processes[j].Name
	})
	if len(out.Processes) > 20 {
		out.Processes = out.Processes[:20]
	}
	out.LearnedProcessesCount = len(processes)
	return out, nil
}

func (h *Deployments) deploymentFileProfile(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string, namespace, name string) (*deploymentFileProfileDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT workload_id,
       severity,
       verdict,
       payload,
       at
  FROM events
 WHERE org_id = $1
   AND kind = 'file_open'
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND workload_id = ANY($3::text[])
 ORDER BY at DESC
 LIMIT 1000`, orgID, clusterID, workloadIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type filePayload struct {
		PID   uint32 `json:"pid"`
		Comm  string `json:"comm"`
		Path  string `json:"path"`
		Flags uint32 `json:"flags"`
		Mode  uint32 `json:"mode"`
	}
	files := map[string]*deploymentFileProfileRow{}
	var workloadID string
	var alerts24h, blocks24h int
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	for rows.Next() {
		var rowWorkloadID, severity, verdict string
		var payloadRaw []byte
		var at time.Time
		if err := rows.Scan(&rowWorkloadID, &severity, &verdict, &payloadRaw, &at); err != nil {
			return nil, err
		}
		if workloadID == "" {
			workloadID = rowWorkloadID
		}
		if at.After(cutoff) && (severity == "high" || severity == "critical" || verdict == "alert") {
			alerts24h++
		}
		if at.After(cutoff) && (verdict == "block" || verdict == "deny") {
			blocks24h++
		}
		var payload filePayload
		_ = json.Unmarshal(payloadRaw, &payload)
		path := strings.TrimSpace(payload.Path)
		if path == "" {
			continue
		}
		comm := strings.TrimSpace(payload.Comm)
		key := path + "\x00" + comm
		item, ok := files[key]
		if !ok {
			item = &deploymentFileProfileRow{
				Path:      path,
				Operation: "open",
				Comm:      comm,
				Flags:     payload.Flags,
				Mode:      payload.Mode,
				Sensitive: isSensitivePath(path),
				FirstSeen: at,
				LastSeen:  at,
			}
			files[key] = item
		}
		item.ObservedCount++
		if at.Before(item.FirstSeen) {
			item.FirstSeen = at
		}
		if at.After(item.LastSeen) {
			item.LastSeen = at
			item.Flags = payload.Flags
			item.Mode = payload.Mode
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if workloadID == "" {
		workloadID = deploymentWorkloadID(namespace, name)
	}
	controlWorkloadID := deploymentWorkloadID(namespace, name)
	out := &deploymentFileProfileDTO{
		WorkloadID:         workloadID,
		ControlWorkloadID:  controlWorkloadID,
		Mode:               "learn",
		MonitoredAlerts24h: alerts24h,
		EnforcedBlocks24h:  blocks24h,
		Files:              make([]deploymentFileProfileRow, 0, len(files)),
		Rules:              []fileProfileRuleDTO{},
		Exceptions:         []fileProfileExceptionDTO{},
	}
	if clusterID != nil {
		out.ClusterID = clusterID.String()
		_ = h.db.Pool().QueryRow(r.Context(), `
SELECT mode,
       learn_started_at,
       monitor_started_at,
       enforce_started_at
  FROM file_profile_states
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3`,
			orgID, *clusterID, controlWorkloadID).Scan(&out.Mode, &out.LearnStartedAt, &out.MonitorStartedAt, &out.EnforceStartedAt)
		transitionRows, err := h.db.Pool().Query(r.Context(), `
SELECT created_at,
       COALESCE(actor_id::text, ''),
       from_mode,
       to_mode,
       reason
  FROM file_profile_transitions
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
 ORDER BY created_at ASC
 LIMIT 50`, orgID, *clusterID, controlWorkloadID)
		if err == nil {
			defer transitionRows.Close()
			for transitionRows.Next() {
				var transition deploymentBaselineTransition
				if err := transitionRows.Scan(&transition.At, &transition.Actor, &transition.From, &transition.To, &transition.Reason); err == nil {
					out.Transitions = append(out.Transitions, transition)
				}
			}
		}
		rules, err := h.deploymentFileProfileRules(r, orgID, *clusterID, controlWorkloadID)
		if err != nil {
			return nil, err
		}
		out.Rules = rules
		out.RuleCount = len(rules)
		exceptions, err := h.deploymentFileProfileExceptions(r, orgID, *clusterID, controlWorkloadID)
		if err != nil {
			return nil, err
		}
		out.Exceptions = fileProfileExceptionsDTO(exceptions)
		watches, err := h.deploymentFileProfileWatches(r, orgID, *clusterID, controlWorkloadID)
		if err != nil {
			return nil, err
		}
		out.WatchedFiles = fileProfileWatchesDTO(watches)
		out.WatchedFileCount = len(watches)
	}
	var lastNewPathAt *time.Time
	for _, file := range files {
		out.Files = append(out.Files, *file)
		if file.Sensitive {
			out.SensitivePathCount++
		}
		observed := file.FirstSeen.UTC()
		if lastNewPathAt == nil || observed.After(*lastNewPathAt) {
			lastNewPathAt = &observed
		}
	}
	sort.SliceStable(out.Files, func(i, j int) bool {
		if out.Files[i].ObservedCount != out.Files[j].ObservedCount {
			return out.Files[i].ObservedCount > out.Files[j].ObservedCount
		}
		if out.Files[i].Sensitive != out.Files[j].Sensitive {
			return out.Files[i].Sensitive
		}
		if out.Files[i].Path != out.Files[j].Path {
			return out.Files[i].Path < out.Files[j].Path
		}
		return out.Files[i].Comm < out.Files[j].Comm
	})
	out.LastNewPathAt = lastNewPathAt
	out.LearnedPathsCount = len(files)
	if len(out.Files) > 20 {
		out.Files = out.Files[:20]
	}
	return out, nil
}

func (h *Deployments) deploymentFileProfileRules(r *http.Request, orgID, clusterID uuid.UUID, workloadID string) ([]fileProfileRuleDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id,
       filter,
       path,
       regex,
       recursive,
       behavior,
       applications,
       enabled,
       description,
       COALESCE(created_by::text, ''),
       COALESCE(updated_by::text, ''),
       created_at,
       updated_at
  FROM file_profile_rules
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
 ORDER BY enabled DESC, updated_at DESC, filter ASC`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fileProfileRuleDTO{}
	for rows.Next() {
		var rule fileProfileRule
		if err := rows.Scan(&rule.ID, &rule.Filter, &rule.Path, &rule.Regex, &rule.Recursive, &rule.Behavior,
			&rule.Applications, &rule.Enabled, &rule.Description, &rule.CreatedBy, &rule.UpdatedBy,
			&rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, fileProfileRuleToDTO(rule))
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentFileProfileWatches(r *http.Request, orgID, clusterID uuid.UUID, workloadID string) ([]fileProfileWatch, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT node,
       rule_id,
       filter,
       path,
       regex,
       recursive,
       behavior,
       applications,
       profile_mode,
       desired_protect,
       protect,
       enforcement_state,
       files,
       files_count,
       sensitive_count,
       bundle_fingerprint,
       observed_at,
       updated_at
  FROM file_profile_watch_inventory
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
 ORDER BY observed_at DESC, node ASC, filter ASC
 LIMIT 200`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fileProfileWatch{}
	for rows.Next() {
		var watch fileProfileWatch
		if err := rows.Scan(&watch.Node, &watch.RuleID, &watch.Filter, &watch.Path, &watch.Regex,
			&watch.Recursive, &watch.Behavior, &watch.Applications, &watch.ProfileMode,
			&watch.DesiredProtect, &watch.Protect, &watch.EnforcementState,
			&watch.Files, &watch.FilesCount, &watch.SensitiveCount,
			&watch.BundleFingerprint, &watch.ObservedAt, &watch.UpdatedAt); err != nil {
			return nil, err
		}
		watch.Applications = nonNilStrings(watch.Applications)
		out = append(out, watch)
	}
	return out, rows.Err()
}

func (h *Deployments) deploymentCompliance(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, workloadIDs []string, namespace, name string) ([]deploymentComplianceDTO, error) {
	collector := complianceevidence.Collector{Pool: h.db.Pool()}
	result, err := collector.Collect(r.Context(), complianceevidence.Query{
		OrgID:     orgID,
		ClusterID: clusterID,
		Scope:     complianceevidence.ScopeWorkload,
		Namespace: namespace,
		Limit:     500,
	})
	if err != nil {
		return nil, err
	}
	workloadSet := map[string]bool{}
	for _, id := range workloadIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			workloadSet[id] = true
		}
	}
	baseWorkloadID := deploymentWorkloadID(namespace, name)
	if baseWorkloadID != "" {
		workloadSet[baseWorkloadID] = true
	}

	out := []deploymentComplianceDTO{}
	for _, item := range result.Items {
		if !complianceTargetsDeployment(item.Target, workloadSet, namespace, name) {
			continue
		}
		dto := deploymentComplianceDTO{
			ID:              item.ID,
			Source:          item.Source,
			Framework:       item.Framework,
			ControlID:       item.ControlID,
			InternalID:      item.InternalID,
			Title:           item.Title,
			Severity:        item.Severity,
			Status:          item.Status,
			EffectiveStatus: item.EffectiveStatus,
			TargetKind:      item.TargetKind,
			Target:          item.Target,
			Evidence:        item.Evidence,
			Remediation:     item.Remediation,
			ObservedAt:      item.ObservedAt,
		}
		if item.Exemption != nil {
			reason := item.Exemption.Reason
			dto.Exemption = &reason
		}
		out = append(out, dto)
	}
	return out, nil
}

func complianceTargetsDeployment(target string, workloadIDs map[string]bool, namespace, name string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	workloadToken := target
	if token, _, ok := strings.Cut(target, " "); ok {
		workloadToken = strings.TrimSpace(token)
	}
	for workloadID := range workloadIDs {
		if workloadToken == workloadID {
			return true
		}
	}
	base := deploymentWorkloadID(namespace, name)
	return base != "" && workloadToken == base
}

func (h *Deployments) deploymentViolations(r *http.Request, orgID, deploymentID uuid.UUID) ([]deploymentViolationDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, COALESCE(policy_name, ''), severity, kind, COALESCE(message, ''), at
  FROM violations
 WHERE deployment_id = $1 AND org_id = $2
 ORDER BY at DESC
 LIMIT 50`, deploymentID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []deploymentViolationDTO{}
	for rows.Next() {
		var item deploymentViolationDTO
		if err := rows.Scan(&item.ID, &item.PolicyName, &item.Severity, &item.Kind, &item.Message, &item.At); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func deploymentWorkloadID(namespace, name string) string {
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if namespace == "" {
		return name
	}
	if name == "" {
		return namespace
	}
	return namespace + "/" + name
}

func runtimeThreatSeverityLabel(severity int16) string {
	switch {
	case severity >= 9:
		return "critical"
	case severity >= 7:
		return "high"
	case severity >= 4:
		return "medium"
	case severity > 0:
		return "low"
	default:
		return "info"
	}
}

func runtimeThreatVerdict(action int16) string {
	switch action {
	case 6:
		return "alert"
	case 7:
		return "deny"
	default:
		return "observed"
	}
}

func runtimeThreatDirection(sessIngress bool) string {
	if sessIngress {
		return "ingress"
	}
	return "egress"
}

func ipProtoLabel(proto int16) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		if proto > 0 {
			return "ipproto-" + strconv.Itoa(int(proto))
		}
		return ""
	}
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func parseOptionalUUID(raw string) *uuid.UUID {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return nil
	}
	return &parsed
}

// Violations returns the global violation timeline.
func (h *Deployments) Violations(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT v.id, v.deployment_id, v.policy_name, v.severity, v.kind, v.message, v.at,
       COALESCE(d.namespace,''), COALESCE(d.name,''), COALESCE(d.kind,'')
  FROM violations v
  LEFT JOIN deployments d ON d.id = v.deployment_id
 WHERE v.org_id = $1
 ORDER BY v.at DESC LIMIT $2`, subj.OrgID, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var (
			id, depID                   uuid.UUID
			pol, sev, k, msg, ns, n, dk string
			at                          time.Time
		)
		if err := rows.Scan(&id, &depID, &pol, &sev, &k, &msg, &at, &ns, &n, &dk); err == nil {
			out = append(out, map[string]any{
				"id": id, "deployment_id": depID, "policy_name": pol, "severity": sev, "kind": k,
				"message": msg, "at": at.UTC().Format(time.RFC3339),
				"deployment": map[string]string{"namespace": ns, "name": n, "kind": dk},
			})
		}
	}
	writeJSON(w, 200, map[string]any{"violations": out})
}
