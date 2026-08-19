package scanning

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

type scanObjectTriggerDTO struct {
	Status          string     `json:"status"`
	TargetID        uuid.UUID  `json:"target_id"`
	TargetType      string     `json:"target_type"`
	TargetRef       string     `json:"target_ref"`
	ScanEvidenceID  uuid.UUID  `json:"scan_evidence_id"`
	InventoryHash   string     `json:"inventory_hash,omitempty"`
	ScanJobEnqueued bool       `json:"scan_job_enqueued"`
	JobID           *uuid.UUID `json:"job_id,omitempty"`
}

type scanObjectReportDTO struct {
	ScanSummary scanObjectBriefDTO   `json:"scan_summary"`
	Report      scanObjectReportBody `json:"report"`
}

type scanObjectPlatformSummaryDTO struct {
	Platforms []scanObjectPlatformDTO `json:"platforms"`
}

type scanObjectPlatformDTO struct {
	Platform   string `json:"platform"`
	K8sVersion string `json:"kube_version,omitempty"`
	OCVersion  string `json:"openshift_version,omitempty"`
	scanObjectBriefDTO
}

type scanObjectBriefDTO struct {
	Status           string `json:"status"`
	CriticalVuls     int    `json:"critical"`
	HighVuls         int    `json:"high"`
	MedVuls          int    `json:"medium"`
	Result           string `json:"result,omitempty"`
	ScannedTimeStamp int64  `json:"scanned_timestamp,omitempty"`
	ScannedAt        string `json:"scanned_at,omitempty"`
	BaseOS           string `json:"base_os,omitempty"`
	CVEDBVersion     string `json:"scanner_version,omitempty"`
	CVEDBCreateTime  string `json:"cvedb_create_time,omitempty"`
	OSScanStatus     string `json:"os_scan_status,omitempty"`
}

type scanObjectReportBody struct {
	Vulnerabilities []scanObjectVulnerabilityDTO `json:"vulnerabilities"`
	Modules         []any                        `json:"modules,omitempty"`
}

type scanObjectVulnerabilityDTO struct {
	Name           string  `json:"name"`
	Score          float64 `json:"score,omitempty"`
	Severity       string  `json:"severity"`
	Vectors        string  `json:"vectors,omitempty"`
	Description    string  `json:"description,omitempty"`
	PackageName    string  `json:"package_name,omitempty"`
	PackageVersion string  `json:"package_version,omitempty"`
	FixedVersion   string  `json:"fixed_version,omitempty"`
	Link           string  `json:"link,omitempty"`
	ScoreV3        float64 `json:"score_v3,omitempty"`
	VectorsV3      string  `json:"vectors_v3,omitempty"`
}

type scanObjectJobState struct {
	Status         string
	Error          string
	PackageCount   int
	FindingCount   int
	BundleMetadata json.RawMessage
	RequestedAt    time.Time
	ClaimedAt      *time.Time
	FinishedAt     *time.Time
}

type scanObjectCounts struct {
	Critical int
	High     int
	Medium   int
}

func (h *ScanJobs) TriggerWorkload(w http.ResponseWriter, r *http.Request) {
	h.triggerScanObject(w, r, "workload", strings.TrimSpace(chi.URLParam(r, "id")), "runtime-agent")
}

func (h *ScanJobs) WorkloadReport(w http.ResponseWriter, r *http.Request) {
	h.scanObjectReport(w, r, "workload", strings.TrimSpace(chi.URLParam(r, "id")))
}

func (h *ScanJobs) TriggerHost(w http.ResponseWriter, r *http.Request) {
	h.triggerScanObject(w, r, "host", strings.TrimSpace(chi.URLParam(r, "id")), "host")
}

func (h *ScanJobs) HostReport(w http.ResponseWriter, r *http.Request) {
	h.scanObjectReport(w, r, "host", strings.TrimSpace(chi.URLParam(r, "id")))
}

func (h *ScanJobs) TriggerPlatform(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	clusterID, ok := h.platformScanClusterID(w, r, subj.OrgID)
	if !ok {
		return
	}
	h.triggerScanObjectWithCluster(w, r, "platform", handler.PlatformTargetRef(clusterID), "platform", &clusterID)
}

func (h *ScanJobs) PlatformReport(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	clusterID, ok := h.platformScanClusterID(w, r, subj.OrgID)
	if !ok {
		return
	}
	h.scanObjectReportWithCluster(w, r, "platform", handler.PlatformTargetRef(clusterID), &clusterID, true)
}

func (h *ScanJobs) PlatformSummary(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	clusterID, ok := h.platformScanClusterID(w, r, subj.OrgID)
	if !ok {
		return
	}
	target, err := h.scanObjectTarget(r.Context(), subj.OrgID, "platform", handler.PlatformTargetRef(clusterID), &clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	brief, err := h.scanObjectBrief(r.Context(), subj.OrgID, target)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	item := scanObjectPlatformDTO{
		Platform:           "kubernetes",
		scanObjectBriefDTO: brief,
	}
	_ = h.db.Pool().QueryRow(r.Context(), `
SELECT COALESCE(distro, 'kubernetes')
  FROM clusters
 WHERE id = $1 AND org_id = $2`, clusterID, subj.OrgID).Scan(&item.Platform)
	_ = h.db.Pool().QueryRow(r.Context(), `
SELECT COALESCE(kubernetes_git_version, '')
  FROM cluster_platform_facts
 WHERE org_id = $1 AND cluster_id = $2
 ORDER BY observed_at DESC
 LIMIT 1`, subj.OrgID, clusterID).Scan(&item.K8sVersion)
	httpx.WriteJSON(w, http.StatusOK, scanObjectPlatformSummaryDTO{Platforms: []scanObjectPlatformDTO{item}})
}

func (h *ScanJobs) triggerScanObject(w http.ResponseWriter, r *http.Request, targetType, targetRef, sourceType string) {
	clusterID, ok := scanObjectOptionalClusterID(w, r)
	if !ok {
		return
	}
	h.triggerScanObjectWithCluster(w, r, targetType, targetRef, sourceType, clusterID)
}

func (h *ScanJobs) triggerScanObjectWithCluster(w http.ResponseWriter, r *http.Request, targetType, targetRef, sourceType string, clusterID *uuid.UUID) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		jsonError(w, http.StatusBadRequest, "scan object id required")
		return
	}
	target, err := h.scanObjectTarget(r.Context(), subj.OrgID, targetType, targetRef, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan target: "+err.Error())
		return
	}
	if target == nil {
		jsonError(w, http.StatusNotFound, "scan target not found")
		return
	}
	if target.SourceType != sourceType {
		jsonError(w, http.StatusConflict, "scan target source mismatch")
		return
	}
	evidence, err := h.scanObjectEvidence(r.Context(), subj.OrgID, target.ID, target.InventoryHash)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan evidence: "+err.Error())
		return
	}
	if evidence == nil || evidence.PackageCount == 0 {
		jsonError(w, http.StatusConflict, "package evidence is missing")
		return
	}
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	jobID, err := handler.EnqueueScanJobIfIdle(r.Context(), tx, subj.OrgID, target.ID, &subj.UserID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan job: "+err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID:      &subj.OrgID,
			ActorID:    &subj.UserID,
			Action:     "scan-object.enqueue",
			TargetKind: "scan-target",
			TargetID:   target.ID.String(),
			After: map[string]any{
				"target_type": target.Type,
				"target_ref":  target.Ref,
				"job_id":      jobID,
			},
		})
	}
	out := scanObjectTriggerDTO{
		Status:          "scheduled",
		TargetID:        target.ID,
		TargetType:      target.Type,
		TargetRef:       target.Ref,
		ScanEvidenceID:  evidence.ID,
		InventoryHash:   evidence.InventoryHash,
		ScanJobEnqueued: jobID != nil,
		JobID:           jobID,
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *ScanJobs) scanObjectReport(w http.ResponseWriter, r *http.Request, targetType, targetRef string) {
	clusterID, ok := scanObjectOptionalClusterID(w, r)
	if !ok {
		return
	}
	h.scanObjectReportWithCluster(w, r, targetType, targetRef, clusterID, false)
}

func (h *ScanJobs) scanObjectReportWithCluster(w http.ResponseWriter, r *http.Request, targetType, targetRef string, clusterID *uuid.UUID, requireTarget bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		jsonError(w, http.StatusBadRequest, "scan object id required")
		return
	}
	target, err := h.scanObjectTarget(r.Context(), subj.OrgID, targetType, targetRef, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if target == nil && requireTarget {
		jsonError(w, http.StatusNotFound, "scan report not found")
		return
	}
	brief, err := h.scanObjectBrief(r.Context(), subj.OrgID, target)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	vuls, err := h.scanObjectVulnerabilities(r.Context(), subj.OrgID, target)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, scanObjectReportDTO{
		ScanSummary: brief,
		Report: scanObjectReportBody{
			Vulnerabilities: vuls,
		},
	})
}

type scanObjectEvidenceDTO struct {
	ID            uuid.UUID
	InventoryHash string
	PackageCount  int
}

func (h *ScanJobs) scanObjectEvidence(ctx context.Context, orgID, targetID uuid.UUID, inventoryHash string) (*scanObjectEvidenceDTO, error) {
	var out scanObjectEvidenceDTO
	err := h.db.Pool().QueryRow(ctx, `
SELECT id, COALESCE(inventory_hash, ''), COALESCE(package_count, 0)
  FROM scan_evidence
 WHERE org_id = $1
   AND scan_target_id = $2
   AND evidence_type = $3
   AND ($4 = '' OR inventory_hash = $4)
 ORDER BY observed_at DESC
 LIMIT 1`, orgID, targetID, handler.PackageInventoryEvidence, inventoryHash).Scan(&out.ID, &out.InventoryHash, &out.PackageCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func scanObjectOptionalClusterID(w http.ResponseWriter, r *http.Request) (*uuid.UUID, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if raw == "" {
		return nil, true
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid cluster_id")
		return nil, false
	}
	return &parsed, true
}

func (h *ScanJobs) platformScanClusterID(w http.ResponseWriter, r *http.Request, orgID uuid.UUID) (uuid.UUID, bool) {
	if clusterID, ok := scanObjectOptionalClusterID(w, r); !ok {
		return uuid.Nil, false
	} else if clusterID != nil {
		var exists bool
		if err := h.db.Pool().QueryRow(r.Context(), `
SELECT EXISTS(SELECT 1 FROM clusters WHERE id = $1 AND org_id = $2)`, *clusterID, orgID).Scan(&exists); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return uuid.Nil, false
		}
		if !exists {
			jsonError(w, http.StatusNotFound, "cluster not found")
			return uuid.Nil, false
		}
		return *clusterID, true
	}
	var clusterID uuid.UUID
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id
  FROM clusters
 WHERE org_id = $1
 ORDER BY last_heartbeat_at DESC NULLS LAST, created_at DESC
 LIMIT 1`, orgID).Scan(&clusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusBadRequest, "cluster_id required")
		return uuid.Nil, false
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return uuid.Nil, false
	}
	return clusterID, true
}

func (h *ScanJobs) scanObjectTarget(ctx context.Context, orgID uuid.UUID, targetType, targetRef string, clusterID *uuid.UUID) (*handler.ScanTarget, error) {
	row := handler.ScanTarget{}
	var metadataRaw []byte
	err := h.db.Pool().QueryRow(ctx, `
SELECT id, org_id, cluster_id, type, ref, source_type,
       COALESCE(source_ref, ''), COALESCE(image_ref, ''), COALESCE(image_digest, ''),
       registry_id, COALESCE(platform, ''), COALESCE(inventory_hash, ''), metadata
  FROM scan_targets
 WHERE org_id = $1
   AND type = $2
   AND ref = $3
   AND ($4::uuid IS NULL OR cluster_id = $4)
 ORDER BY last_seen_at DESC
 LIMIT 1`, orgID, targetType, targetRef, clusterID).Scan(&row.ID, &row.OrgID, &row.ClusterID, &row.Type, &row.Ref, &row.SourceType,
		&row.SourceRef, &row.ImageRef, &row.ImageDigest, &row.RegistryID, &row.Platform, &row.InventoryHash, &metadataRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row.Metadata = handler.NormalizedJSONRaw(metadataRaw)
	return &row, nil
}

func (h *ScanJobs) scanObjectBrief(ctx context.Context, orgID uuid.UUID, target *handler.ScanTarget) (scanObjectBriefDTO, error) {
	if target == nil {
		return scanObjectBriefDTO{Status: ""}, nil
	}
	counts, err := h.scanObjectCounts(ctx, orgID, target.ID)
	if err != nil {
		return scanObjectBriefDTO{}, err
	}
	job, err := h.latestScanObjectJob(ctx, orgID, target.ID)
	if err != nil {
		return scanObjectBriefDTO{}, err
	}
	brief := scanObjectBriefDTO{
		Status:       "",
		CriticalVuls: counts.Critical,
		HighVuls:     counts.High,
		MedVuls:      counts.Medium,
		BaseOS:       scanObjectBaseOS(target.Metadata),
	}
	if job == nil {
		return brief, nil
	}
	brief.Status = scanObjectRESTStatus(job.Status)
	brief.Result = scanObjectResult(job)
	if job.FinishedAt != nil {
		brief.ScannedTimeStamp = job.FinishedAt.UTC().Unix()
		brief.ScannedAt = job.FinishedAt.UTC().Format(time.RFC3339)
	}
	brief.CVEDBVersion, brief.CVEDBCreateTime = scanObjectBundleInfo(job.BundleMetadata)
	if brief.CVEDBVersion == "" && brief.CVEDBCreateTime == "" {
		brief.CVEDBVersion, brief.CVEDBCreateTime = h.latestScannerBundleInfo(ctx, orgID)
	}
	return brief, nil
}

func (h *ScanJobs) latestScanObjectJob(ctx context.Context, orgID, targetID uuid.UUID) (*scanObjectJobState, error) {
	var out scanObjectJobState
	err := h.db.Pool().QueryRow(ctx, `
SELECT status, COALESCE(error, ''), COALESCE(package_count, 0), COALESCE(finding_count, 0),
       COALESCE(bundle_metadata, '{}'::jsonb), requested_at, claimed_at, finished_at
  FROM scan_jobs
 WHERE org_id = $1 AND target_id = $2
 ORDER BY requested_at DESC
 LIMIT 1`, orgID, targetID).Scan(&out.Status, &out.Error, &out.PackageCount, &out.FindingCount, &out.BundleMetadata,
		&out.RequestedAt, &out.ClaimedAt, &out.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &out, err
}

func (h *ScanJobs) scanObjectCounts(ctx context.Context, orgID, targetID uuid.UUID) (scanObjectCounts, error) {
	var out scanObjectCounts
	err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE severity = 'critical')::int,
       COUNT(*) FILTER (WHERE severity = 'high')::int,
       COUNT(*) FILTER (WHERE severity = 'medium')::int
  FROM findings
 WHERE org_id = $1
   AND scan_target_id = $2
   AND kind = 'vulnerability'
   AND lifecycle = 'open'`, orgID, targetID).Scan(&out.Critical, &out.High, &out.Medium)
	return out, err
}

func (h *ScanJobs) scanObjectVulnerabilities(ctx context.Context, orgID uuid.UUID, target *handler.ScanTarget) ([]scanObjectVulnerabilityDTO, error) {
	if target == nil {
		return []scanObjectVulnerabilityDTO{}, nil
	}
	rows, err := h.db.Pool().Query(ctx, `
SELECT COALESCE(external_id, ''),
       COALESCE(severity, ''),
       COALESCE(NULLIF(description, ''), title, ''),
       COALESCE(detail_json->'package'->>'name', ''),
       COALESCE(detail_json->'package'->>'version', ''),
       COALESCE(detail_json->>'fixed', detail_json->>'fixed_version', ''),
       CASE
         WHEN COALESCE(detail_json->>'cvss_base', '') ~ '^[0-9]+(\.[0-9]+)?$'
         THEN (detail_json->>'cvss_base')::float
         ELSE 0
       END,
       COALESCE(detail_json->>'cvss_vector', ''),
       COALESCE(detail_json->'references'->>0, '')
  FROM findings
 WHERE org_id = $1
   AND scan_target_id = $2
   AND kind = 'vulnerability'
   AND lifecycle = 'open'
 ORDER BY risk_score DESC NULLS LAST, last_seen_at DESC
 LIMIT 2000`, orgID, target.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []scanObjectVulnerabilityDTO{}
	for rows.Next() {
		var item scanObjectVulnerabilityDTO
		if err := rows.Scan(&item.Name, &item.Severity, &item.Description, &item.PackageName, &item.PackageVersion,
			&item.FixedVersion, &item.ScoreV3, &item.VectorsV3, &item.Link); err != nil {
			return nil, err
		}
		item.Score = item.ScoreV3
		item.Vectors = item.VectorsV3
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanObjectRESTStatus(status string) string {
	switch status {
	case "pending", "paused":
		return "scheduled"
	case "running":
		return "scanning"
	case "completed":
		return "finished"
	case "failed":
		return "failed"
	case "canceled":
		return "canceled"
	default:
		return ""
	}
}

func scanObjectResult(job *scanObjectJobState) string {
	if job == nil {
		return ""
	}
	switch job.Status {
	case "completed":
		return "succeeded"
	case "failed":
		if job.Error != "" {
			return job.Error
		}
		return "failed"
	case "canceled":
		return "canceled"
	default:
		return ""
	}
}

func scanObjectBaseOS(metadata json.RawMessage) string {
	if len(metadata) == 0 {
		return ""
	}
	var decoded map[string]any
	if err := json.Unmarshal(metadata, &decoded); err != nil {
		return ""
	}
	for _, key := range []string{"base_os", "os", "distro"} {
		if value, ok := decoded[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func scanObjectBundleInfo(raw json.RawMessage) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", ""
	}
	return handler.MetadataString(decoded, "bundle_version"), handler.MetadataString(decoded, "exported_at")
}

func (h *ScanJobs) latestScannerBundleInfo(ctx context.Context, orgID uuid.UUID) (string, string) {
	var version, created string
	_ = h.db.Pool().QueryRow(ctx, `
SELECT COALESCE(metadata->'vulndb'->>'bundle_version', ''),
       COALESCE(metadata->'vulndb'->>'exported_at', '')
  FROM component_heartbeats
 WHERE org_id = $1
   AND component = 'scanner'
   AND last_seen_at > NOW() - INTERVAL '24 hours'
 ORDER BY last_seen_at DESC
 LIMIT 1`, orgID).Scan(&version, &created)
	return version, created
}
