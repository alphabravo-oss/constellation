package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

const platformTargetRefPrefix = "cluster:"

type PlatformFactsHandler struct {
	db *db.DB
}

func NewPlatformFacts(d *db.DB) *PlatformFactsHandler {
	return &PlatformFactsHandler{db: d}
}

type PlatformFactsReport struct {
	ClusterID            uuid.UUID           `json:"cluster_id"`
	ClusterName          string              `json:"cluster_name,omitempty"`
	ObservedAt           time.Time           `json:"observed_at"`
	Distro               string              `json:"distro,omitempty"`
	KubernetesGitVersion string              `json:"kubernetes_git_version,omitempty"`
	KubernetesMajor      string              `json:"kubernetes_major,omitempty"`
	KubernetesMinor      string              `json:"kubernetes_minor,omitempty"`
	PlatformProvider     string              `json:"platform_provider,omitempty"`
	PlatformVersion      string              `json:"platform_version,omitempty"`
	NodeCount            int                 `json:"node_count,omitempty"`
	KubeletVersions      map[string]int      `json:"kubelet_versions,omitempty"`
	Components           []PlatformComponent `json:"components,omitempty"`
}

type PlatformComponent struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type,omitempty"`
	Source    string `json:"source,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type PlatformFactsResponse struct {
	ClusterID       uuid.UUID               `json:"cluster_id"`
	ClusterName     string                  `json:"cluster_name"`
	Distro          string                  `json:"distro"`
	Status          string                  `json:"status"`
	Facts           *ClusterPlatformFacts   `json:"facts,omitempty"`
	ScanTarget      *PlatformScanTargetView `json:"scan_target,omitempty"`
	Evidence        *PlatformEvidenceView   `json:"evidence,omitempty"`
	LatestJob       *PlatformScanJobView    `json:"latest_job,omitempty"`
	FindingsSummary PlatformFindingsSummary `json:"findings_summary"`
	Findings        []PlatformFindingRow    `json:"findings"`
}

type ClusterPlatformFacts struct {
	ClusterID            uuid.UUID           `json:"cluster_id"`
	Distro               string              `json:"distro"`
	KubernetesGitVersion string              `json:"kubernetes_git_version,omitempty"`
	KubernetesMajor      string              `json:"kubernetes_major,omitempty"`
	KubernetesMinor      string              `json:"kubernetes_minor,omitempty"`
	PlatformProvider     string              `json:"platform_provider,omitempty"`
	PlatformVersion      string              `json:"platform_version,omitempty"`
	NodeCount            int                 `json:"node_count"`
	KubeletVersions      map[string]int      `json:"kubelet_versions,omitempty"`
	Components           []PlatformComponent `json:"components,omitempty"`
	ObservedAt           time.Time           `json:"observed_at"`
	UpdatedAt            time.Time           `json:"updated_at"`
}

type PlatformScanTargetView struct {
	ID            uuid.UUID `json:"id"`
	Ref           string    `json:"ref"`
	SourceType    string    `json:"source_type"`
	SourceRef     string    `json:"source_ref,omitempty"`
	Platform      string    `json:"platform,omitempty"`
	InventoryHash string    `json:"inventory_hash,omitempty"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

type PlatformEvidenceView struct {
	ID            uuid.UUID         `json:"id"`
	InventoryHash string            `json:"inventory_hash"`
	PackageCount  int               `json:"package_count"`
	Packages      []scanner.Package `json:"packages,omitempty"`
	ObservedAt    time.Time         `json:"observed_at"`
}

type PlatformScanJobView struct {
	ID             uuid.UUID               `json:"id"`
	Status         string                  `json:"status"`
	Error          string                  `json:"error,omitempty"`
	PackageCount   int                     `json:"package_count,omitempty"`
	FindingCount   int                     `json:"finding_count,omitempty"`
	BundleMetadata *scanner.BundleMetadata `json:"bundle_metadata,omitempty"`
	RequestedAt    time.Time               `json:"requested_at"`
	ClaimedAt      *time.Time              `json:"claimed_at,omitempty"`
	FinishedAt     *time.Time              `json:"finished_at,omitempty"`
}

type PlatformFindingsSummary struct {
	Open     int `json:"open"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type PlatformFindingRow struct {
	ID             uuid.UUID `json:"id"`
	ExternalID     string    `json:"external_id,omitempty"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	RiskScore      int       `json:"risk_score"`
	PackageName    string    `json:"package_name,omitempty"`
	PackageVersion string    `json:"package_version,omitempty"`
	FixedVersion   string    `json:"fixed_version,omitempty"`
	Source         string    `json:"source,omitempty"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

func (h *PlatformFactsHandler) Report(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromTokenContext(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "service token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)

	var body PlatformFactsReport
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	normalizePlatformFactsReport(&body)
	if body.ClusterID == uuid.Nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}

	var clusterName, clusterDistro string
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT name, distro
  FROM clusters
 WHERE org_id = $1 AND id = $2`, orgID, body.ClusterID).Scan(&clusterName, &clusterDistro)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "cluster lookup: "+err.Error())
		return
	}
	if body.ClusterName == "" {
		body.ClusterName = clusterName
	}
	if body.Distro == "" {
		body.Distro = clusterDistro
	}
	if body.Distro == "" {
		body.Distro = "kubernetes"
	}

	raw, err := json.Marshal(body)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "platform payload: "+err.Error())
		return
	}
	packages := scannerPackagesFromPlatformFacts(body)
	inventoryHash := ""
	if len(packages) > 0 {
		inventoryHash, err = packageEvidenceHash(scanEvidencePackagePayload{
			Packages:      packages,
			Distro:        body.Distro,
			DistroVersion: body.KubernetesGitVersion,
			Source:        "platform",
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "evidence hash: "+err.Error())
			return
		}
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	kubeletRaw, _ := json.Marshal(body.KubeletVersions)
	if _, err := tx.Exec(r.Context(), `
INSERT INTO cluster_platform_facts (
    org_id, cluster_id, distro, kubernetes_git_version, kubernetes_major, kubernetes_minor,
    platform_provider, platform_version, node_count, kubelet_versions, payload, observed_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10::jsonb, $11::jsonb, $12, NOW()
)
ON CONFLICT (org_id, cluster_id) DO UPDATE SET
    distro = EXCLUDED.distro,
    kubernetes_git_version = EXCLUDED.kubernetes_git_version,
    kubernetes_major = EXCLUDED.kubernetes_major,
    kubernetes_minor = EXCLUDED.kubernetes_minor,
    platform_provider = EXCLUDED.platform_provider,
    platform_version = EXCLUDED.platform_version,
    node_count = EXCLUDED.node_count,
    kubelet_versions = EXCLUDED.kubelet_versions,
    payload = EXCLUDED.payload,
    observed_at = EXCLUDED.observed_at,
    updated_at = NOW()`,
		orgID, body.ClusterID, body.Distro, body.KubernetesGitVersion, body.KubernetesMajor, body.KubernetesMinor,
		body.PlatformProvider, body.PlatformVersion, body.NodeCount, string(kubeletRaw), string(raw), body.ObservedAt); err != nil {
		jsonError(w, http.StatusInternalServerError, "upsert facts: "+err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `
UPDATE clusters
   SET distro = COALESCE(NULLIF($3, ''), distro),
       state = 'connected',
       last_heartbeat_at = GREATEST(COALESCE(last_heartbeat_at, $4), $4),
       updated_at = NOW()
 WHERE org_id = $1 AND id = $2`, orgID, body.ClusterID, body.Distro, body.ObservedAt); err != nil {
		jsonError(w, http.StatusInternalServerError, "update cluster: "+err.Error())
		return
	}

	var target scanTarget
	var evidenceID uuid.UUID
	var jobID *uuid.UUID
	if len(packages) > 0 {
		metadata, _ := json.Marshal(map[string]any{
			"cluster_id":             body.ClusterID.String(),
			"cluster_name":           body.ClusterName,
			"distro":                 body.Distro,
			"kubernetes_git_version": body.KubernetesGitVersion,
			"platform_provider":      body.PlatformProvider,
			"platform_version":       body.PlatformVersion,
			"node_count":             body.NodeCount,
			"package_count":          len(packages),
		})
		target, err = upsertScanTarget(r.Context(), nil, tx, orgID, scanTargetUpsert{
			TargetType:      "platform",
			TargetRef:       platformTargetRef(body.ClusterID),
			TargetClusterID: &body.ClusterID,
			SourceType:      "platform",
			SourceRef:       body.ClusterID.String(),
			Platform:        body.Distro,
			InventoryHash:   inventoryHash,
			Metadata:        metadata,
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "scan target: "+err.Error())
			return
		}
		evidencePayload := scanEvidencePackagePayload{
			Packages:      packages,
			Distro:        body.Distro,
			DistroVersion: body.KubernetesGitVersion,
			Source:        "platform",
		}
		evidenceID, err = upsertPackageScanEvidence(r.Context(), tx, orgID, target, inventoryHash, evidencePayload, body.ObservedAt)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "scan evidence: "+err.Error())
			return
		}
		jobID, err = enqueueScanJobIfIdle(r.Context(), tx, orgID, target.ID, nil)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "enqueue scan job: "+err.Error())
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"cluster_id":        body.ClusterID,
		"scan_target_id":    nullableUUID(target.ID),
		"scan_evidence_id":  nullableUUID(evidenceID),
		"inventory_hash":    inventoryHash,
		"package_count":     len(packages),
		"scan_job_enqueued": jobID != nil,
		"scan_job_id":       jobID,
	})
}

func (h *PlatformFactsHandler) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterID, ok := h.clusterIDFromRoute(w, r, subj.OrgID)
	if !ok {
		return
	}
	clusterName, distro, err := h.clusterIdentity(r, subj.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "cluster lookup: "+err.Error())
		return
	}

	facts, err := h.loadFacts(r, subj.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "platform facts: "+err.Error())
		return
	}
	target, err := h.loadPlatformTarget(r, subj.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "platform target: "+err.Error())
		return
	}
	var evidence *PlatformEvidenceView
	var job *PlatformScanJobView
	if target != nil {
		evidence, err = h.loadPlatformEvidence(r, subj.OrgID, target.ID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "platform evidence: "+err.Error())
			return
		}
		job, err = h.loadPlatformJob(r, subj.OrgID, target.ID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "platform job: "+err.Error())
			return
		}
	}
	summary, findingsRows, err := h.loadPlatformFindings(r, subj.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "platform findings: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, PlatformFactsResponse{
		ClusterID:       clusterID,
		ClusterName:     clusterName,
		Distro:          distro,
		Status:          platformFactsStatus(facts, evidence, job),
		Facts:           facts,
		ScanTarget:      target,
		Evidence:        evidence,
		LatestJob:       job,
		FindingsSummary: summary,
		Findings:        findingsRows,
	})
}

func (h *PlatformFactsHandler) Scan(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterID, ok := h.clusterIDFromRoute(w, r, subj.OrgID)
	if !ok {
		return
	}
	target, err := h.loadPlatformTarget(r, subj.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "platform target: "+err.Error())
		return
	}
	if target == nil {
		jsonError(w, http.StatusConflict, "platform facts have not been reported")
		return
	}
	evidence, err := h.loadPlatformEvidence(r, subj.OrgID, target.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "platform evidence: "+err.Error())
		return
	}
	if evidence == nil || evidence.PackageCount == 0 {
		jsonError(w, http.StatusConflict, "platform package evidence is missing")
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	jobID, err := enqueueScanJobIfIdle(r.Context(), tx, subj.OrgID, target.ID, &subj.UserID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "enqueue scan job: "+err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"scan_target_id":    target.ID,
		"scan_evidence_id":  evidence.ID,
		"inventory_hash":    evidence.InventoryHash,
		"scan_job_enqueued": jobID != nil,
		"scan_job_id":       jobID,
	})
}

func (h *PlatformFactsHandler) clusterIDFromRoute(w http.ResponseWriter, r *http.Request, orgID uuid.UUID) (uuid.UUID, bool) {
	clusterID, err := uuid.Parse(chi.URLParam(r, "id"))
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

func (h *PlatformFactsHandler) clusterIdentity(r *http.Request, orgID, clusterID uuid.UUID) (name, distro string, err error) {
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT name, distro
  FROM clusters
 WHERE org_id = $1 AND id = $2`, orgID, clusterID).Scan(&name, &distro)
	return name, distro, err
}

func (h *PlatformFactsHandler) loadFacts(r *http.Request, orgID, clusterID uuid.UUID) (*ClusterPlatformFacts, error) {
	var row ClusterPlatformFacts
	var kubeletRaw, payloadRaw []byte
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT cluster_id, distro, kubernetes_git_version, kubernetes_major, kubernetes_minor,
       platform_provider, platform_version, node_count, kubelet_versions, payload,
       observed_at, updated_at
  FROM cluster_platform_facts
 WHERE org_id = $1 AND cluster_id = $2`, orgID, clusterID).Scan(
		&row.ClusterID, &row.Distro, &row.KubernetesGitVersion, &row.KubernetesMajor, &row.KubernetesMinor,
		&row.PlatformProvider, &row.PlatformVersion, &row.NodeCount, &kubeletRaw, &payloadRaw,
		&row.ObservedAt, &row.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(kubeletRaw, &row.KubeletVersions)
	var payload PlatformFactsReport
	if err := json.Unmarshal(payloadRaw, &payload); err == nil {
		row.Components = payload.Components
	}
	return &row, nil
}

func (h *PlatformFactsHandler) loadPlatformTarget(r *http.Request, orgID, clusterID uuid.UUID) (*PlatformScanTargetView, error) {
	var out PlatformScanTargetView
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id, ref, source_type, COALESCE(source_ref, ''), COALESCE(platform, ''),
       COALESCE(inventory_hash, ''), last_seen_at
  FROM scan_targets
 WHERE org_id = $1
   AND cluster_id = $2
   AND type = 'platform'
 ORDER BY last_seen_at DESC
 LIMIT 1`, orgID, clusterID).Scan(&out.ID, &out.Ref, &out.SourceType, &out.SourceRef, &out.Platform, &out.InventoryHash, &out.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &out, err
}

func (h *PlatformFactsHandler) loadPlatformEvidence(r *http.Request, orgID, targetID uuid.UUID) (*PlatformEvidenceView, error) {
	var out PlatformEvidenceView
	var payloadRaw []byte
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id, inventory_hash, package_count, payload, observed_at
  FROM scan_evidence
 WHERE org_id = $1
   AND scan_target_id = $2
   AND evidence_type = $3
 ORDER BY observed_at DESC
 LIMIT 1`, orgID, targetID, packageInventoryEvidence).Scan(&out.ID, &out.InventoryHash, &out.PackageCount, &payloadRaw, &out.ObservedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var payload scanEvidencePackagePayload
	if err := json.Unmarshal(payloadRaw, &payload); err == nil {
		out.Packages = payload.Packages
	}
	return &out, nil
}

func (h *PlatformFactsHandler) loadPlatformJob(r *http.Request, orgID, targetID uuid.UUID) (*PlatformScanJobView, error) {
	var out PlatformScanJobView
	var bundleRaw []byte
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id, status, COALESCE(error, ''), COALESCE(package_count, 0), COALESCE(finding_count, 0),
       COALESCE(bundle_metadata, '{}'::jsonb), requested_at, claimed_at, finished_at
  FROM scan_jobs
 WHERE org_id = $1 AND target_id = $2
 ORDER BY requested_at DESC
 LIMIT 1`, orgID, targetID).Scan(&out.ID, &out.Status, &out.Error, &out.PackageCount, &out.FindingCount,
		&bundleRaw, &out.RequestedAt, &out.ClaimedAt, &out.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var metadata scanner.BundleMetadata
	if len(bundleRaw) > 0 && string(bundleRaw) != "{}" {
		if err := json.Unmarshal(bundleRaw, &metadata); err == nil {
			out.BundleMetadata = &metadata
		}
	}
	return &out, nil
}

func (h *PlatformFactsHandler) loadPlatformFindings(r *http.Request, orgID, clusterID uuid.UUID) (PlatformFindingsSummary, []PlatformFindingRow, error) {
	var summary PlatformFindingsSummary
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT COUNT(*) FILTER (WHERE lifecycle = 'open'),
       COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'critical'),
       COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'high'),
       COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'medium'),
       COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'low')
  FROM findings
 WHERE org_id = $1
   AND kind = 'vulnerability'
   AND target_type = 'platform'
   AND target_cluster_id = $2`, orgID, clusterID).Scan(&summary.Open, &summary.Critical, &summary.High, &summary.Medium, &summary.Low); err != nil {
		return summary, nil, err
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, COALESCE(external_id, ''), title, severity, risk_score,
       COALESCE(detail_json->'package'->>'name', ''),
       COALESCE(detail_json->'package'->>'version', ''),
       COALESCE(detail_json->>'fixed', ''),
       COALESCE(NULLIF(source_type, ''), NULLIF(canonical_engine, ''), 'scanner'),
       last_seen_at
  FROM findings
 WHERE org_id = $1
   AND kind = 'vulnerability'
   AND lifecycle = 'open'
   AND target_type = 'platform'
   AND target_cluster_id = $2
 ORDER BY risk_score DESC NULLS LAST, last_seen_at DESC
 LIMIT 50`, orgID, clusterID)
	if err != nil {
		return summary, nil, err
	}
	defer rows.Close()
	out := []PlatformFindingRow{}
	for rows.Next() {
		var row PlatformFindingRow
		if err := rows.Scan(&row.ID, &row.ExternalID, &row.Title, &row.Severity, &row.RiskScore,
			&row.PackageName, &row.PackageVersion, &row.FixedVersion, &row.Source, &row.LastSeenAt); err != nil {
			return summary, nil, err
		}
		out = append(out, row)
	}
	return summary, out, rows.Err()
}

func normalizePlatformFactsReport(body *PlatformFactsReport) {
	body.ClusterName = strings.TrimSpace(body.ClusterName)
	body.Distro = strings.ToLower(strings.TrimSpace(body.Distro))
	body.KubernetesGitVersion = strings.TrimSpace(body.KubernetesGitVersion)
	body.KubernetesMajor = strings.TrimSpace(body.KubernetesMajor)
	body.KubernetesMinor = strings.TrimSpace(body.KubernetesMinor)
	body.PlatformProvider = strings.TrimSpace(body.PlatformProvider)
	body.PlatformVersion = strings.TrimSpace(body.PlatformVersion)
	if body.ObservedAt.IsZero() {
		body.ObservedAt = time.Now().UTC()
	} else {
		body.ObservedAt = body.ObservedAt.UTC()
	}
	if body.NodeCount < 0 {
		body.NodeCount = 0
	}
	if body.KubeletVersions == nil {
		body.KubeletVersions = map[string]int{}
	}
	components := make([]PlatformComponent, 0, len(body.Components))
	for _, component := range body.Components {
		component.Name = canonicalPlatformPackageName(component.Name)
		component.Version = strings.TrimSpace(component.Version)
		component.Type = strings.TrimSpace(component.Type)
		component.Source = strings.TrimSpace(component.Source)
		component.Namespace = strings.TrimSpace(component.Namespace)
		if component.Name == "" || component.Version == "" {
			continue
		}
		components = append(components, component)
	}
	body.Components = components
}

func scannerPackagesFromPlatformFacts(body PlatformFactsReport) []scanner.Package {
	type key struct {
		namespace string
		name      string
		version   string
	}
	seen := map[key]bool{}
	out := []scanner.Package{}
	add := func(name, namespace, version string) {
		name = canonicalPlatformPackageName(name)
		namespace = canonicalPlatformNamespace(namespace, name)
		version = strings.TrimSpace(version)
		if name == "" || namespace == "" || version == "" {
			return
		}
		k := key{namespace: namespace, name: name, version: version}
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, scanner.Package{
			Ecosystem:     "generic",
			Name:          name,
			Version:       version,
			Purl:          "pkg:generic/" + name,
			NamespaceKind: "generic",
			NamespaceName: namespace,
		})
	}

	add("kubernetes", "kubernetes", body.KubernetesGitVersion)
	if strings.Contains(strings.ToLower(body.Distro), "k3s") || strings.Contains(strings.ToLower(body.KubernetesGitVersion), "+k3s") {
		add("k3s", "k3s", body.KubernetesGitVersion)
	}
	if body.PlatformVersion != "" && body.Distro != "" && body.Distro != "kubernetes" {
		add(body.Distro, body.Distro, body.PlatformVersion)
	}
	for version := range body.KubeletVersions {
		add("kubelet", "kubernetes", version)
	}
	for _, component := range body.Components {
		add(component.Name, component.Namespace, component.Version)
	}
	return out
}

func canonicalPlatformPackageName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer(" ", "-", "_", "-").Replace(value)
	value = strings.Trim(value, "-")
	return value
}

func canonicalPlatformNamespace(namespace, name string) string {
	namespace = canonicalPlatformPackageName(namespace)
	if namespace != "" {
		return namespace
	}
	switch {
	case name == "k3s" || strings.HasPrefix(name, "k3s-"):
		return "k3s"
	default:
		return "kubernetes"
	}
}

func platformTargetRef(clusterID uuid.UUID) string {
	return platformTargetRefPrefix + clusterID.String()
}

// PlatformTargetRef / EnqueueScanJobIfIdle are exported seams over the
// package-internal helpers, consumed by the handler/scanning sub-package.
func PlatformTargetRef(clusterID uuid.UUID) string { return platformTargetRef(clusterID) }

// EnqueueScanJobIfIdle is the exported seam over enqueueScanJobIfIdle.
func EnqueueScanJobIfIdle(ctx context.Context, tx pgx.Tx, orgID, targetID uuid.UUID, requestedBy *uuid.UUID) (*uuid.UUID, error) {
	return enqueueScanJobIfIdle(ctx, tx, orgID, targetID, requestedBy)
}

func enqueueScanJobIfIdle(ctx context.Context, tx pgx.Tx, orgID, targetID uuid.UUID, requestedBy *uuid.UUID) (*uuid.UUID, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS(
    SELECT 1
      FROM scan_jobs
     WHERE org_id = $1
       AND target_id = $2
       AND status IN ('pending', 'running', 'paused')
)`, orgID, targetID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, nil
	}
	id := uuid.New()
	var requestedByArg any
	if requestedBy != nil {
		requestedByArg = *requestedBy
	}
	_, err := tx.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status, requested_by)
VALUES ($1, $2, $3, 'pending', $4)`, id, orgID, targetID, requestedByArg)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func platformFactsStatus(facts *ClusterPlatformFacts, evidence *PlatformEvidenceView, job *PlatformScanJobView) string {
	if facts == nil {
		return "missing"
	}
	if job != nil {
		if job.Status == "completed" {
			return "scanned"
		}
		return job.Status
	}
	if evidence != nil {
		return "ready"
	}
	return "reported"
}
