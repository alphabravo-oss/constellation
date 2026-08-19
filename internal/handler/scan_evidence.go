package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

const packageInventoryEvidence = "package-inventory"

// PackageInventoryEvidence is the exported seam over packageInventoryEvidence,
// used by handler sub-packages (e.g. handler/findings) during the D2
// god-package split.
const PackageInventoryEvidence = packageInventoryEvidence

type scanEvidencePackagePayload struct {
	Packages      []scanner.Package       `json:"packages"`
	Distro        string                  `json:"distro,omitempty"`
	DistroVersion string                  `json:"distro_version,omitempty"`
	Source        string                  `json:"source,omitempty"`
	Node          string                  `json:"node,omitempty"`
	WorkloadID    string                  `json:"workload_id,omitempty"`
	Namespace     string                  `json:"namespace,omitempty"`
	PodName       string                  `json:"pod_name,omitempty"`
	PodUID        string                  `json:"pod_uid,omitempty"`
	Runtime       string                  `json:"runtime,omitempty"`
	Containers    []scanEvidenceContainer `json:"containers,omitempty"`
	FunctionRef   string                  `json:"function_ref,omitempty"`
	Provider      string                  `json:"provider,omitempty"`
	AccountID     string                  `json:"account_id,omitempty"`
	Region        string                  `json:"region,omitempty"`
	Version       string                  `json:"version,omitempty"`
	Architecture  string                  `json:"architecture,omitempty"`
	RepositoryRef string                  `json:"repository_ref,omitempty"`
	RepositoryURL string                  `json:"repository_url,omitempty"`
	CommitSHA     string                  `json:"commit_sha,omitempty"`
	Branch        string                  `json:"branch,omitempty"`
	Path          string                  `json:"path,omitempty"`
	Workflow      string                  `json:"workflow,omitempty"`
	RunID         string                  `json:"run_id,omitempty"`
}

type scanEvidenceContainer struct {
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	Image         string `json:"image,omitempty"`
	ImageRef      string `json:"image_ref,omitempty"`
	Distro        string `json:"distro,omitempty"`
	DistroVersion string `json:"distro_version,omitempty"`
	Source        string `json:"source,omitempty"`
	PackageCount  int    `json:"package_count,omitempty"`
}

type scanEvidenceWriter interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ScanEvidenceWriter is the exported seam over scanEvidenceWriter for the
// scanning sub-package.
type ScanEvidenceWriter = scanEvidenceWriter

// ScanEvidencePackagePayload / ScanEvidenceContainer are exported seams over
// the package-inventory evidence payload types, consumed by the scanning
// sub-package (workload/serverless package ingest).
type ScanEvidencePackagePayload = scanEvidencePackagePayload

type ScanEvidenceContainer = scanEvidenceContainer

// UpsertPackageScanEvidence is the exported seam over upsertPackageScanEvidence.
func UpsertPackageScanEvidence(ctx context.Context, q ScanEvidenceWriter, orgID uuid.UUID, target ScanTarget, inventoryHash string, payload ScanEvidencePackagePayload, observedAt time.Time) (uuid.UUID, error) {
	return upsertPackageScanEvidence(ctx, q, orgID, target, inventoryHash, payload, observedAt)
}

type ScanEvidence struct {
	db *db.DB
}

func NewScanEvidence(d *db.DB) *ScanEvidence {
	return &ScanEvidence{db: d}
}

func upsertPackageScanEvidence(ctx context.Context, q scanEvidenceWriter, orgID uuid.UUID, target scanTarget, inventoryHash string, payload scanEvidencePackagePayload, observedAt time.Time) (uuid.UUID, error) {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = q.QueryRow(ctx, `
INSERT INTO scan_evidence (
    org_id, scan_target_id, cluster_id, target_type, target_ref,
    source_type, source_ref, evidence_type, inventory_hash, package_count,
    payload, observed_at
) VALUES ($1, $2, $3, $4, $5,
          $6, NULLIF($7,''), $8, $9, $10,
          $11::jsonb, $12)
ON CONFLICT (org_id, scan_target_id, evidence_type, inventory_hash) DO UPDATE SET
    package_count = EXCLUDED.package_count,
    payload       = EXCLUDED.payload,
    observed_at   = EXCLUDED.observed_at,
    created_at    = NOW()
RETURNING id`,
		orgID, target.ID, target.ClusterID, target.Type, target.Ref,
		target.SourceType, target.SourceRef, packageInventoryEvidence, inventoryHash, len(payload.Packages),
		string(raw), observedAt).Scan(&id)
	return id, err
}

func latestPackageEvidenceID(ctx context.Context, q scanEvidenceWriter, orgID, targetID uuid.UUID, inventoryHash string) (*uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `
SELECT id
  FROM scan_evidence
 WHERE org_id = $1
   AND scan_target_id = $2
   AND evidence_type = $3
   AND ($4 = '' OR inventory_hash = $4)
 ORDER BY observed_at DESC
 LIMIT 1`, orgID, targetID, packageInventoryEvidence, inventoryHash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func (h *ScanEvidence) Get(w http.ResponseWriter, r *http.Request) {
	token, ok := scannerTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "scanner token required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid evidence id")
		return
	}

	var (
		targetID      uuid.UUID
		targetType    string
		targetRef     string
		sourceType    string
		sourceRef     string
		evidenceType  string
		inventoryHash string
		packageCount  int
		payloadRaw    []byte
		observedAt    time.Time
	)
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT scan_target_id, target_type, target_ref, source_type, COALESCE(source_ref, ''),
       evidence_type, inventory_hash, package_count, payload, observed_at
  FROM scan_evidence
 WHERE id = $1
   AND org_id = $2`, id, token.OrgID).Scan(&targetID, &targetType, &targetRef, &sourceType, &sourceRef,
		&evidenceType, &inventoryHash, &packageCount, &payloadRaw, &observedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "evidence not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var payload scanEvidencePackagePayload
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		jsonError(w, http.StatusInternalServerError, "invalid evidence payload")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             id,
		"target_id":      targetID,
		"target_type":    targetType,
		"target_ref":     targetRef,
		"source_type":    sourceType,
		"source_ref":     sourceRef,
		"evidence_type":  evidenceType,
		"inventory_hash": inventoryHash,
		"package_count":  packageCount,
		"packages":       payload.Packages,
		"distro":         payload.Distro,
		"distro_version": payload.DistroVersion,
		"source":         payload.Source,
		"node":           payload.Node,
		"workload_id":    payload.WorkloadID,
		"namespace":      payload.Namespace,
		"pod_name":       payload.PodName,
		"pod_uid":        payload.PodUID,
		"runtime":        payload.Runtime,
		"containers":     payload.Containers,
		"function_ref":   payload.FunctionRef,
		"provider":       payload.Provider,
		"account_id":     payload.AccountID,
		"region":         payload.Region,
		"version":        payload.Version,
		"architecture":   payload.Architecture,
		"repository_ref": payload.RepositoryRef,
		"repository_url": payload.RepositoryURL,
		"commit_sha":     payload.CommitSHA,
		"branch":         payload.Branch,
		"path":           payload.Path,
		"workflow":       payload.Workflow,
		"run_id":         payload.RunID,
		"observed_at":    observedAt,
	})
}
