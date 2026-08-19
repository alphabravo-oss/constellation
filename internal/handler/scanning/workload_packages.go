package scanning

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

type WorkloadPackagesHandler struct {
	db *db.DB
}

func NewWorkloadPackages(d *db.DB) *WorkloadPackagesHandler {
	return &WorkloadPackagesHandler{db: d}
}

type WorkloadPackagesPayload struct {
	ClusterID  *uuid.UUID                 `json:"cluster_id,omitempty"`
	Node       string                     `json:"node"`
	ObservedAt time.Time                  `json:"observed_at"`
	Runtime    string                     `json:"runtime,omitempty"`
	WorkloadID string                     `json:"workload_id"`
	Namespace  string                     `json:"namespace,omitempty"`
	PodName    string                     `json:"pod_name,omitempty"`
	PodUID     string                     `json:"pod_uid,omitempty"`
	Count      int                        `json:"count"`
	Containers []WorkloadPackageContainer `json:"containers"`
}

type WorkloadPackageContainer struct {
	ContainerID   string                    `json:"container_id"`
	ContainerName string                    `json:"container_name,omitempty"`
	ContainerPID  int                       `json:"container_pid,omitempty"`
	Image         string                    `json:"image,omitempty"`
	ImageRef      string                    `json:"image_ref,omitempty"`
	Distro        string                    `json:"distro,omitempty"`
	DistroVersion string                    `json:"distro_version,omitempty"`
	Source        string                    `json:"source,omitempty"`
	Count         int                       `json:"count"`
	Items         []handler.HostPackageItem `json:"items"`
}

func (h *WorkloadPackagesHandler) Report(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)

	var body WorkloadPackagesPayload
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	body.Node = strings.TrimSpace(body.Node)
	body.WorkloadID = strings.TrimSpace(body.WorkloadID)
	body.Namespace = strings.TrimSpace(body.Namespace)
	body.PodName = strings.TrimSpace(body.PodName)
	body.PodUID = strings.TrimSpace(body.PodUID)
	body.Runtime = strings.TrimSpace(body.Runtime)
	if body.Node == "" {
		jsonError(w, http.StatusBadRequest, "node is required")
		return
	}
	if body.WorkloadID == "" {
		jsonError(w, http.StatusBadRequest, "workload_id is required")
		return
	}
	if len(body.Containers) == 0 {
		jsonError(w, http.StatusBadRequest, "containers are required")
		return
	}
	if body.ObservedAt.IsZero() {
		body.ObservedAt = time.Now().UTC()
	}

	clusterID, err := h.resolveWorkloadCluster(r, tok.OrgID, body.ClusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "resolve cluster: "+err.Error())
		return
	}
	if body.ClusterID != nil && clusterID == nil {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return
	}

	evidencePayload := handler.ScanEvidencePackagePayload{
		Packages:   scannerPackagesFromWorkloadPackages(body),
		Node:       body.Node,
		WorkloadID: body.WorkloadID,
		Namespace:  body.Namespace,
		PodName:    body.PodName,
		PodUID:     body.PodUID,
		Runtime:    body.Runtime,
		Containers: scanEvidenceContainersFromWorkload(body),
	}
	evidencePayload.Distro, evidencePayload.DistroVersion, evidencePayload.Source = firstWorkloadDistroSource(body)
	if len(evidencePayload.Packages) == 0 {
		jsonError(w, http.StatusBadRequest, "no packages in workload evidence")
		return
	}
	inventoryHash, err := handler.PackageEvidenceHash(evidencePayload)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "evidence hash: "+err.Error())
		return
	}
	metadata, _ := json.Marshal(map[string]any{
		"node":            body.Node,
		"workload_id":     body.WorkloadID,
		"namespace":       body.Namespace,
		"pod_name":        body.PodName,
		"pod_uid":         body.PodUID,
		"runtime":         body.Runtime,
		"container_count": len(body.Containers),
		"package_count":   len(evidencePayload.Packages),
	})

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	target, err := handler.UpsertScanTarget(r.Context(), nil, tx, tok.OrgID, handler.ScanTargetUpsert{
		TargetType:      "workload",
		TargetRef:       body.WorkloadID,
		TargetClusterID: clusterID,
		SourceType:      "runtime-agent",
		SourceRef:       body.WorkloadID,
		ImageRef:        firstWorkloadImageRef(body),
		ImageDigest:     firstWorkloadImageDigest(body),
		InventoryHash:   inventoryHash,
		Metadata:        metadata,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan target: "+err.Error())
		return
	}
	evidenceID, err := handler.UpsertPackageScanEvidence(r.Context(), tx, tok.OrgID, target, inventoryHash, evidencePayload, body.ObservedAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan evidence: "+err.Error())
		return
	}

	var exists bool
	if err := tx.QueryRow(r.Context(), `
SELECT EXISTS(
    SELECT 1
      FROM scan_jobs
     WHERE org_id = $1
       AND target_id = $2
       AND status IN ('pending', 'running', 'paused')
)`, tok.OrgID, target.ID).Scan(&exists); err != nil {
		jsonError(w, http.StatusInternalServerError, "scan job check: "+err.Error())
		return
	}
	var jobID *uuid.UUID
	if !exists {
		id := uuid.New()
		if _, err := tx.Exec(r.Context(), `
INSERT INTO scan_jobs (id, org_id, target_id, status)
VALUES ($1, $2, $3, 'pending')`, id, tok.OrgID, target.ID); err != nil {
			jsonError(w, http.StatusInternalServerError, "enqueue scan job: "+err.Error())
			return
		}
		jobID = &id
	}
	imageReports, err := upsertRuntimeImagePackageEvidence(r.Context(), tx, tok.OrgID, clusterID, body)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "image scan evidence: "+err.Error())
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"scan_target_id":     target.ID,
		"scan_evidence_id":   evidenceID,
		"inventory_hash":     inventoryHash,
		"package_count":      len(evidencePayload.Packages),
		"scan_job_enqueued":  jobID != nil,
		"scan_job_id":        jobID,
		"scanner_source":     "scan_evidence",
		"scanner_target_ref": target.Ref,
		"image_scan_targets": imageReports,
	})
}

func (h *WorkloadPackagesHandler) resolveWorkloadCluster(r *http.Request, orgID uuid.UUID, requested *uuid.UUID) (*uuid.UUID, error) {
	if requested != nil {
		var exists bool
		if err := h.db.Pool().QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM clusters WHERE id = $1 AND org_id = $2)`,
			*requested, orgID).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, nil
		}
		id := *requested
		return &id, nil
	}
	var cid uuid.UUID
	err := h.db.Pool().QueryRow(r.Context(),
		`SELECT id FROM clusters WHERE org_id = $1 ORDER BY created_at LIMIT 1`,
		orgID).Scan(&cid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cid, nil
}

type runtimeImageEvidenceReport struct {
	ScanTargetID   uuid.UUID `json:"scan_target_id"`
	ScanEvidenceID uuid.UUID `json:"scan_evidence_id"`
	ScanJobID      uuid.UUID `json:"scan_job_id,omitempty"`
	ImageRef       string    `json:"image_ref"`
	ImageDigest    string    `json:"image_digest,omitempty"`
	InventoryHash  string    `json:"inventory_hash"`
	PackageCount   int       `json:"package_count"`
}

func upsertRuntimeImagePackageEvidence(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, clusterID *uuid.UUID, body WorkloadPackagesPayload) ([]runtimeImageEvidenceReport, error) {
	out := []runtimeImageEvidenceReport{}
	for _, container := range body.Containers {
		imageRef := workloadContainerImageRef(container)
		if imageRef == "" {
			continue
		}
		packages := scannerPackagesFromWorkloadContainer(container)
		if len(packages) == 0 {
			continue
		}
		evidencePayload := handler.ScanEvidencePackagePayload{
			Packages:      packages,
			Distro:        strings.TrimSpace(container.Distro),
			DistroVersion: strings.TrimSpace(container.DistroVersion),
			Source:        strings.TrimSpace(container.Source),
			Node:          body.Node,
			WorkloadID:    body.WorkloadID,
			Namespace:     body.Namespace,
			PodName:       body.PodName,
			PodUID:        body.PodUID,
			Runtime:       body.Runtime,
			Containers:    []handler.ScanEvidenceContainer{scanEvidenceContainerFromWorkload(container)},
		}
		inventoryHash, err := handler.PackageEvidenceHash(evidencePayload)
		if err != nil {
			return nil, err
		}
		metadata, _ := json.Marshal(map[string]any{
			"node":           body.Node,
			"workload_id":    body.WorkloadID,
			"namespace":      body.Namespace,
			"pod_name":       body.PodName,
			"pod_uid":        body.PodUID,
			"runtime":        body.Runtime,
			"container_id":   strings.TrimSpace(container.ContainerID),
			"container_name": strings.TrimSpace(container.ContainerName),
			"image":          strings.TrimSpace(container.Image),
			"image_ref":      imageRef,
			"package_count":  len(packages),
		})
		target, err := handler.UpsertScanTarget(ctx, nil, tx, orgID, handler.ScanTargetUpsert{
			TargetType:      "image",
			TargetRef:       imageRef,
			TargetClusterID: clusterID,
			SourceType:      "runtime-agent",
			SourceRef:       body.Node,
			ImageRef:        imageRef,
			ImageDigest:     imageDigestFromRef(imageRef),
			InventoryHash:   inventoryHash,
			Metadata:        metadata,
		})
		if err != nil {
			return nil, err
		}
		evidenceID, err := handler.UpsertPackageScanEvidence(ctx, tx, orgID, target, inventoryHash, evidencePayload, body.ObservedAt)
		if err != nil {
			return nil, err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `
SELECT EXISTS(
    SELECT 1
      FROM scan_jobs
     WHERE org_id = $1
       AND target_id = $2
       AND status IN ('pending', 'running', 'paused')
)`, orgID, target.ID).Scan(&exists); err != nil {
			return nil, err
		}
		var jobID uuid.UUID
		if !exists {
			jobID = uuid.New()
			if _, err := tx.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status)
VALUES ($1, $2, $3, 'pending')`, jobID, orgID, target.ID); err != nil {
				return nil, err
			}
		}
		out = append(out, runtimeImageEvidenceReport{
			ScanTargetID:   target.ID,
			ScanEvidenceID: evidenceID,
			ScanJobID:      jobID,
			ImageRef:       imageRef,
			ImageDigest:    target.ImageDigest,
			InventoryHash:  inventoryHash,
			PackageCount:   len(packages),
		})
	}
	return out, nil
}

func scannerPackagesFromWorkloadPackages(body WorkloadPackagesPayload) []scanner.Package {
	out := []scanner.Package{}
	for _, container := range body.Containers {
		out = append(out, scannerPackagesFromWorkloadContainer(container)...)
	}
	return out
}

func scannerPackagesFromWorkloadContainer(container WorkloadPackageContainer) []scanner.Package {
	namespace := handler.HostPackageNamespace(container.Distro)
	if namespace == "" {
		namespace = strings.ToLower(strings.TrimSpace(container.Distro))
	}
	source := handler.HostPackageEcosystem(container.Source)
	baseImage := workloadContainerImageRef(container)
	out := []scanner.Package{}
	for _, item := range container.Items {
		name := strings.TrimSpace(item.Name)
		version := strings.TrimSpace(item.Version)
		if name == "" || version == "" {
			continue
		}
		itemSource := strings.TrimSpace(item.Source)
		if itemSource == "" {
			itemSource = source
		} else {
			itemSource = handler.HostPackageEcosystem(itemSource)
		}
		out = append(out, scanner.Package{
			Ecosystem:        itemSource,
			Name:             name,
			Version:          version,
			Arch:             strings.TrimSpace(item.Arch),
			NamespaceKind:    "os",
			NamespaceName:    namespace,
			NamespaceVersion: strings.TrimSpace(container.DistroVersion),
			BaseImage:        baseImage,
		})
	}
	return out
}

func scanEvidenceContainersFromWorkload(body WorkloadPackagesPayload) []handler.ScanEvidenceContainer {
	out := make([]handler.ScanEvidenceContainer, 0, len(body.Containers))
	for _, container := range body.Containers {
		out = append(out, scanEvidenceContainerFromWorkload(container))
	}
	return out
}

func scanEvidenceContainerFromWorkload(container WorkloadPackageContainer) handler.ScanEvidenceContainer {
	return handler.ScanEvidenceContainer{
		ContainerID:   strings.TrimSpace(container.ContainerID),
		ContainerName: strings.TrimSpace(container.ContainerName),
		Image:         strings.TrimSpace(container.Image),
		ImageRef:      strings.TrimSpace(container.ImageRef),
		Distro:        strings.TrimSpace(container.Distro),
		DistroVersion: strings.TrimSpace(container.DistroVersion),
		Source:        strings.TrimSpace(container.Source),
		PackageCount:  len(container.Items),
	}
}

func firstWorkloadDistroSource(body WorkloadPackagesPayload) (distro, version, source string) {
	for _, container := range body.Containers {
		if distro == "" {
			distro = strings.TrimSpace(container.Distro)
		}
		if version == "" {
			version = strings.TrimSpace(container.DistroVersion)
		}
		if source == "" {
			source = strings.TrimSpace(container.Source)
		}
	}
	return distro, version, source
}

func firstWorkloadImageRef(body WorkloadPackagesPayload) string {
	for _, container := range body.Containers {
		if ref := workloadContainerImageRef(container); ref != "" {
			return ref
		}
	}
	return ""
}

func firstWorkloadImageDigest(body WorkloadPackagesPayload) string {
	return imageDigestFromRef(firstWorkloadImageRef(body))
}

func workloadContainerImageRef(container WorkloadPackageContainer) string {
	if ref := strings.TrimSpace(container.ImageRef); ref != "" {
		return ref
	}
	return strings.TrimSpace(container.Image)
}

func imageDigestFromRef(ref string) string {
	if idx := strings.LastIndex(ref, "@"); idx >= 0 {
		digest := strings.TrimSpace(ref[idx+1:])
		if strings.HasPrefix(digest, "sha256:") {
			return digest
		}
	}
	if strings.HasPrefix(ref, "sha256:") {
		return strings.TrimSpace(ref)
	}
	return ""
}
