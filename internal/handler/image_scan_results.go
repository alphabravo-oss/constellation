package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

type ImageScanResults struct {
	db *db.DB
}

func NewImageScanResults(database *db.DB) *ImageScanResults {
	return &ImageScanResults{db: database}
}

type imageScanResultDTO struct {
	ID                  uuid.UUID               `json:"id"`
	AssetID             *uuid.UUID              `json:"asset_id,omitempty"`
	ScanTargetID        *uuid.UUID              `json:"scan_target_id,omitempty"`
	LastScanJobID       *uuid.UUID              `json:"last_scan_job_id,omitempty"`
	SourceType          string                  `json:"source_type,omitempty"`
	SourceRef           string                  `json:"source_ref,omitempty"`
	ScanTargetMetadata  json.RawMessage         `json:"scan_target_metadata,omitempty"`
	ImageRef            string                  `json:"image_ref"`
	ImageRefNormalized  string                  `json:"image_ref_normalized"`
	ImageRepository     string                  `json:"image_repository"`
	ImageTag            string                  `json:"image_tag,omitempty"`
	ImageDigest         string                  `json:"image_digest"`
	Platform            string                  `json:"platform,omitempty"`
	ScannerProfile      string                  `json:"scanner_profile"`
	VulnDBBundleVersion string                  `json:"vulndb_bundle_version,omitempty"`
	VulnDBBundleHash    string                  `json:"vulndb_bundle_hash,omitempty"`
	PackageCount        int                     `json:"package_count"`
	LayerCount          int                     `json:"layer_count"`
	SecretCount         int                     `json:"secret_count"`
	FileRiskCount       int                     `json:"file_risk_count"`
	ImageSigned         bool                    `json:"image_signed"`
	SignatureStatus     string                  `json:"signature_status,omitempty"`
	FindingCount        int                     `json:"finding_count"`
	SeverityCounts      map[string]int          `json:"severity_counts"`
	MaxRiskScore        int                     `json:"max_risk_score"`
	CriticalCount       int                     `json:"critical_count"`
	HighCount           int                     `json:"high_count"`
	MediumCount         int                     `json:"medium_count"`
	LowCount            int                     `json:"low_count"`
	InfoCount           int                     `json:"info_count"`
	ImpactedCount       int                     `json:"impacted_count"`
	BundleMetadata      *scanner.BundleMetadata `json:"bundle_metadata,omitempty"`
	FirstSeenAt         time.Time               `json:"first_seen_at"`
	LastScannedAt       time.Time               `json:"last_scanned_at"`
	UpdatedAt           time.Time               `json:"updated_at"`
}

type imageScanFindingDTO struct {
	ID                  uuid.UUID                      `json:"id"`
	ImageScanResultID   uuid.UUID                      `json:"image_scan_result_id"`
	FindingKey          string                         `json:"finding_key"`
	ExternalID          string                         `json:"external_id,omitempty"`
	Title               string                         `json:"title"`
	Description         string                         `json:"description,omitempty"`
	Severity            string                         `json:"severity"`
	RiskScore           int                            `json:"risk_score"`
	CanonicalEngine     string                         `json:"canonical_engine,omitempty"`
	Engines             []scanner.EngineProvenance     `json:"engines,omitempty"`
	PackageEcosystem    string                         `json:"package_ecosystem,omitempty"`
	PackageName         string                         `json:"package_name,omitempty"`
	PackageVersion      string                         `json:"package_version,omitempty"`
	PackagePURL         string                         `json:"package_purl,omitempty"`
	FixedVersion        string                         `json:"fixed_version,omitempty"`
	AffectedRange       *scanner.AffectedRange         `json:"affected_range,omitempty"`
	CVSSBase            float64                        `json:"cvss_base,omitempty"`
	CVSSVector          string                         `json:"cvss_vector,omitempty"`
	EPSSProbability     float64                        `json:"epss_probability,omitempty"`
	KEVListed           bool                           `json:"kev_listed,omitempty"`
	Aliases             []string                       `json:"aliases,omitempty"`
	References          []string                       `json:"references,omitempty"`
	Reconciliation      []scanner.ReconciliationSignal `json:"reconciliation,omitempty"`
	ReconciliationCount int                            `json:"reconciliation_count,omitempty"`
	Detail              json.RawMessage                `json:"detail,omitempty"`
	FirstSeenAt         time.Time                      `json:"first_seen_at"`
	LastSeenAt          time.Time                      `json:"last_seen_at"`
}

type imageScanArtifact struct {
	Payload      []byte
	SHA256       string
	PackageCount int
	CreatedAt    time.Time
}

type imagePackageLayerDTO struct {
	LayerIndex   *int              `json:"layer_index,omitempty"`
	LayerDigest  string            `json:"layer_digest,omitempty"`
	LayerMedia   string            `json:"layer_media_type,omitempty"`
	LayerSize    int64             `json:"layer_size_bytes,omitempty"`
	PackageCount int               `json:"package_count"`
	Packages     []scanner.Package `json:"packages"`
}

func (h *ImageScanResults) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	digest := r.URL.Query().Get("image_digest")
	if digest == "" {
		digest = r.URL.Query().Get("digest")
	}
	q := r.URL.Query().Get("q")
	clusterID, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	rows, err := h.db.Pool().Query(r.Context(), `
WITH finding_rollup AS (
    SELECT image_scan_result_id,
           COUNT(*)::int AS finding_count,
           COUNT(*) FILTER (WHERE severity = 'critical')::int AS critical_count,
           COUNT(*) FILTER (WHERE severity = 'high')::int AS high_count,
           COUNT(*) FILTER (WHERE severity = 'medium')::int AS medium_count,
           COUNT(*) FILTER (WHERE severity = 'low')::int AS low_count,
           COUNT(*) FILTER (WHERE severity NOT IN ('critical','high','medium','low'))::int AS info_count,
           COALESCE(MAX(risk_score), 0)::int AS max_risk_score
     FROM image_scan_findings
     WHERE org_id = $1
     GROUP BY image_scan_result_id
),
artifact_rollup AS (
    SELECT image_scan_result_id,
           COALESCE(MAX(package_count) FILTER (
               WHERE artifact_type = 'layer-metadata'
                 AND format = 'constellation-image-layers-v1'
           ), 0)::int AS layer_count,
	           COALESCE(MAX(package_count) FILTER (
	               WHERE artifact_type = 'secret-scan'
	                 AND format = 'constellation-image-secrets-v1'
	           ), 0)::int AS secret_count,
	           COALESCE(MAX(package_count) FILTER (
	               WHERE artifact_type = 'file-risk'
	                 AND format = 'constellation-image-file-risk-v1'
	           ), 0)::int AS file_risk_count,
	           COALESCE(BOOL_OR(LOWER(COALESCE(payload->>'signed', 'false')) = 'true') FILTER (
               WHERE artifact_type = 'signature-scan'
                 AND format = 'constellation-image-signature-v1'
           ), false) AS image_signed,
           COALESCE(MAX(payload->>'status') FILTER (
               WHERE artifact_type = 'signature-scan'
                 AND format = 'constellation-image-signature-v1'
           ), '') AS signature_status
      FROM image_scan_artifacts
     WHERE org_id = $1
     GROUP BY image_scan_result_id
),
impact_rollup AS (
    SELECT r.id,
           COUNT(DISTINCT l.cluster_id::text || '/' || l.workload_id)::int AS impacted_count
      FROM image_scan_results r
      JOIN image_workload_links l
        ON l.org_id = r.org_id
       AND ($2::uuid IS NULL OR l.cluster_id = $2)
       AND (
            (l.image_digest IS NOT NULL AND l.image_digest = r.image_digest)
         OR (l.image_ref <> '' AND l.image_ref = r.image_ref)
         OR (l.image_ref_normalized <> '' AND l.image_ref_normalized = r.image_ref_normalized)
         OR (l.image_repository IS NOT NULL AND l.image_repository = r.image_repository
             AND (l.image_tag IS NULL OR l.image_tag = r.image_tag))
       )
     WHERE r.org_id = $1
     GROUP BY r.id
)
SELECT r.id, r.asset_id, r.scan_target_id, r.last_scan_job_id,
       COALESCE(NULLIF(r.source_type, ''), st.source_type, ''), COALESCE(NULLIF(r.source_ref, ''), st.source_ref, ''), COALESCE(st.metadata, '{}'::jsonb),
       r.image_ref, r.image_ref_normalized, r.image_repository, COALESCE(r.image_tag, ''),
       r.image_digest, r.platform, r.scanner_profile, r.vulndb_bundle_version, r.vulndb_bundle_hash,
	       r.package_count, COALESCE(ar.layer_count, 0), COALESCE(ar.secret_count, 0), COALESCE(ar.file_risk_count, 0), COALESCE(ar.image_signed, false), COALESCE(ar.signature_status, ''),
       COALESCE(fr.finding_count, r.finding_count), COALESCE(fr.critical_count, 0),
       COALESCE(fr.high_count, 0), COALESCE(fr.medium_count, 0), COALESCE(fr.low_count, 0),
       COALESCE(fr.info_count, 0), COALESCE(fr.max_risk_score, 0), COALESCE(ir.impacted_count, 0), r.bundle_metadata,
       r.first_seen_at, r.last_scanned_at, r.updated_at
  FROM image_scan_results r
  LEFT JOIN scan_targets st ON st.id = r.scan_target_id
  LEFT JOIN finding_rollup fr ON fr.image_scan_result_id = r.id
  LEFT JOIN artifact_rollup ar ON ar.image_scan_result_id = r.id
  LEFT JOIN impact_rollup ir ON ir.id = r.id
 WHERE r.org_id = $1
   AND ($2::uuid IS NULL OR COALESCE(ir.impacted_count, 0) > 0)
   AND ($3 = '' OR r.image_digest = $3)
   AND ($4 = '' OR r.image_ref ILIKE '%' || $4 || '%' OR r.image_repository ILIKE '%' || $4 || '%' OR r.image_digest ILIKE '%' || $4 || '%' OR COALESCE(NULLIF(r.source_ref, ''), st.source_ref, '') ILIKE '%' || $4 || '%')
 ORDER BY r.last_scanned_at DESC
 LIMIT $5 OFFSET $6`, subj.OrgID, clusterID, digest, q, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	out := []imageScanResultDTO{}
	for rows.Next() {
		item, err := scanImageResultRow(rows)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"image_scan_results": out, "limit": limit, "offset": offset})
}

func (h *ImageScanResults) Packages(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	artifact, err := h.getArtifact(r, subj.OrgID, id, "package-inventory", "constellation-package-inventory-v1")
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "package inventory not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var inventory struct {
		Packages []scanner.Package `json:"packages"`
	}
	if err := json.Unmarshal(artifact.Payload, &inventory); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "package inventory decode: " + err.Error()})
		return
	}
	layers := []scanner.ImageLayer{}
	if layerArtifact, err := h.getArtifact(r, subj.OrgID, id, "layer-metadata", "constellation-image-layers-v1"); err == nil {
		var layerPayload struct {
			Layers []scanner.ImageLayer `json:"layers"`
		}
		if err := json.Unmarshal(layerArtifact.Payload, &layerPayload); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "layer metadata decode: " + err.Error()})
			return
		}
		layers = layerPayload.Layers
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	packageLayers, layerPackageCount, unattributedPackageCount := packageLayerSummary(inventory.Packages, layers)
	writeJSON(w, http.StatusOK, map[string]any{
		"image_scan_result_id":       id,
		"format":                     "constellation-package-inventory-v1",
		"sha256":                     artifact.SHA256,
		"package_count":              artifact.PackageCount,
		"created_at":                 artifact.CreatedAt,
		"package_inventory":          json.RawMessage(artifact.Payload),
		"package_layers":             packageLayers,
		"layer_package_count":        layerPackageCount,
		"unattributed_package_count": unattributedPackageCount,
	})
}

func (h *ImageScanResults) Secrets(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	artifact, err := h.getArtifact(r, subj.OrgID, id, "secret-scan", "constellation-image-secrets-v1")
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "secret report not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"image_scan_result_id": id,
		"format":               "constellation-image-secrets-v1",
		"sha256":               artifact.SHA256,
		"secret_count":         artifact.PackageCount,
		"created_at":           artifact.CreatedAt,
		"secret_scan":          json.RawMessage(artifact.Payload),
	})
}

func (h *ImageScanResults) Layers(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	artifact, err := h.getArtifact(r, subj.OrgID, id, "layer-metadata", "constellation-image-layers-v1")
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "layer metadata not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"image_scan_result_id": id,
		"format":               "constellation-image-layers-v1",
		"sha256":               artifact.SHA256,
		"layer_count":          artifact.PackageCount,
		"created_at":           artifact.CreatedAt,
		"layer_metadata":       json.RawMessage(artifact.Payload),
	})
}

func (h *ImageScanResults) FileRisks(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	artifact, err := h.getArtifact(r, subj.OrgID, id, "file-risk", "constellation-image-file-risk-v1")
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "file risk report not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"image_scan_result_id": id,
		"format":               "constellation-image-file-risk-v1",
		"sha256":               artifact.SHA256,
		"file_risk_count":      artifact.PackageCount,
		"created_at":           artifact.CreatedAt,
		"file_risk":            json.RawMessage(artifact.Payload),
	})
}

func (h *ImageScanResults) Signature(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	artifact, err := h.getArtifact(r, subj.OrgID, id, "signature-scan", "constellation-image-signature-v1")
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "signature report not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"image_scan_result_id": id,
		"format":               "constellation-image-signature-v1",
		"sha256":               artifact.SHA256,
		"created_at":           artifact.CreatedAt,
		"signature_scan":       json.RawMessage(artifact.Payload),
	})
}

func (h *ImageScanResults) SPDX(w http.ResponseWriter, r *http.Request) {
	h.writeSBOMArtifact(w, r, "spdx-2.3", "image-scan-spdx-2.3.json")
}

func (h *ImageScanResults) CycloneDX(w http.ResponseWriter, r *http.Request) {
	h.writeSBOMArtifact(w, r, "cyclonedx-1.6", "image-scan-cyclonedx-1.6.json")
}

func (h *ImageScanResults) Get(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	result, err := h.getResult(r, subj.OrgID, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	findings, err := h.getFindings(r, subj.OrgID, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	impacts, err := h.getImpactedWorkloads(r, subj.OrgID, result)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	result.ImpactedCount = len(impacts)
	writeJSON(w, http.StatusOK, map[string]any{
		"image_scan_result":  result,
		"findings":           findings,
		"impacted_workloads": impacts,
	})
}

func (h *ImageScanResults) writeSBOMArtifact(w http.ResponseWriter, r *http.Request, format, filename string) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	artifact, err := h.getArtifact(r, subj.OrgID, id, "sbom", format)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "sbom not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteRawSBOM(w, artifact.Payload, filename)
}

func (h *ImageScanResults) getArtifact(r *http.Request, orgID, resultID uuid.UUID, artifactType, format string) (imageScanArtifact, error) {
	var artifact imageScanArtifact
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT a.payload, a.sha256, a.package_count, a.created_at
  FROM image_scan_results r
  JOIN image_scan_artifacts a
    ON a.org_id = r.org_id
   AND a.image_scan_result_id = r.id
 WHERE r.org_id = $1
   AND r.id = $2
   AND a.artifact_type = $3
   AND a.format = $4`, orgID, resultID, artifactType, format).
		Scan(&artifact.Payload, &artifact.SHA256, &artifact.PackageCount, &artifact.CreatedAt)
	return artifact, err
}

func packageLayerSummary(packages []scanner.Package, layers []scanner.ImageLayer) ([]imagePackageLayerDTO, int, int) {
	type layerState struct {
		item imagePackageLayerDTO
		seen map[string]struct{}
	}
	layerOrder := make([]string, 0, len(layers))
	layerByDigest := map[string]*layerState{}
	for idx, layer := range layers {
		digest := strings.TrimSpace(layer.Digest)
		if digest == "" {
			continue
		}
		index := idx
		layerByDigest[digest] = &layerState{
			item: imagePackageLayerDTO{
				LayerIndex:  &index,
				LayerDigest: digest,
				LayerMedia:  strings.TrimSpace(layer.MediaType),
				LayerSize:   layer.SizeBytes,
			},
			seen: map[string]struct{}{},
		}
		layerOrder = append(layerOrder, digest)
	}

	attributedPackages := map[string]struct{}{}
	for _, pkg := range packages {
		pkgKey := packageProvenanceKey(pkg)
		if pkgKey == "" {
			continue
		}
		for _, loc := range pkg.Locations {
			digest := strings.TrimSpace(loc.LayerDigest)
			if digest == "" {
				digest = strings.TrimSpace(loc.LayerID)
			}
			if digest == "" {
				continue
			}
			state := layerByDigest[digest]
			if state == nil {
				state = &layerState{
					item: imagePackageLayerDTO{LayerDigest: digest},
					seen: map[string]struct{}{},
				}
				layerByDigest[digest] = state
				layerOrder = append(layerOrder, digest)
			}
			if _, ok := state.seen[pkgKey]; ok {
				continue
			}
			state.seen[pkgKey] = struct{}{}
			state.item.Packages = append(state.item.Packages, pkg)
			state.item.PackageCount = len(state.item.Packages)
			attributedPackages[pkgKey] = struct{}{}
		}
	}

	out := make([]imagePackageLayerDTO, 0, len(layerOrder))
	layerPackageCount := 0
	for _, digest := range layerOrder {
		state := layerByDigest[digest]
		if state == nil || state.item.PackageCount == 0 {
			continue
		}
		out = append(out, state.item)
		layerPackageCount += state.item.PackageCount
	}
	unattributedPackageCount := 0
	for _, pkg := range packages {
		key := packageProvenanceKey(pkg)
		if key == "" {
			continue
		}
		if _, ok := attributedPackages[key]; !ok {
			unattributedPackageCount++
		}
	}
	return out, layerPackageCount, unattributedPackageCount
}

func packageProvenanceKey(pkg scanner.Package) string {
	parts := []string{
		strings.TrimSpace(pkg.Ecosystem),
		strings.TrimSpace(pkg.Name),
		strings.TrimSpace(pkg.Version),
		strings.TrimSpace(pkg.Purl),
		strings.TrimSpace(pkg.NamespaceKind),
		strings.TrimSpace(pkg.NamespaceName),
		strings.TrimSpace(pkg.NamespaceVersion),
	}
	for _, part := range parts {
		if part != "" {
			return strings.Join(parts, "\x00")
		}
	}
	return ""
}

func (h *ImageScanResults) AffectedWorkloads(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	result, err := h.getResult(r, subj.OrgID, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	impacts, err := h.getImpactedWorkloads(r, subj.OrgID, result)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"image_scan_result_id": id,
		"image_ref":            result.ImageRef,
		"image_ref_normalized": result.ImageRefNormalized,
		"image_repository":     result.ImageRepository,
		"image_tag":            result.ImageTag,
		"image_digest":         result.ImageDigest,
		"affected_count":       len(impacts),
		"affected_workloads":   impacts,
	})
}

type imageScanResultRowScanner interface {
	Scan(dest ...any) error
}

func scanImageResultRow(row imageScanResultRowScanner) (imageScanResultDTO, error) {
	var item imageScanResultDTO
	var bundleRaw, metadataRaw []byte
	if err := row.Scan(
		&item.ID, &item.AssetID, &item.ScanTargetID, &item.LastScanJobID,
		&item.SourceType, &item.SourceRef, &metadataRaw,
		&item.ImageRef, &item.ImageRefNormalized, &item.ImageRepository, &item.ImageTag,
		&item.ImageDigest, &item.Platform, &item.ScannerProfile, &item.VulnDBBundleVersion, &item.VulnDBBundleHash,
		&item.PackageCount, &item.LayerCount, &item.SecretCount, &item.FileRiskCount, &item.ImageSigned, &item.SignatureStatus, &item.FindingCount, &item.CriticalCount,
		&item.HighCount, &item.MediumCount, &item.LowCount,
		&item.InfoCount, &item.MaxRiskScore, &item.ImpactedCount, &bundleRaw,
		&item.FirstSeenAt, &item.LastScannedAt, &item.UpdatedAt,
	); err != nil {
		return imageScanResultDTO{}, err
	}
	item.ScanTargetMetadata = normalizedJSONRaw(metadataRaw)
	item.SeverityCounts = map[string]int{
		"critical": item.CriticalCount,
		"high":     item.HighCount,
		"medium":   item.MediumCount,
		"low":      item.LowCount,
		"info":     item.InfoCount,
	}
	if len(bundleRaw) > 0 && string(bundleRaw) != "{}" && string(bundleRaw) != "null" {
		var metadata scanner.BundleMetadata
		if err := json.Unmarshal(bundleRaw, &metadata); err == nil {
			item.BundleMetadata = &metadata
		}
	}
	return item, nil
}

func (h *ImageScanResults) getResult(r *http.Request, orgID uuid.UUID, id uuid.UUID) (imageScanResultDTO, error) {
	return scanImageResultRow(h.db.Pool().QueryRow(r.Context(), `
WITH finding_rollup AS (
    SELECT image_scan_result_id,
           COUNT(*)::int AS finding_count,
           COUNT(*) FILTER (WHERE severity = 'critical')::int AS critical_count,
           COUNT(*) FILTER (WHERE severity = 'high')::int AS high_count,
           COUNT(*) FILTER (WHERE severity = 'medium')::int AS medium_count,
           COUNT(*) FILTER (WHERE severity = 'low')::int AS low_count,
           COUNT(*) FILTER (WHERE severity NOT IN ('critical','high','medium','low'))::int AS info_count,
           COALESCE(MAX(risk_score), 0)::int AS max_risk_score
     FROM image_scan_findings
     WHERE org_id = $1 AND image_scan_result_id = $2
     GROUP BY image_scan_result_id
),
artifact_rollup AS (
    SELECT image_scan_result_id,
           COALESCE(MAX(package_count) FILTER (
               WHERE artifact_type = 'layer-metadata'
                 AND format = 'constellation-image-layers-v1'
           ), 0)::int AS layer_count,
	           COALESCE(MAX(package_count) FILTER (
	               WHERE artifact_type = 'secret-scan'
	                 AND format = 'constellation-image-secrets-v1'
	           ), 0)::int AS secret_count,
	           COALESCE(MAX(package_count) FILTER (
	               WHERE artifact_type = 'file-risk'
	                 AND format = 'constellation-image-file-risk-v1'
	           ), 0)::int AS file_risk_count,
	           COALESCE(BOOL_OR(LOWER(COALESCE(payload->>'signed', 'false')) = 'true') FILTER (
               WHERE artifact_type = 'signature-scan'
                 AND format = 'constellation-image-signature-v1'
           ), false) AS image_signed,
           COALESCE(MAX(payload->>'status') FILTER (
               WHERE artifact_type = 'signature-scan'
                 AND format = 'constellation-image-signature-v1'
           ), '') AS signature_status
      FROM image_scan_artifacts
     WHERE org_id = $1 AND image_scan_result_id = $2
     GROUP BY image_scan_result_id
)
SELECT r.id, r.asset_id, r.scan_target_id, r.last_scan_job_id,
       COALESCE(NULLIF(r.source_type, ''), st.source_type, ''), COALESCE(NULLIF(r.source_ref, ''), st.source_ref, ''), COALESCE(st.metadata, '{}'::jsonb),
       r.image_ref, r.image_ref_normalized, r.image_repository, COALESCE(r.image_tag, ''),
       r.image_digest, r.platform, r.scanner_profile, r.vulndb_bundle_version, r.vulndb_bundle_hash,
	       r.package_count, COALESCE(ar.layer_count, 0), COALESCE(ar.secret_count, 0), COALESCE(ar.file_risk_count, 0), COALESCE(ar.image_signed, false), COALESCE(ar.signature_status, ''),
       COALESCE(fr.finding_count, r.finding_count), COALESCE(fr.critical_count, 0),
       COALESCE(fr.high_count, 0), COALESCE(fr.medium_count, 0), COALESCE(fr.low_count, 0),
       COALESCE(fr.info_count, 0), COALESCE(fr.max_risk_score, 0), 0, r.bundle_metadata,
       r.first_seen_at, r.last_scanned_at, r.updated_at
  FROM image_scan_results r
  LEFT JOIN scan_targets st ON st.id = r.scan_target_id
  LEFT JOIN finding_rollup fr ON fr.image_scan_result_id = r.id
  LEFT JOIN artifact_rollup ar ON ar.image_scan_result_id = r.id
 WHERE r.org_id = $1 AND r.id = $2`, orgID, id))
}

func (h *ImageScanResults) getFindings(r *http.Request, orgID uuid.UUID, resultID uuid.UUID) ([]imageScanFindingDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, image_scan_result_id, finding_key, COALESCE(external_id, ''), title,
       COALESCE(description, ''), severity, risk_score, COALESCE(canonical_engine, ''),
       engines, COALESCE(package_ecosystem, ''), COALESCE(package_name, ''),
       COALESCE(package_version, ''), COALESCE(package_purl, ''), COALESCE(fixed_version, ''),
       detail_json, first_seen_at, last_seen_at
  FROM image_scan_findings
 WHERE org_id = $1 AND image_scan_result_id = $2
 ORDER BY CASE severity
            WHEN 'critical' THEN 4
            WHEN 'high' THEN 3
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 1
            ELSE 0
          END DESC,
          risk_score DESC,
          COALESCE(external_id, ''),
          package_name`, orgID, resultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []imageScanFindingDTO{}
	for rows.Next() {
		var item imageScanFindingDTO
		var enginesRaw, detailRaw []byte
		if err := rows.Scan(
			&item.ID, &item.ImageScanResultID, &item.FindingKey, &item.ExternalID, &item.Title,
			&item.Description, &item.Severity, &item.RiskScore, &item.CanonicalEngine,
			&enginesRaw, &item.PackageEcosystem, &item.PackageName,
			&item.PackageVersion, &item.PackagePURL, &item.FixedVersion,
			&detailRaw, &item.FirstSeenAt, &item.LastSeenAt,
		); err != nil {
			return nil, err
		}
		if len(enginesRaw) > 0 && string(enginesRaw) != "null" {
			_ = json.Unmarshal(enginesRaw, &item.Engines)
		}
		hydrateImageScanFindingDetail(&item, detailRaw)
		out = append(out, item)
	}
	return out, rows.Err()
}

func hydrateImageScanFindingDetail(item *imageScanFindingDTO, detailRaw []byte) {
	if len(detailRaw) == 0 || string(detailRaw) == "null" {
		return
	}
	item.Detail = json.RawMessage(detailRaw)
	var detail struct {
		Package         scanner.Package                `json:"package"`
		FixedVersion    string                         `json:"fixed"`
		AffectedRange   *scanner.AffectedRange         `json:"affected_range"`
		CVSSBase        float64                        `json:"cvss_base"`
		CVSSVector      string                         `json:"cvss_vector"`
		EPSSProbability float64                        `json:"epss"`
		KEVListed       bool                           `json:"kev"`
		Aliases         []string                       `json:"aliases"`
		References      []string                       `json:"references"`
		Reconciliation  []scanner.ReconciliationSignal `json:"reconciliation"`
	}
	if err := json.Unmarshal(detailRaw, &detail); err != nil {
		return
	}
	if item.PackageEcosystem == "" {
		item.PackageEcosystem = detail.Package.Ecosystem
	}
	if item.PackageName == "" {
		item.PackageName = detail.Package.Name
	}
	if item.PackageVersion == "" {
		item.PackageVersion = detail.Package.Version
	}
	if item.PackagePURL == "" {
		item.PackagePURL = detail.Package.Purl
	}
	if item.FixedVersion == "" {
		item.FixedVersion = detail.FixedVersion
	}
	item.AffectedRange = detail.AffectedRange
	item.CVSSBase = detail.CVSSBase
	item.CVSSVector = detail.CVSSVector
	item.EPSSProbability = detail.EPSSProbability
	item.KEVListed = detail.KEVListed
	item.Aliases = detail.Aliases
	item.References = detail.References
	item.Reconciliation = detail.Reconciliation
	item.ReconciliationCount = len(detail.Reconciliation)
}

func (h *ImageScanResults) getImpactedWorkloads(r *http.Request, orgID uuid.UUID, result imageScanResultDTO) ([]ImpactedWorkload, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT l.cluster_id, l.deployment_id, l.workload_id, l.namespace, l.name, l.kind,
       l.image_ref, l.image_ref_normalized, COALESCE(l.image_repository, ''),
       COALESCE(l.image_tag, ''), COALESCE(l.image_digest, ''),
       COALESCE(d.risk_score, 0), COALESCE(d.finding_count, 0),
       COALESCE(d.critical_count, 0), COALESCE(d.high_count, 0),
       l.last_seen_at
  FROM image_workload_links l
  LEFT JOIN deployments d
    ON d.id = l.deployment_id
   AND d.org_id = l.org_id
 WHERE l.org_id = $1
   AND (
        ($2 <> '' AND l.image_digest = $2)
     OR ($3 <> '' AND l.image_ref = $3)
     OR ($4 <> '' AND l.image_ref_normalized = $4)
     OR ($5 <> '' AND l.image_repository = $5 AND ($6 = '' OR l.image_tag = $6))
   )
 ORDER BY l.namespace, l.name, l.image_ref`, orgID, result.ImageDigest, result.ImageRef, result.ImageRefNormalized, result.ImageRepository, result.ImageTag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ImpactedWorkload{}
	for rows.Next() {
		var item ImpactedWorkload
		if err := rows.Scan(&item.ClusterID, &item.DeploymentID, &item.WorkloadID,
			&item.Namespace, &item.Name, &item.Kind, &item.ImageRef, &item.ImageRefNormalized,
			&item.ImageRepository, &item.ImageTag, &item.ImageDigest, &item.RiskScore,
			&item.FindingCount, &item.CriticalCount, &item.HighCount, &item.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
