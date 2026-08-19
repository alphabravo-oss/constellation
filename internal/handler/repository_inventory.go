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
	"github.com/alphabravocompany/constellation/internal/scanner"
)

type RepositoryInventoryHandler struct {
	db *db.DB
}

func NewRepositoryInventory(d *db.DB) *RepositoryInventoryHandler {
	return &RepositoryInventoryHandler{db: d}
}

type repositoryScanDTO struct {
	ID                uuid.UUID                  `json:"id"`
	RepositoryRef     string                     `json:"repository_ref"`
	RepositoryURL     string                     `json:"repository_url,omitempty"`
	SourceType        string                     `json:"source_type"`
	SourceRef         string                     `json:"source_ref,omitempty"`
	CommitSHA         string                     `json:"commit_sha,omitempty"`
	Branch            string                     `json:"branch,omitempty"`
	Path              string                     `json:"path,omitempty"`
	Workflow          string                     `json:"workflow,omitempty"`
	RunID             string                     `json:"run_id,omitempty"`
	InventoryHash     string                     `json:"inventory_hash,omitempty"`
	PackageCount      int                        `json:"package_count"`
	LatestEvidenceID  *uuid.UUID                 `json:"latest_evidence_id,omitempty"`
	LatestObservedAt  *time.Time                 `json:"latest_observed_at,omitempty"`
	LatestJobID       *uuid.UUID                 `json:"latest_job_id,omitempty"`
	LatestJobStatus   string                     `json:"latest_job_status,omitempty"`
	LatestAttestation *scanAttestationSummaryDTO `json:"latest_attestation,omitempty"`
	OpenFindings      int                        `json:"open_findings"`
	CriticalFindings  int                        `json:"critical_findings"`
	HighFindings      int                        `json:"high_findings"`
	LastSeenAt        time.Time                  `json:"last_seen_at"`
	Metadata          json.RawMessage            `json:"metadata,omitempty"`
}

type repositoryScanMetadata struct {
	RepositoryRef string `json:"repository_ref"`
	RepositoryURL string `json:"repository_url"`
	SourceRef     string `json:"source_ref"`
	CommitSHA     string `json:"commit_sha"`
	Branch        string `json:"branch"`
	Path          string `json:"path"`
	Workflow      string `json:"workflow"`
	RunID         string `json:"run_id"`
	PackageCount  int    `json:"package_count"`
}

type repositoryEvidenceDTO struct {
	ID            uuid.UUID         `json:"id"`
	InventoryHash string            `json:"inventory_hash"`
	PackageCount  int               `json:"package_count"`
	ObservedAt    time.Time         `json:"observed_at"`
	RepositoryRef string            `json:"repository_ref,omitempty"`
	RepositoryURL string            `json:"repository_url,omitempty"`
	CommitSHA     string            `json:"commit_sha,omitempty"`
	Branch        string            `json:"branch,omitempty"`
	Path          string            `json:"path,omitempty"`
	Workflow      string            `json:"workflow,omitempty"`
	RunID         string            `json:"run_id,omitempty"`
	Packages      []scanner.Package `json:"packages,omitempty"`
}

type repositoryJobDTO struct {
	ID           uuid.UUID  `json:"id"`
	Status       string     `json:"status"`
	Error        string     `json:"error,omitempty"`
	PackageCount int        `json:"package_count"`
	FindingCount int        `json:"finding_count"`
	RequestedAt  time.Time  `json:"requested_at"`
	ClaimedAt    *time.Time `json:"claimed_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
}

type repositoryFindingDTO struct {
	ID         uuid.UUID       `json:"id"`
	Kind       string          `json:"kind"`
	ExternalID string          `json:"external_id,omitempty"`
	Title      string          `json:"title"`
	Severity   string          `json:"severity"`
	RiskScore  int             `json:"risk_score"`
	Lifecycle  string          `json:"lifecycle"`
	Detail     json.RawMessage `json:"detail,omitempty"`
	FirstSeen  time.Time       `json:"first_seen_at"`
	LastSeen   time.Time       `json:"last_seen_at"`
}

type scanAttestationSummaryDTO struct {
	ID                 uuid.UUID  `json:"id"`
	SubjectKind        string     `json:"subject_kind"`
	SubjectDigest      string     `json:"subject_digest"`
	PredicateType      string     `json:"predicate_type"`
	PayloadSHA256      string     `json:"payload_sha256"`
	VerificationStatus string     `json:"verification_status"`
	Trusted            bool       `json:"trusted"`
	TrustPolicyID      *uuid.UUID `json:"trust_policy_id,omitempty"`
	VerificationReason string     `json:"verification_reason,omitempty"`
	SignerIdentity     string     `json:"signer_identity,omitempty"`
	SignerIssuer       string     `json:"signer_issuer,omitempty"`
	ObservedAt         time.Time  `json:"observed_at"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
}

func (h *RepositoryInventoryHandler) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	branch := strings.TrimSpace(r.URL.Query().Get("branch"))
	workflow := strings.TrimSpace(r.URL.Query().Get("workflow"))

	rows, err := h.db.Pool().Query(r.Context(), `
WITH finding_rollup AS (
    SELECT scan_target_id,
           COUNT(*) FILTER (WHERE lifecycle = 'open')::int AS open_findings,
           COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'critical')::int AS critical_findings,
           COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'high')::int AS high_findings
      FROM findings
     WHERE org_id = $1
       AND target_type = 'repository'
     GROUP BY scan_target_id
)
SELECT st.id, st.ref, st.source_type, COALESCE(st.source_ref, ''),
       COALESCE(st.inventory_hash, ''), st.metadata, st.last_seen_at,
       ev.id, COALESCE(ev.package_count, 0), ev.observed_at,
       sj.id, COALESCE(sj.status, ''),
       att.id, COALESCE(att.subject_kind, ''), COALESCE(att.subject_digest, ''),
       COALESCE(att.predicate_type, ''), COALESCE(att.payload_sha256, ''),
       COALESCE(att.verification_status, ''), COALESCE(att.trusted, false), att.trust_policy_id, COALESCE(att.verification_reason, ''),
       COALESCE(att.signer_identity, ''), COALESCE(att.signer_issuer, ''), att.observed_at, att.expires_at,
       COALESCE(fr.open_findings, 0), COALESCE(fr.critical_findings, 0), COALESCE(fr.high_findings, 0)
  FROM scan_targets st
  LEFT JOIN LATERAL (
      SELECT id, package_count, observed_at
        FROM scan_evidence
       WHERE org_id = st.org_id
         AND scan_target_id = st.id
         AND evidence_type = 'package-inventory'
       ORDER BY observed_at DESC
       LIMIT 1
  ) ev ON true
  LEFT JOIN LATERAL (
      SELECT id, status
        FROM scan_jobs
       WHERE org_id = st.org_id
         AND target_id = st.id
       ORDER BY requested_at DESC
       LIMIT 1
  ) sj ON true
  LEFT JOIN LATERAL (
      SELECT id, subject_kind, subject_digest, predicate_type, payload_sha256,
             verification_status, trusted, trust_policy_id, verification_reason, signer_identity, signer_issuer, observed_at, expires_at
        FROM scan_result_attestations
       WHERE org_id = st.org_id
         AND scan_target_id = st.id
       ORDER BY trusted DESC, observed_at DESC, created_at DESC
       LIMIT 1
  ) att ON true
  LEFT JOIN finding_rollup fr ON fr.scan_target_id = st.id
 WHERE st.org_id = $1
   AND st.type = 'repository'
   AND ($2 = '' OR st.ref ILIKE '%' || $2 || '%'
        OR COALESCE(st.source_ref, '') ILIKE '%' || $2 || '%'
        OR st.metadata->>'repository_ref' ILIKE '%' || $2 || '%'
        OR st.metadata->>'repository_url' ILIKE '%' || $2 || '%'
        OR st.metadata->>'commit_sha' ILIKE '%' || $2 || '%')
   AND ($3 = '' OR st.metadata->>'branch' = $3)
   AND ($4 = '' OR st.metadata->>'workflow' = $4)
 ORDER BY st.last_seen_at DESC
 LIMIT $5 OFFSET $6`, subj.OrgID, q, branch, workflow, limit, offset)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	out := make([]repositoryScanDTO, 0)
	for rows.Next() {
		item, err := scanRepositoryRow(rows)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repository_scans": out,
		"limit":            limit,
		"offset":           offset,
	})
}

func (h *RepositoryInventoryHandler) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid repository scan id")
		return
	}
	scan, err := h.getScan(r, subj.OrgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "repository scan not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	evidence, err := h.latestEvidence(r, subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "evidence: "+err.Error())
		return
	}
	jobs, err := h.recentJobs(r, subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "jobs: "+err.Error())
		return
	}
	findings, err := h.findings(r, subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "findings: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repository_scan": scan,
		"latest_evidence": evidence,
		"jobs":            jobs,
		"findings":        findings,
	})
}

type repositoryRowScanner interface {
	Scan(dest ...any) error
}

func scanRepositoryRow(row repositoryRowScanner) (repositoryScanDTO, error) {
	var item repositoryScanDTO
	var metadataRaw []byte
	var evidenceID *uuid.UUID
	var evidencePackageCount *int
	var evidenceObservedAt *time.Time
	var jobID *uuid.UUID
	var attestationID *uuid.UUID
	var attestationSubjectKind, attestationSubjectDigest, attestationPredicateType string
	var attestationPayloadSHA, attestationStatus string
	var attestationTrusted bool
	var attestationTrustPolicyID *uuid.UUID
	var attestationReason string
	var attestationSignerIdentity, attestationSignerIssuer string
	var attestationObservedAt, attestationExpiresAt *time.Time
	if err := row.Scan(&item.ID, &item.RepositoryRef, &item.SourceType, &item.SourceRef,
		&item.InventoryHash, &metadataRaw, &item.LastSeenAt,
		&evidenceID, &evidencePackageCount, &evidenceObservedAt,
		&jobID, &item.LatestJobStatus,
		&attestationID, &attestationSubjectKind, &attestationSubjectDigest,
		&attestationPredicateType, &attestationPayloadSHA,
		&attestationStatus, &attestationTrusted, &attestationTrustPolicyID, &attestationReason,
		&attestationSignerIdentity, &attestationSignerIssuer, &attestationObservedAt, &attestationExpiresAt,
		&item.OpenFindings, &item.CriticalFindings, &item.HighFindings); err != nil {
		return item, err
	}
	item.Metadata = normalizedJSONRaw(metadataRaw)
	applyRepositoryMetadata(&item, item.Metadata)
	item.LatestEvidenceID = evidenceID
	item.LatestObservedAt = evidenceObservedAt
	item.LatestJobID = jobID
	if evidencePackageCount != nil {
		item.PackageCount = *evidencePackageCount
	}
	if attestationID != nil && attestationObservedAt != nil {
		item.LatestAttestation = &scanAttestationSummaryDTO{
			ID:                 *attestationID,
			SubjectKind:        attestationSubjectKind,
			SubjectDigest:      attestationSubjectDigest,
			PredicateType:      attestationPredicateType,
			PayloadSHA256:      attestationPayloadSHA,
			VerificationStatus: attestationStatus,
			Trusted:            attestationTrusted,
			TrustPolicyID:      attestationTrustPolicyID,
			VerificationReason: attestationReason,
			SignerIdentity:     attestationSignerIdentity,
			SignerIssuer:       attestationSignerIssuer,
			ObservedAt:         *attestationObservedAt,
			ExpiresAt:          attestationExpiresAt,
		}
	}
	return item, nil
}

func applyRepositoryMetadata(item *repositoryScanDTO, metadataRaw json.RawMessage) {
	if item == nil || len(metadataRaw) == 0 {
		return
	}
	var metadata repositoryScanMetadata
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		return
	}
	item.RepositoryURL = metadata.RepositoryURL
	item.CommitSHA = metadata.CommitSHA
	item.Branch = metadata.Branch
	item.Path = metadata.Path
	item.Workflow = metadata.Workflow
	item.RunID = metadata.RunID
	if metadata.RepositoryRef != "" {
		item.RepositoryRef = metadata.RepositoryRef
	}
	if item.SourceRef == "" {
		item.SourceRef = metadata.SourceRef
	}
	if item.PackageCount == 0 {
		item.PackageCount = metadata.PackageCount
	}
}

func (h *RepositoryInventoryHandler) getScan(r *http.Request, orgID uuid.UUID, id uuid.UUID) (repositoryScanDTO, error) {
	row := h.db.Pool().QueryRow(r.Context(), `
WITH finding_rollup AS (
    SELECT scan_target_id,
           COUNT(*) FILTER (WHERE lifecycle = 'open')::int AS open_findings,
           COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'critical')::int AS critical_findings,
           COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'high')::int AS high_findings
      FROM findings
     WHERE org_id = $1
       AND scan_target_id = $2
     GROUP BY scan_target_id
)
SELECT st.id, st.ref, st.source_type, COALESCE(st.source_ref, ''),
       COALESCE(st.inventory_hash, ''), st.metadata, st.last_seen_at,
       ev.id, COALESCE(ev.package_count, 0), ev.observed_at,
       sj.id, COALESCE(sj.status, ''),
       att.id, COALESCE(att.subject_kind, ''), COALESCE(att.subject_digest, ''),
       COALESCE(att.predicate_type, ''), COALESCE(att.payload_sha256, ''),
       COALESCE(att.verification_status, ''), COALESCE(att.trusted, false), att.trust_policy_id, COALESCE(att.verification_reason, ''),
       COALESCE(att.signer_identity, ''), COALESCE(att.signer_issuer, ''), att.observed_at, att.expires_at,
       COALESCE(fr.open_findings, 0), COALESCE(fr.critical_findings, 0), COALESCE(fr.high_findings, 0)
  FROM scan_targets st
  LEFT JOIN LATERAL (
      SELECT id, package_count, observed_at
        FROM scan_evidence
       WHERE org_id = st.org_id
         AND scan_target_id = st.id
         AND evidence_type = 'package-inventory'
       ORDER BY observed_at DESC
       LIMIT 1
  ) ev ON true
  LEFT JOIN LATERAL (
      SELECT id, status
        FROM scan_jobs
       WHERE org_id = st.org_id
         AND target_id = st.id
       ORDER BY requested_at DESC
       LIMIT 1
  ) sj ON true
  LEFT JOIN LATERAL (
      SELECT id, subject_kind, subject_digest, predicate_type, payload_sha256,
             verification_status, trusted, trust_policy_id, verification_reason, signer_identity, signer_issuer, observed_at, expires_at
        FROM scan_result_attestations
       WHERE org_id = st.org_id
         AND scan_target_id = st.id
       ORDER BY trusted DESC, observed_at DESC, created_at DESC
       LIMIT 1
  ) att ON true
  LEFT JOIN finding_rollup fr ON fr.scan_target_id = st.id
 WHERE st.org_id = $1
   AND st.id = $2
   AND st.type = 'repository'`, orgID, id)
	return scanRepositoryRow(row)
}

func (h *RepositoryInventoryHandler) latestEvidence(r *http.Request, orgID uuid.UUID, targetID uuid.UUID) (*repositoryEvidenceDTO, error) {
	var id uuid.UUID
	var inventoryHash string
	var packageCount int
	var payloadRaw []byte
	var observedAt time.Time
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id, inventory_hash, package_count, payload, observed_at
  FROM scan_evidence
 WHERE org_id = $1
   AND scan_target_id = $2
   AND evidence_type = 'package-inventory'
 ORDER BY observed_at DESC
 LIMIT 1`, orgID, targetID).Scan(&id, &inventoryHash, &packageCount, &payloadRaw, &observedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var payload scanEvidencePackagePayload
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return nil, err
	}
	return &repositoryEvidenceDTO{
		ID:            id,
		InventoryHash: inventoryHash,
		PackageCount:  packageCount,
		ObservedAt:    observedAt,
		RepositoryRef: payload.RepositoryRef,
		RepositoryURL: payload.RepositoryURL,
		CommitSHA:     payload.CommitSHA,
		Branch:        payload.Branch,
		Path:          payload.Path,
		Workflow:      payload.Workflow,
		RunID:         payload.RunID,
		Packages:      payload.Packages,
	}, nil
}

func (h *RepositoryInventoryHandler) recentJobs(r *http.Request, orgID uuid.UUID, targetID uuid.UUID) ([]repositoryJobDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, status, COALESCE(error, ''), COALESCE(package_count, 0), COALESCE(finding_count, 0),
       requested_at, claimed_at, finished_at
  FROM scan_jobs
 WHERE org_id = $1
   AND target_id = $2
 ORDER BY requested_at DESC
 LIMIT 25`, orgID, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []repositoryJobDTO{}
	for rows.Next() {
		var item repositoryJobDTO
		if err := rows.Scan(&item.ID, &item.Status, &item.Error, &item.PackageCount, &item.FindingCount,
			&item.RequestedAt, &item.ClaimedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *RepositoryInventoryHandler) findings(r *http.Request, orgID uuid.UUID, targetID uuid.UUID) ([]repositoryFindingDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, kind, COALESCE(external_id, ''), title, severity, risk_score,
       lifecycle, detail_json, first_seen_at, last_seen_at
  FROM findings
 WHERE org_id = $1
   AND scan_target_id = $2
 ORDER BY lifecycle = 'open' DESC, risk_score DESC, last_seen_at DESC
 LIMIT 100`, orgID, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []repositoryFindingDTO{}
	for rows.Next() {
		var item repositoryFindingDTO
		var detail []byte
		if err := rows.Scan(&item.ID, &item.Kind, &item.ExternalID, &item.Title, &item.Severity,
			&item.RiskScore, &item.Lifecycle, &detail, &item.FirstSeen, &item.LastSeen); err != nil {
			return nil, err
		}
		item.Detail = normalizedJSONRaw(detail)
		out = append(out, item)
	}
	return out, rows.Err()
}
