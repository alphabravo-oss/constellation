package scanning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/sigverify"
)

type ScanAttestations struct {
	db       *db.DB
	verifier scanAttestationVerifier
	auditLog *audit.Logger
}

type scanAttestationVerifier interface {
	VerifyAttestation(ctx context.Context, subjectRef string, policy sigverify.TrustPolicy) (*sigverify.AttestationResult, error)
}

type cosignScanAttestationVerifier struct {
	binary string
}

func (v cosignScanAttestationVerifier) VerifyAttestation(ctx context.Context, subjectRef string, policy sigverify.TrustPolicy) (*sigverify.AttestationResult, error) {
	verifier := sigverify.New()
	if strings.TrimSpace(v.binary) != "" {
		verifier.CosignBinary = strings.TrimSpace(v.binary)
	}
	return verifier.VerifyAttestation(ctx, subjectRef, policy)
}

func NewScanAttestations(d *db.DB) *ScanAttestations {
	return NewScanAttestationsWithAudit(d, nil)
}

func NewScanAttestationsWithAudit(d *db.DB, auditLog *audit.Logger) *ScanAttestations {
	binary := strings.TrimSpace(os.Getenv("CONSTELLATION_ATTESTATION_COSIGN_BIN"))
	if binary == "" {
		binary = strings.TrimSpace(os.Getenv("CONSTELLATION_COSIGN_BIN"))
	}
	if binary == "" {
		binary = "cosign"
	}
	return NewScanAttestationsWithVerifierAndAudit(d, cosignScanAttestationVerifier{binary: binary}, auditLog)
}

func NewScanAttestationsWithVerifier(d *db.DB, verifier scanAttestationVerifier) *ScanAttestations {
	return NewScanAttestationsWithVerifierAndAudit(d, verifier, nil)
}

func NewScanAttestationsWithVerifierAndAudit(d *db.DB, verifier scanAttestationVerifier, auditLog *audit.Logger) *ScanAttestations {
	return &ScanAttestations{db: d, verifier: verifier, auditLog: auditLog}
}

type scanAttestationReportRequest struct {
	ScanTargetID      *uuid.UUID      `json:"scan_target_id,omitempty"`
	ScanJobID         *uuid.UUID      `json:"scan_job_id,omitempty"`
	ScanEvidenceID    *uuid.UUID      `json:"scan_evidence_id,omitempty"`
	ImageScanResultID *uuid.UUID      `json:"image_scan_result_id,omitempty"`
	SubjectKind       string          `json:"subject_kind"`
	SubjectRef        string          `json:"subject_ref"`
	SubjectDigest     string          `json:"subject_digest"`
	RepositoryRef     string          `json:"repository_ref,omitempty"`
	RepositoryURL     string          `json:"repository_url,omitempty"`
	CommitSHA         string          `json:"commit_sha,omitempty"`
	Branch            string          `json:"branch,omitempty"`
	Workflow          string          `json:"workflow,omitempty"`
	RunID             string          `json:"run_id,omitempty"`
	RunAttempt        string          `json:"run_attempt,omitempty"`
	CIProvider        string          `json:"ci_provider,omitempty"`
	PredicateType     string          `json:"predicate_type"`
	Format            string          `json:"format,omitempty"`
	Payload           json.RawMessage `json:"payload"`
	Envelope          json.RawMessage `json:"envelope,omitempty"`
	Signature         json.RawMessage `json:"signature,omitempty"`
	Verification      string          `json:"verification_status,omitempty"`
	Trusted           bool            `json:"trusted,omitempty"`
	SignerIdentity    string          `json:"signer_identity,omitempty"`
	SignerIssuer      string          `json:"signer_issuer,omitempty"`
	VerifiedAt        *time.Time      `json:"verified_at,omitempty"`
	ObservedAt        *time.Time      `json:"observed_at,omitempty"`
	ExpiresAt         *time.Time      `json:"expires_at,omitempty"`
	Metadata          json.RawMessage `json:"metadata,omitempty"`
}

type scanAttestationDTO struct {
	ID                 uuid.UUID       `json:"id"`
	ScanTargetID       uuid.UUID       `json:"scan_target_id"`
	ScanJobID          *uuid.UUID      `json:"scan_job_id,omitempty"`
	ScanEvidenceID     *uuid.UUID      `json:"scan_evidence_id,omitempty"`
	ImageScanResultID  *uuid.UUID      `json:"image_scan_result_id,omitempty"`
	TargetType         string          `json:"target_type"`
	TargetRef          string          `json:"target_ref"`
	SourceType         string          `json:"source_type"`
	SourceRef          string          `json:"source_ref,omitempty"`
	SubjectKind        string          `json:"subject_kind"`
	SubjectRef         string          `json:"subject_ref"`
	SubjectDigest      string          `json:"subject_digest"`
	RepositoryRef      string          `json:"repository_ref,omitempty"`
	RepositoryURL      string          `json:"repository_url,omitempty"`
	CommitSHA          string          `json:"commit_sha,omitempty"`
	Branch             string          `json:"branch,omitempty"`
	Workflow           string          `json:"workflow,omitempty"`
	RunID              string          `json:"run_id,omitempty"`
	RunAttempt         string          `json:"run_attempt,omitempty"`
	CIProvider         string          `json:"ci_provider,omitempty"`
	PredicateType      string          `json:"predicate_type"`
	Format             string          `json:"format"`
	PayloadSHA256      string          `json:"payload_sha256"`
	VerificationStatus string          `json:"verification_status"`
	Trusted            bool            `json:"trusted"`
	TrustPolicyID      *uuid.UUID      `json:"trust_policy_id,omitempty"`
	VerificationReason string          `json:"verification_reason,omitempty"`
	SignerIdentity     string          `json:"signer_identity,omitempty"`
	SignerIssuer       string          `json:"signer_issuer,omitempty"`
	VerifiedAt         *time.Time      `json:"verified_at,omitempty"`
	ObservedAt         time.Time       `json:"observed_at"`
	ExpiresAt          *time.Time      `json:"expires_at,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	Metadata           json.RawMessage `json:"metadata,omitempty"`
	Payload            json.RawMessage `json:"payload,omitempty"`
	Envelope           json.RawMessage `json:"envelope,omitempty"`
	Signature          json.RawMessage `json:"signature,omitempty"`
}

type scanAttestationVerifyRequest struct {
	PolicyID *uuid.UUID `json:"policy_id,omitempty"`
}

type scanAttestationVerifyPendingRequest struct {
	Limit int `json:"limit,omitempty"`
}

type scanAttestationTrustPolicyDTO struct {
	ID                    uuid.UUID `json:"id"`
	Name                  string    `json:"name"`
	Description           string    `json:"description"`
	Enabled               bool      `json:"enabled"`
	AutoVerify            bool      `json:"auto_verify"`
	SubjectKind           string    `json:"subject_kind"`
	SourceTypes           []string  `json:"source_types"`
	RepositoryRefPatterns []string  `json:"repository_ref_patterns"`
	SourceRefPatterns     []string  `json:"source_ref_patterns"`
	PredicateTypes        []string  `json:"predicate_types"`
	AllowedIdentities     []string  `json:"allowed_identities"`
	AllowedIssuers        []string  `json:"allowed_issuers"`
	RequireRekor          bool      `json:"require_rekor"`
	VerifierMode          string    `json:"verifier_mode"`
	PublicKeyPEM          string    `json:"public_key_pem,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type scanAttestationTrustPolicyRequest struct {
	Name                  string   `json:"name,omitempty"`
	Description           string   `json:"description,omitempty"`
	Enabled               *bool    `json:"enabled,omitempty"`
	AutoVerify            *bool    `json:"auto_verify,omitempty"`
	SubjectKind           string   `json:"subject_kind,omitempty"`
	SourceTypes           []string `json:"source_types,omitempty"`
	RepositoryRefPatterns []string `json:"repository_ref_patterns,omitempty"`
	SourceRefPatterns     []string `json:"source_ref_patterns,omitempty"`
	PredicateTypes        []string `json:"predicate_types,omitempty"`
	AllowedIdentities     []string `json:"allowed_identities,omitempty"`
	AllowedIssuers        []string `json:"allowed_issuers,omitempty"`
	RequireRekor          *bool    `json:"require_rekor,omitempty"`
	VerifierMode          string   `json:"verifier_mode,omitempty"`
	PublicKeyPEM          string   `json:"public_key_pem,omitempty"`
}

type scanAttestationVerificationDTO struct {
	ID               uuid.UUID       `json:"id"`
	AttestationID    uuid.UUID       `json:"attestation_id"`
	TrustPolicyID    *uuid.UUID      `json:"trust_policy_id,omitempty"`
	TrustPolicyName  string          `json:"trust_policy_name,omitempty"`
	Status           string          `json:"status"`
	Trusted          bool            `json:"trusted"`
	Reason           string          `json:"reason,omitempty"`
	Error            string          `json:"error,omitempty"`
	SignerIdentity   string          `json:"signer_identity,omitempty"`
	SignerIssuer     string          `json:"signer_issuer,omitempty"`
	SubjectRef       string          `json:"subject_ref,omitempty"`
	SubjectDigest    string          `json:"subject_digest,omitempty"`
	PredicateType    string          `json:"predicate_type,omitempty"`
	PayloadSHA256    string          `json:"payload_sha256,omitempty"`
	RequireRekor     bool            `json:"require_rekor"`
	PolicySnapshot   json.RawMessage `json:"policy_snapshot,omitempty"`
	VerifierMetadata json.RawMessage `json:"verifier_metadata,omitempty"`
	VerifiedBy       *uuid.UUID      `json:"verified_by,omitempty"`
	AutoVerified     bool            `json:"auto_verified"`
	VerifiedAt       time.Time       `json:"verified_at"`
}

func (h *ScanAttestations) Report(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var req scanAttestationReportRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	req.normalize()
	if err := validateAttestationReport(req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload, payloadHash, err := canonicalAttestationJSON(req.Payload, true)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "payload: "+err.Error())
		return
	}
	if err := validateAttestationPayload(payload, req.PredicateType, req.SubjectDigest); err != nil {
		jsonError(w, http.StatusBadRequest, "payload: "+err.Error())
		return
	}
	envelope, err := canonicalAttestationJSONNoHash(req.Envelope, false)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "envelope: "+err.Error())
		return
	}
	signature, err := canonicalAttestationJSONNoHash(req.Signature, false)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "signature: "+err.Error())
		return
	}
	metadata, err := canonicalAttestationJSONNoHash(req.Metadata, false)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "metadata: "+err.Error())
		return
	}
	target, imageResultID, err := h.resolveAttestationTarget(r.Context(), subj.OrgID, req)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "scan target not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ScanEvidenceID != nil {
		if err := h.requireEvidenceForTarget(r.Context(), subj.OrgID, target.ID, *req.ScanEvidenceID); err != nil {
			jsonError(w, statusForLinkError(err), err.Error())
			return
		}
	}
	if req.ScanJobID != nil {
		if err := h.requireJobForTarget(r.Context(), subj.OrgID, target.ID, *req.ScanJobID); err != nil {
			jsonError(w, statusForLinkError(err), err.Error())
			return
		}
	}
	if req.ImageScanResultID != nil {
		if err := h.requireImageResultForTarget(r.Context(), subj.OrgID, target.ID, *req.ImageScanResultID); err != nil {
			jsonError(w, statusForLinkError(err), err.Error())
			return
		}
	}
	observedAt := time.Now().UTC()
	if req.ObservedAt != nil {
		observedAt = req.ObservedAt.UTC()
	}
	status := normalizeAttestationVerificationStatus(req.Verification, len(signature) > 0 || len(envelope) > 0)
	trusted := false
	var verifiedAt *time.Time
	if req.VerifiedAt != nil {
		v := req.VerifiedAt.UTC()
		verifiedAt = &v
	}
	if req.Trusted || status == "trusted" {
		jsonError(w, http.StatusBadRequest, "trusted attestations require server-side verification")
		return
	}

	var id uuid.UUID
	err = h.db.Pool().QueryRow(r.Context(), `
INSERT INTO scan_result_attestations (
    org_id, scan_target_id, scan_job_id, scan_evidence_id, image_scan_result_id,
    target_type, target_ref, source_type, source_ref,
    subject_kind, subject_ref, subject_digest,
    repository_ref, repository_url, commit_sha, branch, workflow, run_id, run_attempt, ci_provider,
    predicate_type, format, payload, payload_sha256, envelope, signature,
    verification_status, trusted, signer_identity, signer_issuer, verified_at,
    observed_at, expires_at, metadata
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, NULLIF($9, ''),
    $10, $11, $12,
    NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''), NULLIF($16, ''), NULLIF($17, ''), NULLIF($18, ''), NULLIF($19, ''), NULLIF($20, ''),
    $21, $22, $23::jsonb, $24, NULLIF($25::jsonb, 'null'::jsonb), NULLIF($26::jsonb, 'null'::jsonb),
    $27, $28, NULLIF($29, ''), NULLIF($30, ''), $31,
    $32, $33, $34::jsonb
)
ON CONFLICT (org_id, subject_kind, subject_digest, predicate_type, payload_sha256) DO UPDATE SET
    scan_target_id = EXCLUDED.scan_target_id,
    scan_job_id = EXCLUDED.scan_job_id,
    scan_evidence_id = EXCLUDED.scan_evidence_id,
    image_scan_result_id = EXCLUDED.image_scan_result_id,
    target_type = EXCLUDED.target_type,
    target_ref = EXCLUDED.target_ref,
    source_type = EXCLUDED.source_type,
    source_ref = EXCLUDED.source_ref,
    subject_ref = EXCLUDED.subject_ref,
    repository_ref = EXCLUDED.repository_ref,
    repository_url = EXCLUDED.repository_url,
    commit_sha = EXCLUDED.commit_sha,
    branch = EXCLUDED.branch,
    workflow = EXCLUDED.workflow,
    run_id = EXCLUDED.run_id,
    run_attempt = EXCLUDED.run_attempt,
    ci_provider = EXCLUDED.ci_provider,
    format = EXCLUDED.format,
    payload = EXCLUDED.payload,
    envelope = EXCLUDED.envelope,
    signature = EXCLUDED.signature,
    verification_status = CASE
        WHEN scan_result_attestations.trusted THEN scan_result_attestations.verification_status
        ELSE EXCLUDED.verification_status
    END,
    trusted = scan_result_attestations.trusted OR EXCLUDED.trusted,
    signer_identity = COALESCE(scan_result_attestations.signer_identity, EXCLUDED.signer_identity),
    signer_issuer = COALESCE(scan_result_attestations.signer_issuer, EXCLUDED.signer_issuer),
    verified_at = COALESCE(scan_result_attestations.verified_at, EXCLUDED.verified_at),
    observed_at = EXCLUDED.observed_at,
    expires_at = EXCLUDED.expires_at,
    metadata = CASE
        WHEN scan_result_attestations.trusted THEN scan_result_attestations.metadata
        ELSE EXCLUDED.metadata
    END
RETURNING id`,
		subj.OrgID, target.ID, req.ScanJobID, req.ScanEvidenceID, imageResultID,
		target.Type, target.Ref, target.SourceType, target.SourceRef,
		req.SubjectKind, req.SubjectRef, req.SubjectDigest,
		req.RepositoryRef, req.RepositoryURL, req.CommitSHA, req.Branch, req.Workflow, req.RunID, req.RunAttempt, req.CIProvider,
		req.PredicateType, req.Format, string(payload), payloadHash, string(nullJSON(envelope)), string(nullJSON(signature)),
		status, trusted, req.SignerIdentity, req.SignerIssuer, verifiedAt,
		observedAt, req.ExpiresAt, string(metadata)).Scan(&id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "attestation: "+err.Error())
		return
	}
	dto, err := h.getAttestation(r.Context(), subj.OrgID, id, true)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "read attestation: "+err.Error())
		return
	}
	if updated, _, _, _, err := h.autoVerifyAttestation(r.Context(), subj.OrgID, &subj.UserID, dto); err == nil && updated.ID != uuid.Nil {
		dto = updated
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "attestation": dto})
}

func (h *ScanAttestations) ListTrustPolicies(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, name, description, enabled, auto_verify, subject_kind, source_types,
       repository_ref_patterns, source_ref_patterns, predicate_types,
       allowed_identities, allowed_issuers, require_rekor, verifier_mode, public_key_pem, created_at, updated_at
  FROM scan_attestation_trust_policies
 WHERE org_id = $1
 ORDER BY enabled DESC, auto_verify DESC, lower(name)`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	items := []scanAttestationTrustPolicyDTO{}
	for rows.Next() {
		item, err := scanAttestationTrustPolicyRow(rows)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"policies": items})
}

func (h *ScanAttestations) CreateTrustPolicy(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	var req scanAttestationTrustPolicyRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	policy, err := trustPolicyFromRequest(req, nil)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var id uuid.UUID
	err = h.db.Pool().QueryRow(r.Context(), `
INSERT INTO scan_attestation_trust_policies (
    org_id, name, description, enabled, auto_verify, subject_kind, source_types,
    repository_ref_patterns, source_ref_patterns, predicate_types,
    allowed_identities, allowed_issuers, require_rekor, verifier_mode, public_key_pem, created_by, updated_by
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$16
) RETURNING id`, subj.OrgID, policy.Name, policy.Description, policy.Enabled, policy.AutoVerify,
		policy.SubjectKind, policy.SourceTypes, policy.RepositoryRefPatterns, policy.SourceRefPatterns,
		policy.PredicateTypes, policy.AllowedIdentities, policy.AllowedIssuers, policy.RequireRekor,
		policy.VerifierMode, policy.PublicKeyPEM, subj.UserID).Scan(&id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dto, err := h.getTrustPolicy(r.Context(), subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditTrustPolicy(r, subj, "attestation_trust_policy.create", nil, &dto)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"policy": dto})
}

func (h *ScanAttestations) PatchTrustPolicy(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	existing, err := h.getTrustPolicy(r.Context(), subj.OrgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "attestation trust policy not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var req scanAttestationTrustPolicyRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	policy, err := trustPolicyFromRequest(req, &existing)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE scan_attestation_trust_policies
   SET name = $1,
       description = $2,
       enabled = $3,
       auto_verify = $4,
       subject_kind = $5,
       source_types = $6,
       repository_ref_patterns = $7,
       source_ref_patterns = $8,
       predicate_types = $9,
       allowed_identities = $10,
       allowed_issuers = $11,
       require_rekor = $12,
       verifier_mode = $13,
       public_key_pem = $14,
       updated_by = $15,
       updated_at = NOW()
 WHERE org_id = $16
   AND id = $17`, policy.Name, policy.Description, policy.Enabled, policy.AutoVerify,
		policy.SubjectKind, policy.SourceTypes, policy.RepositoryRefPatterns, policy.SourceRefPatterns,
		policy.PredicateTypes, policy.AllowedIdentities, policy.AllowedIssuers, policy.RequireRekor,
		policy.VerifierMode, policy.PublicKeyPEM, subj.UserID, subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "attestation trust policy not found")
		return
	}
	dto, err := h.getTrustPolicy(r.Context(), subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditTrustPolicy(r, subj, "attestation_trust_policy.update", &existing, &dto)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"policy": dto})
}

func (h *ScanAttestations) DeleteTrustPolicy(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	existing, err := h.getTrustPolicy(r.Context(), subj.OrgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "attestation trust policy not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(), `DELETE FROM scan_attestation_trust_policies WHERE org_id = $1 AND id = $2`, subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "attestation trust policy not found")
		return
	}
	h.auditTrustPolicy(r, subj, "attestation_trust_policy.delete", &existing, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *ScanAttestations) VerifyPendingForPolicy(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	policy, err := h.getTrustPolicy(r.Context(), subj.OrgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "attestation trust policy not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var req scanAttestationVerifyPendingRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	items, err := h.pendingAttestationsForPolicy(r.Context(), subj.OrgID, policy, limit)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	results := []map[string]any{}
	trustedCount := 0
	for _, item := range items {
		updated, trusted, reason, verifyErr, err := h.verifyAttestationWithPolicy(r.Context(), subj.OrgID, &subj.UserID, false, item, policy)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if trusted {
			trustedCount++
		}
		entry := map[string]any{"id": item.ID, "trusted": trusted, "status": updated.VerificationStatus}
		if reason != "" {
			entry["reason"] = reason
		}
		if verifyErr != nil {
			entry["error"] = verifyErr.Error()
		}
		results = append(results, entry)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"policy":           policy,
		"verified":         len(results),
		"trusted":          trustedCount,
		"verification_run": results,
	})
}

func (h *ScanAttestations) Verify(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	if h.verifier == nil {
		jsonError(w, http.StatusInternalServerError, "attestation verifier unavailable")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid attestation id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req scanAttestationVerifyRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	dto, err := h.getAttestation(r.Context(), subj.OrgID, id, true)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "attestation not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	policy, err := h.policyForVerification(r.Context(), subj.OrgID, dto, req.PolicyID, false)
	if err != nil {
		jsonError(w, statusForPolicyError(err), err.Error())
		return
	}
	updated, trusted, reason, verifyErr, err := h.verifyAttestationWithPolicy(r.Context(), subj.OrgID, &subj.UserID, false, dto, policy)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	body := map[string]any{"ok": trusted, "policy": policy, "attestation": updated}
	if reason != "" {
		body["reason"] = reason
	}
	if verifyErr != nil {
		body["error"] = verifyErr.Error()
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

func (h *ScanAttestations) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid attestation id")
		return
	}
	dto, err := h.getAttestation(r.Context(), subj.OrgID, id, true)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "attestation not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"attestation": dto})
}

func (h *ScanAttestations) ListVerifications(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid attestation id")
		return
	}
	if _, err := h.getAttestation(r.Context(), subj.OrgID, id, false); errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "attestation not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	items, err := h.verificationsForAttestation(r.Context(), subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verifications": items})
}

func (h *ScanAttestations) Export(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid attestation id")
		return
	}
	dto, err := h.getAttestation(r.Context(), subj.OrgID, id, true)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "attestation not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	verifications, err := h.verificationsForAttestation(r.Context(), subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="constellation-repository-attestation-%s.json"`, id.String()))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"kind":          "constellation-repository-attestation-export-v1",
		"generated_at":  time.Now().UTC(),
		"attestation":   dto,
		"verifications": verifications,
	})
}

func (h *ScanAttestations) ListForRepositoryScan(w http.ResponseWriter, r *http.Request) {
	h.list(w, r, "scan_target_id", chi.URLParam(r, "id"))
}

func (h *ScanAttestations) ListForImageScanResult(w http.ResponseWriter, r *http.Request) {
	h.list(w, r, "image_scan_result_id", chi.URLParam(r, "id"))
}

func (h *ScanAttestations) list(w http.ResponseWriter, r *http.Request, column string, rawID string) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(rawID))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	query := fmt.Sprintf(`
SELECT id, scan_target_id, scan_job_id, scan_evidence_id, image_scan_result_id,
       target_type, target_ref, source_type, COALESCE(source_ref, ''),
       subject_kind, subject_ref, subject_digest,
       COALESCE(repository_ref, ''), COALESCE(repository_url, ''), COALESCE(commit_sha, ''),
       COALESCE(branch, ''), COALESCE(workflow, ''), COALESCE(run_id, ''), COALESCE(run_attempt, ''), COALESCE(ci_provider, ''),
       predicate_type, format, payload_sha256, verification_status, trusted, trust_policy_id, COALESCE(verification_reason, ''),
       COALESCE(signer_identity, ''), COALESCE(signer_issuer, ''), verified_at, observed_at, expires_at,
       created_at, metadata, NULL::jsonb, NULL::jsonb, NULL::jsonb
  FROM scan_result_attestations
 WHERE org_id = $1 AND %s = $2
 ORDER BY observed_at DESC, created_at DESC
 LIMIT 100`, column)
	rows, err := h.db.Pool().Query(r.Context(), query, subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	items := []scanAttestationDTO{}
	for rows.Next() {
		item, err := scanAttestationRow(rows, false)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"attestations": items})
}

func scanAttestationTrustPolicyRow(row interface{ Scan(dest ...any) error }) (scanAttestationTrustPolicyDTO, error) {
	var item scanAttestationTrustPolicyDTO
	if err := row.Scan(
		&item.ID,
		&item.Name,
		&item.Description,
		&item.Enabled,
		&item.AutoVerify,
		&item.SubjectKind,
		&item.SourceTypes,
		&item.RepositoryRefPatterns,
		&item.SourceRefPatterns,
		&item.PredicateTypes,
		&item.AllowedIdentities,
		&item.AllowedIssuers,
		&item.RequireRekor,
		&item.VerifierMode,
		&item.PublicKeyPEM,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return item, err
	}
	if strings.TrimSpace(item.VerifierMode) == "" {
		item.VerifierMode = "keyless"
	}
	return item, nil
}

func (h *ScanAttestations) verificationsForAttestation(ctx context.Context, orgID uuid.UUID, attestationID uuid.UUID) ([]scanAttestationVerificationDTO, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id, attestation_id, trust_policy_id, trust_policy_name,
       status, trusted, reason, error, signer_identity, signer_issuer,
       subject_ref, subject_digest, predicate_type, payload_sha256,
       require_rekor, policy_snapshot, verifier_metadata, verified_by, auto_verified, verified_at
  FROM scan_attestation_verifications
 WHERE org_id = $1
   AND attestation_id = $2
 ORDER BY verified_at DESC, id DESC`, orgID, attestationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []scanAttestationVerificationDTO{}
	for rows.Next() {
		item, err := scanAttestationVerificationRow(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanAttestationVerificationRow(row interface{ Scan(dest ...any) error }) (scanAttestationVerificationDTO, error) {
	var item scanAttestationVerificationDTO
	var policySnapshotRaw, verifierMetadataRaw []byte
	if err := row.Scan(
		&item.ID,
		&item.AttestationID,
		&item.TrustPolicyID,
		&item.TrustPolicyName,
		&item.Status,
		&item.Trusted,
		&item.Reason,
		&item.Error,
		&item.SignerIdentity,
		&item.SignerIssuer,
		&item.SubjectRef,
		&item.SubjectDigest,
		&item.PredicateType,
		&item.PayloadSHA256,
		&item.RequireRekor,
		&policySnapshotRaw,
		&verifierMetadataRaw,
		&item.VerifiedBy,
		&item.AutoVerified,
		&item.VerifiedAt,
	); err != nil {
		return item, err
	}
	item.PolicySnapshot = handler.NormalizedJSONRaw(policySnapshotRaw)
	item.VerifierMetadata = handler.NormalizedJSONRaw(verifierMetadataRaw)
	return item, nil
}

func (h *ScanAttestations) getTrustPolicy(ctx context.Context, orgID uuid.UUID, id uuid.UUID) (scanAttestationTrustPolicyDTO, error) {
	row := h.db.Pool().QueryRow(ctx, `
SELECT id, name, description, enabled, auto_verify, subject_kind, source_types,
       repository_ref_patterns, source_ref_patterns, predicate_types,
       allowed_identities, allowed_issuers, require_rekor, verifier_mode, public_key_pem, created_at, updated_at
  FROM scan_attestation_trust_policies
 WHERE org_id = $1
   AND id = $2`, orgID, id)
	return scanAttestationTrustPolicyRow(row)
}

func trustPolicyFromRequest(req scanAttestationTrustPolicyRequest, existing *scanAttestationTrustPolicyDTO) (scanAttestationTrustPolicyDTO, error) {
	policy := scanAttestationTrustPolicyDTO{
		Enabled:               true,
		AutoVerify:            true,
		SubjectKind:           "image",
		SourceTypes:           []string{"repository"},
		PredicateTypes:        normalizeAttestationStrings(req.PredicateTypes),
		AllowedIdentities:     normalizeAttestationStrings(req.AllowedIdentities),
		AllowedIssuers:        normalizeAttestationStrings(req.AllowedIssuers),
		VerifierMode:          "keyless",
		PublicKeyPEM:          strings.TrimSpace(req.PublicKeyPEM),
		RepositoryRefPatterns: normalizeAttestationStrings(req.RepositoryRefPatterns),
		SourceRefPatterns:     normalizeAttestationStrings(req.SourceRefPatterns),
	}
	if existing != nil {
		policy = *existing
	}
	if strings.TrimSpace(req.Name) != "" || existing == nil {
		policy.Name = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.Description) != "" || existing == nil {
		policy.Description = strings.TrimSpace(req.Description)
	}
	if req.Enabled != nil {
		policy.Enabled = *req.Enabled
	}
	if req.AutoVerify != nil {
		policy.AutoVerify = *req.AutoVerify
	}
	if strings.TrimSpace(req.SubjectKind) != "" || existing == nil {
		policy.SubjectKind = strings.ToLower(strings.TrimSpace(req.SubjectKind))
		if policy.SubjectKind == "" {
			policy.SubjectKind = "image"
		}
	}
	if req.SourceTypes != nil || existing == nil {
		policy.SourceTypes = normalizeAttestationStrings(req.SourceTypes)
		if existing == nil && len(policy.SourceTypes) == 0 {
			policy.SourceTypes = []string{"repository"}
		}
	}
	if req.RepositoryRefPatterns != nil || existing == nil {
		policy.RepositoryRefPatterns = normalizeAttestationStrings(req.RepositoryRefPatterns)
	}
	if req.SourceRefPatterns != nil || existing == nil {
		policy.SourceRefPatterns = normalizeAttestationStrings(req.SourceRefPatterns)
	}
	if req.PredicateTypes != nil || existing == nil {
		policy.PredicateTypes = normalizeAttestationStrings(req.PredicateTypes)
	}
	if req.AllowedIdentities != nil || existing == nil {
		policy.AllowedIdentities = normalizeAttestationStrings(req.AllowedIdentities)
	}
	if req.AllowedIssuers != nil || existing == nil {
		policy.AllowedIssuers = normalizeAttestationStrings(req.AllowedIssuers)
	}
	if req.RequireRekor != nil {
		policy.RequireRekor = *req.RequireRekor
	}
	if strings.TrimSpace(req.VerifierMode) != "" || existing == nil {
		policy.VerifierMode = normalizeVerifierMode(req.VerifierMode)
	}
	if strings.TrimSpace(req.PublicKeyPEM) != "" || existing == nil || policy.VerifierMode == "keyless" {
		policy.PublicKeyPEM = strings.TrimSpace(req.PublicKeyPEM)
	}
	if policy.VerifierMode == "keyless" {
		policy.PublicKeyPEM = ""
	}
	if err := validateTrustPolicy(policy); err != nil {
		return scanAttestationTrustPolicyDTO{}, err
	}
	return policy, nil
}

func validateTrustPolicy(policy scanAttestationTrustPolicyDTO) error {
	if strings.TrimSpace(policy.Name) == "" {
		return errors.New("name is required")
	}
	switch policy.SubjectKind {
	case "image":
	default:
		return errors.New("subject_kind must be image")
	}
	for _, sourceType := range policy.SourceTypes {
		if !validAttestationSourceType(sourceType) {
			return fmt.Errorf("unsupported source_type %q", sourceType)
		}
	}
	if len(policy.PredicateTypes) == 0 {
		return errors.New("predicate_types is required")
	}
	switch normalizeVerifierMode(policy.VerifierMode) {
	case "keyless":
		if len(policy.AllowedIdentities) == 0 {
			return errors.New("allowed_identities is required for keyless verification")
		}
		if len(policy.AllowedIssuers) == 0 {
			return errors.New("allowed_issuers is required for keyless verification")
		}
		if strings.TrimSpace(policy.PublicKeyPEM) != "" {
			return errors.New("public_key_pem is only valid for public-key verification")
		}
	case "public-key":
		if strings.TrimSpace(policy.PublicKeyPEM) == "" {
			return errors.New("public_key_pem is required for public-key verification")
		}
		if !strings.Contains(policy.PublicKeyPEM, "BEGIN") || !strings.Contains(policy.PublicKeyPEM, "PUBLIC KEY") {
			return errors.New("public_key_pem must be PEM-encoded public key material")
		}
	default:
		return errors.New("verifier_mode must be keyless or public-key")
	}
	return nil
}

func normalizeVerifierMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "keyless":
		return "keyless"
	case "public-key", "key", "keyed":
		return "public-key"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func validAttestationSourceType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "manual", "registry", "repository", "runtime-agent", "discoverer", "platform", "host", "serverless":
		return true
	default:
		return false
	}
}

func (h *ScanAttestations) policyForVerification(ctx context.Context, orgID uuid.UUID, item scanAttestationDTO, policyID *uuid.UUID, autoOnly bool) (scanAttestationTrustPolicyDTO, error) {
	if policyID != nil {
		policy, err := h.getTrustPolicy(ctx, orgID, *policyID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return scanAttestationTrustPolicyDTO{}, errors.New("attestation trust policy not found")
			}
			return scanAttestationTrustPolicyDTO{}, err
		}
		if !policy.Enabled {
			return scanAttestationTrustPolicyDTO{}, errors.New("attestation trust policy is disabled")
		}
		if autoOnly && !policy.AutoVerify {
			return scanAttestationTrustPolicyDTO{}, errors.New("attestation trust policy auto_verify is disabled")
		}
		if !policyMatchesAttestation(policy, item) {
			return scanAttestationTrustPolicyDTO{}, errors.New("attestation trust policy does not match attestation")
		}
		return policy, nil
	}
	policies, err := h.matchingTrustPolicies(ctx, orgID, item, autoOnly)
	if err != nil {
		return scanAttestationTrustPolicyDTO{}, err
	}
	if len(policies) == 0 {
		return scanAttestationTrustPolicyDTO{}, errors.New("no matching attestation trust policy")
	}
	return policies[0], nil
}

func (h *ScanAttestations) matchingTrustPolicies(ctx context.Context, orgID uuid.UUID, item scanAttestationDTO, autoOnly bool) ([]scanAttestationTrustPolicyDTO, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id, name, description, enabled, auto_verify, subject_kind, source_types,
       repository_ref_patterns, source_ref_patterns, predicate_types,
       allowed_identities, allowed_issuers, require_rekor, verifier_mode, public_key_pem, created_at, updated_at
  FROM scan_attestation_trust_policies
 WHERE org_id = $1
   AND enabled
   AND (NOT $2::bool OR auto_verify)
 ORDER BY auto_verify DESC, updated_at DESC, lower(name)`, orgID, autoOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []scanAttestationTrustPolicyDTO{}
	for rows.Next() {
		policy, err := scanAttestationTrustPolicyRow(rows)
		if err != nil {
			return nil, err
		}
		if policyMatchesAttestation(policy, item) {
			out = append(out, policy)
		}
	}
	return out, rows.Err()
}

func (h *ScanAttestations) autoVerifyAttestation(ctx context.Context, orgID uuid.UUID, actorID *uuid.UUID, item scanAttestationDTO) (scanAttestationDTO, bool, string, error, error) {
	if h.verifier == nil || item.Trusted {
		return scanAttestationDTO{}, false, "", nil, nil
	}
	policy, err := h.policyForVerification(ctx, orgID, item, nil, true)
	if err != nil {
		return scanAttestationDTO{}, false, "", nil, nil
	}
	return h.verifyAttestationWithPolicy(ctx, orgID, actorID, true, item, policy)
}

func (h *ScanAttestations) pendingAttestationsForPolicy(ctx context.Context, orgID uuid.UUID, policy scanAttestationTrustPolicyDTO, limit int) ([]scanAttestationDTO, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id, scan_target_id, scan_job_id, scan_evidence_id, image_scan_result_id,
       target_type, target_ref, source_type, COALESCE(source_ref, ''),
       subject_kind, subject_ref, subject_digest,
       COALESCE(repository_ref, ''), COALESCE(repository_url, ''), COALESCE(commit_sha, ''),
       COALESCE(branch, ''), COALESCE(workflow, ''), COALESCE(run_id, ''), COALESCE(run_attempt, ''), COALESCE(ci_provider, ''),
       predicate_type, format, payload_sha256, verification_status, trusted, trust_policy_id, COALESCE(verification_reason, ''),
       COALESCE(signer_identity, ''), COALESCE(signer_issuer, ''), verified_at, observed_at, expires_at,
       created_at, metadata, payload, envelope, signature
  FROM scan_result_attestations
 WHERE org_id = $1
   AND NOT trusted
 ORDER BY observed_at DESC, created_at DESC
 LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []scanAttestationDTO{}
	for rows.Next() {
		item, err := scanAttestationRow(rows, true)
		if err != nil {
			return nil, err
		}
		if policyMatchesAttestation(policy, item) {
			out = append(out, item)
		}
	}
	return out, rows.Err()
}

func (h *ScanAttestations) verifyAttestationWithPolicy(ctx context.Context, orgID uuid.UUID, actorID *uuid.UUID, autoVerified bool, item scanAttestationDTO, policy scanAttestationTrustPolicyDTO) (scanAttestationDTO, bool, string, error, error) {
	if h.verifier == nil {
		return scanAttestationDTO{}, false, "", nil, errors.New("attestation verifier unavailable")
	}
	if item.SubjectKind != "image" {
		return scanAttestationDTO{}, false, "", nil, errors.New("trusted attestation verification currently requires image subjects")
	}
	if !strings.Contains(item.SubjectRef, "@sha256:") {
		return scanAttestationDTO{}, false, "", nil, errors.New("trusted attestation verification requires a digest-pinned subject_ref")
	}
	result, verifyErr := h.verifier.VerifyAttestation(ctx, item.SubjectRef, sigverify.TrustPolicy{
		Mode:                policy.VerifierMode,
		Identities:          policy.AllowedIdentities,
		Issuers:             policy.AllowedIssuers,
		RequireRekor:        policy.RequireRekor,
		RequireAttestations: policy.PredicateTypes,
		PublicKeyPEM:        policy.PublicKeyPEM,
	})
	status := "error"
	trusted := false
	reason := ""
	identity := ""
	issuer := ""
	if result != nil {
		reason = strings.TrimSpace(result.Reason)
		identity = strings.TrimSpace(result.Identity)
		issuer = strings.TrimSpace(result.Issuer)
	}
	if verifyErr == nil {
		status = "untrusted"
		if result == nil {
			reason = "attestation verifier returned no result"
		} else if result.PredicateType != item.PredicateType {
			reason = fmt.Sprintf("verified predicate type %q does not match stored predicate type %q", result.PredicateType, item.PredicateType)
		} else if result.PayloadSHA256 != item.PayloadSHA256 {
			reason = fmt.Sprintf("verified payload hash %q does not match stored payload hash %q", result.PayloadSHA256, item.PayloadSHA256)
		} else if !attestationPayloadSubjectDigestMatches(result.Payload, item.SubjectDigest) {
			reason = fmt.Sprintf("verified attestation does not bind subject digest %q", item.SubjectDigest)
		} else if result.Trusted {
			status = "trusted"
			trusted = true
			if reason == "" {
				reason = "attestation trusted"
			}
		}
	} else if reason == "" {
		reason = verifyErr.Error()
	}
	verificationID, err := h.recordAttestationVerification(ctx, orgID, actorID, autoVerified, item, policy, status, trusted, reason, verifyErr, identity, issuer, result)
	if err != nil {
		return scanAttestationDTO{}, false, reason, verifyErr, fmt.Errorf("record attestation verification: %w", err)
	}
	metadata, err := verificationMetadata(item.Metadata, reason, verifyErr, &policy, verificationID)
	if err != nil {
		return scanAttestationDTO{}, false, "", verifyErr, fmt.Errorf("verification metadata: %w", err)
	}
	now := time.Now().UTC()
	if _, err := h.db.Pool().Exec(ctx, `
UPDATE scan_result_attestations
   SET verification_status = $1,
       trusted = $2,
       signer_identity = NULLIF($3, ''),
       signer_issuer = NULLIF($4, ''),
       verified_at = $5,
       metadata = $6::jsonb,
       trust_policy_id = $7,
       verification_reason = NULLIF($8, '')
 WHERE org_id = $9
   AND id = $10`, status, trusted, identity, issuer, now, string(metadata), policy.ID, reason, orgID, item.ID); err != nil {
		return scanAttestationDTO{}, false, reason, verifyErr, fmt.Errorf("update attestation verification: %w", err)
	}
	updated, err := h.getAttestation(ctx, orgID, item.ID, true)
	if err != nil {
		return scanAttestationDTO{}, false, reason, verifyErr, fmt.Errorf("read attestation: %w", err)
	}
	h.auditAttestationVerification(ctx, orgID, actorID, autoVerified, item, policy, status, trusted, reason, verifyErr, verificationID)
	return updated, trusted, reason, verifyErr, nil
}

func (h *ScanAttestations) recordAttestationVerification(
	ctx context.Context,
	orgID uuid.UUID,
	actorID *uuid.UUID,
	autoVerified bool,
	item scanAttestationDTO,
	policy scanAttestationTrustPolicyDTO,
	status string,
	trusted bool,
	reason string,
	verifyErr error,
	identity string,
	issuer string,
	result *sigverify.AttestationResult,
) (uuid.UUID, error) {
	policySnapshot, err := json.Marshal(policy)
	if err != nil {
		return uuid.Nil, err
	}
	verifierMetadata := map[string]any{}
	if result != nil {
		verifierMetadata["result_trusted"] = result.Trusted
		verifierMetadata["result_predicate_type"] = result.PredicateType
		verifierMetadata["result_payload_sha256"] = result.PayloadSHA256
		verifierMetadata["result_subject_ref"] = result.SubjectRef
	}
	if verifyErr != nil {
		verifierMetadata["error"] = verifyErr.Error()
	}
	verifierMetadataRaw, err := json.Marshal(verifierMetadata)
	if err != nil {
		return uuid.Nil, err
	}
	errString := ""
	if verifyErr != nil {
		errString = verifyErr.Error()
	}
	var verificationID uuid.UUID
	err = h.db.Pool().QueryRow(ctx, `
INSERT INTO scan_attestation_verifications (
    org_id, attestation_id, trust_policy_id, trust_policy_name,
    status, trusted, reason, error, signer_identity, signer_issuer,
    subject_ref, subject_digest, predicate_type, payload_sha256,
    require_rekor, policy_snapshot, verifier_metadata, verified_by, auto_verified
) VALUES (
    $1,$2,$3,$4,
    $5,$6,$7,$8,$9,$10,
    $11,$12,$13,$14,
    $15,$16::jsonb,$17::jsonb,$18,$19
) RETURNING id`,
		orgID, item.ID, policy.ID, policy.Name,
		status, trusted, strings.TrimSpace(reason), errString, strings.TrimSpace(identity), strings.TrimSpace(issuer),
		item.SubjectRef, item.SubjectDigest, item.PredicateType, item.PayloadSHA256,
		policy.RequireRekor, string(policySnapshot), string(verifierMetadataRaw), actorID, autoVerified).Scan(&verificationID)
	if err != nil {
		return uuid.Nil, err
	}
	return verificationID, nil
}

func statusForPolicyError(err error) int {
	msg := err.Error()
	if strings.Contains(msg, "not found") || strings.Contains(msg, "no matching") {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

func policyMatchesAttestation(policy scanAttestationTrustPolicyDTO, item scanAttestationDTO) bool {
	if !policy.Enabled {
		return false
	}
	if policy.SubjectKind != "" && policy.SubjectKind != item.SubjectKind {
		return false
	}
	if len(policy.SourceTypes) > 0 && !stringIn(policy.SourceTypeNormalized(), strings.ToLower(strings.TrimSpace(item.SourceType))) {
		return false
	}
	if len(policy.PredicateTypes) > 0 && !stringIn(policy.PredicateTypes, item.PredicateType) {
		return false
	}
	if len(policy.RepositoryRefPatterns) > 0 && !globMatchesAny(item.RepositoryRef, policy.RepositoryRefPatterns) {
		return false
	}
	if len(policy.SourceRefPatterns) > 0 && !globMatchesAny(item.SourceRef, policy.SourceRefPatterns) {
		return false
	}
	return true
}

func (p scanAttestationTrustPolicyDTO) SourceTypeNormalized() []string {
	out := make([]string, 0, len(p.SourceTypes))
	for _, value := range p.SourceTypes {
		out = append(out, strings.ToLower(strings.TrimSpace(value)))
	}
	return out
}

func stringIn(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func globMatchesAny(value string, patterns []string) bool {
	value = strings.TrimSpace(value)
	for _, pattern := range patterns {
		if handler.GlobMatch(pattern, value) {
			return true
		}
	}
	return false
}

func (h *ScanAttestations) getAttestation(ctx context.Context, orgID uuid.UUID, id uuid.UUID, includePayload bool) (scanAttestationDTO, error) {
	payloadSelect := "NULL::jsonb, NULL::jsonb, NULL::jsonb"
	if includePayload {
		payloadSelect = "payload, envelope, signature"
	}
	row := h.db.Pool().QueryRow(ctx, `
SELECT id, scan_target_id, scan_job_id, scan_evidence_id, image_scan_result_id,
       target_type, target_ref, source_type, COALESCE(source_ref, ''),
       subject_kind, subject_ref, subject_digest,
       COALESCE(repository_ref, ''), COALESCE(repository_url, ''), COALESCE(commit_sha, ''),
       COALESCE(branch, ''), COALESCE(workflow, ''), COALESCE(run_id, ''), COALESCE(run_attempt, ''), COALESCE(ci_provider, ''),
       predicate_type, format, payload_sha256, verification_status, trusted, trust_policy_id, COALESCE(verification_reason, ''),
       COALESCE(signer_identity, ''), COALESCE(signer_issuer, ''), verified_at, observed_at, expires_at,
       created_at, metadata, `+payloadSelect+`
  FROM scan_result_attestations
 WHERE org_id = $1 AND id = $2`, orgID, id)
	return scanAttestationRow(row, includePayload)
}

func scanAttestationRow(row interface{ Scan(dest ...any) error }, includePayload bool) (scanAttestationDTO, error) {
	var item scanAttestationDTO
	var metadataRaw []byte
	var payloadRaw, envelopeRaw, signatureRaw []byte
	if err := row.Scan(
		&item.ID, &item.ScanTargetID, &item.ScanJobID, &item.ScanEvidenceID, &item.ImageScanResultID,
		&item.TargetType, &item.TargetRef, &item.SourceType, &item.SourceRef,
		&item.SubjectKind, &item.SubjectRef, &item.SubjectDigest,
		&item.RepositoryRef, &item.RepositoryURL, &item.CommitSHA,
		&item.Branch, &item.Workflow, &item.RunID, &item.RunAttempt, &item.CIProvider,
		&item.PredicateType, &item.Format, &item.PayloadSHA256, &item.VerificationStatus, &item.Trusted,
		&item.TrustPolicyID, &item.VerificationReason,
		&item.SignerIdentity, &item.SignerIssuer, &item.VerifiedAt, &item.ObservedAt, &item.ExpiresAt,
		&item.CreatedAt, &metadataRaw, &payloadRaw, &envelopeRaw, &signatureRaw,
	); err != nil {
		return item, err
	}
	item.Metadata = handler.NormalizedJSONRaw(metadataRaw)
	if includePayload {
		item.Payload = handler.NormalizedJSONRaw(payloadRaw)
		item.Envelope = handler.NormalizedJSONRaw(envelopeRaw)
		item.Signature = handler.NormalizedJSONRaw(signatureRaw)
	}
	return item, nil
}

func (h *ScanAttestations) resolveAttestationTarget(ctx context.Context, orgID uuid.UUID, req scanAttestationReportRequest) (handler.ScanTarget, *uuid.UUID, error) {
	targetID := req.ScanTargetID
	imageResultID := req.ImageScanResultID
	if targetID == nil && imageResultID != nil {
		var id uuid.UUID
		err := h.db.Pool().QueryRow(ctx, `
SELECT scan_target_id
  FROM image_scan_results
 WHERE org_id = $1 AND id = $2 AND scan_target_id IS NOT NULL`, orgID, *imageResultID).Scan(&id)
		if err != nil {
			return handler.ScanTarget{}, nil, fmt.Errorf("image scan result target: %w", err)
		}
		targetID = &id
	}
	if targetID == nil {
		return handler.ScanTarget{}, nil, errors.New("scan_target_id or image_scan_result_id is required")
	}
	target, err := handler.LoadScanTarget(ctx, h.db.Pool(), nil, *targetID)
	if err != nil {
		return handler.ScanTarget{}, nil, err
	}
	if target.OrgID != orgID {
		return handler.ScanTarget{}, nil, errors.New("scan target not found")
	}
	if imageResultID == nil && req.SubjectKind == "image" && req.SubjectDigest != "" {
		var id uuid.UUID
		err := h.db.Pool().QueryRow(ctx, `
SELECT id
  FROM image_scan_results
 WHERE org_id = $1
   AND scan_target_id = $2
   AND image_digest = $3
 ORDER BY last_scanned_at DESC
 LIMIT 1`, orgID, target.ID, req.SubjectDigest).Scan(&id)
		if err == nil {
			imageResultID = &id
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return handler.ScanTarget{}, nil, err
		}
	}
	return target, imageResultID, nil
}

func (h *ScanAttestations) requireEvidenceForTarget(ctx context.Context, orgID, targetID, evidenceID uuid.UUID) error {
	return requireLinkedTarget(ctx, h.db.Pool().QueryRow(ctx, `SELECT scan_target_id FROM scan_evidence WHERE org_id = $1 AND id = $2`, orgID, evidenceID), targetID, "scan evidence")
}

func (h *ScanAttestations) requireJobForTarget(ctx context.Context, orgID, targetID, jobID uuid.UUID) error {
	return requireLinkedTarget(ctx, h.db.Pool().QueryRow(ctx, `SELECT target_id FROM scan_jobs WHERE org_id = $1 AND id = $2`, orgID, jobID), targetID, "scan job")
}

func (h *ScanAttestations) requireImageResultForTarget(ctx context.Context, orgID, targetID, resultID uuid.UUID) error {
	return requireLinkedTarget(ctx, h.db.Pool().QueryRow(ctx, `SELECT scan_target_id FROM image_scan_results WHERE org_id = $1 AND id = $2 AND scan_target_id IS NOT NULL`, orgID, resultID), targetID, "image scan result")
}

func requireLinkedTarget(_ context.Context, row pgx.Row, targetID uuid.UUID, label string) error {
	var linked uuid.UUID
	if err := row.Scan(&linked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%s not found", label)
		}
		return err
	}
	if linked != targetID {
		return fmt.Errorf("%s does not belong to scan target", label)
	}
	return nil
}

func statusForLinkError(err error) int {
	if strings.Contains(err.Error(), "not found") {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

func (r *scanAttestationReportRequest) normalize() {
	r.SubjectKind = strings.ToLower(strings.TrimSpace(r.SubjectKind))
	r.SubjectRef = strings.TrimSpace(r.SubjectRef)
	r.SubjectDigest = strings.TrimSpace(r.SubjectDigest)
	r.RepositoryRef = strings.TrimSpace(r.RepositoryRef)
	r.RepositoryURL = strings.TrimSpace(r.RepositoryURL)
	r.CommitSHA = strings.TrimSpace(r.CommitSHA)
	r.Branch = strings.TrimSpace(r.Branch)
	r.Workflow = strings.TrimSpace(r.Workflow)
	r.RunID = strings.TrimSpace(r.RunID)
	r.RunAttempt = strings.TrimSpace(r.RunAttempt)
	r.CIProvider = strings.TrimSpace(r.CIProvider)
	r.PredicateType = strings.TrimSpace(r.PredicateType)
	r.Format = strings.TrimSpace(r.Format)
	if r.Format == "" {
		r.Format = "in-toto-statement-v1"
	}
	r.Verification = normalizeAttestationVerificationStatus(r.Verification, len(r.Signature) > 0 || len(r.Envelope) > 0)
	r.SignerIdentity = strings.TrimSpace(r.SignerIdentity)
	r.SignerIssuer = strings.TrimSpace(r.SignerIssuer)
}

func validateAttestationReport(req scanAttestationReportRequest) error {
	switch req.SubjectKind {
	case "image", "repository":
	default:
		return errors.New("subject_kind must be image or repository")
	}
	if req.SubjectRef == "" {
		return errors.New("subject_ref is required")
	}
	if req.SubjectDigest == "" {
		return errors.New("subject_digest is required")
	}
	if req.PredicateType == "" {
		return errors.New("predicate_type is required")
	}
	if req.Format == "" {
		return errors.New("format is required")
	}
	if !validAttestationVerificationStatus(req.Verification) {
		return errors.New("unsupported verification_status")
	}
	return nil
}

func normalizeAttestationVerificationStatus(value string, hasSignatureMaterial bool) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		if hasSignatureMaterial {
			return "unverified"
		}
		return "unsigned"
	}
	return value
}

func validAttestationVerificationStatus(value string) bool {
	switch value {
	case "trusted", "untrusted", "unsigned", "error", "unverified":
		return true
	default:
		return false
	}
}

func canonicalAttestationJSON(raw json.RawMessage, required bool) (json.RawMessage, string, error) {
	normalized, err := canonicalAttestationJSONNoHash(raw, required)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(normalized)
	return normalized, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalAttestationJSONNoHash(raw json.RawMessage, required bool) (json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		if required {
			return nil, errors.New("required")
		}
		return json.RawMessage(`{}`), nil
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	if decoded == nil && required {
		return nil, errors.New("required")
	}
	normalized, err := json.Marshal(decoded)
	if err != nil {
		return nil, err
	}
	if string(normalized) == "null" && !required {
		return json.RawMessage(`{}`), nil
	}
	return normalized, nil
}

func nullJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "{}" {
		return json.RawMessage("null")
	}
	return raw
}

func normalizeAttestationStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func attestationPayloadSubjectDigestMatches(raw json.RawMessage, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" || len(raw) == 0 {
		return false
	}
	expectedAlg := "sha256"
	expectedValue := expected
	if idx := strings.Index(expected, ":"); idx > 0 {
		expectedAlg = strings.ToLower(strings.TrimSpace(expected[:idx]))
		expectedValue = strings.TrimSpace(expected[idx+1:])
	}
	var statement struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(raw, &statement); err != nil {
		return false
	}
	for _, subject := range statement.Subject {
		for alg, digest := range subject.Digest {
			if strings.EqualFold(strings.TrimSpace(alg), expectedAlg) && strings.EqualFold(strings.TrimSpace(digest), expectedValue) {
				return true
			}
			if strings.EqualFold(strings.TrimSpace(digest), expected) {
				return true
			}
		}
	}
	return false
}

func validateAttestationPayload(raw json.RawMessage, predicateType string, subjectDigest string) error {
	var statement struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(raw, &statement); err != nil {
		return err
	}
	if statement.Type != "https://in-toto.io/Statement/v1" {
		return errors.New("_type must be https://in-toto.io/Statement/v1")
	}
	if statement.PredicateType != predicateType {
		return fmt.Errorf("predicateType %q does not match predicate_type %q", statement.PredicateType, predicateType)
	}
	if !attestationPayloadSubjectDigestMatches(raw, subjectDigest) {
		return fmt.Errorf("subject does not bind digest %q", subjectDigest)
	}
	return nil
}

func verificationMetadata(raw json.RawMessage, reason string, verifyErr error, policy *scanAttestationTrustPolicyDTO, verificationID uuid.UUID) (json.RawMessage, error) {
	metadata := map[string]any{}
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return nil, err
		}
	}
	record := map[string]any{
		"reason":      strings.TrimSpace(reason),
		"observed_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if verifyErr != nil {
		record["error"] = verifyErr.Error()
	}
	if policy != nil {
		record["policy_id"] = policy.ID.String()
		record["policy_name"] = policy.Name
	}
	if verificationID != uuid.Nil {
		record["verification_id"] = verificationID.String()
	}
	metadata["verification"] = record
	return json.Marshal(metadata)
}

func (h *ScanAttestations) auditTrustPolicy(r *http.Request, subj authctx.Subject, action string, before *scanAttestationTrustPolicyDTO, after *scanAttestationTrustPolicyDTO) {
	if h.auditLog == nil {
		return
	}
	orgID := subj.OrgID
	userID := subj.UserID
	targetID := ""
	if after != nil {
		targetID = after.ID.String()
	} else if before != nil {
		targetID = before.ID.String()
	}
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    actorIPFromRequest(r),
		Action:     action,
		TargetKind: "attestation-trust-policy",
		TargetID:   targetID,
		Before:     before,
		After:      after,
		RequestID:  chimw.GetReqID(r.Context()),
	})
}

func (h *ScanAttestations) auditAttestationVerification(
	ctx context.Context,
	orgID uuid.UUID,
	actorID *uuid.UUID,
	autoVerified bool,
	item scanAttestationDTO,
	policy scanAttestationTrustPolicyDTO,
	status string,
	trusted bool,
	reason string,
	verifyErr error,
	verificationID uuid.UUID,
) {
	if h.auditLog == nil {
		return
	}
	after := map[string]any{
		"verification_id": verificationID,
		"attestation_id":  item.ID,
		"trust_policy_id": policy.ID,
		"policy_name":     policy.Name,
		"status":          status,
		"trusted":         trusted,
		"reason":          strings.TrimSpace(reason),
		"auto_verified":   autoVerified,
		"subject_digest":  item.SubjectDigest,
		"predicate_type":  item.PredicateType,
		"payload_sha256":  item.PayloadSHA256,
	}
	if verifyErr != nil {
		after["error"] = verifyErr.Error()
	}
	_, _, _ = h.auditLog.Log(ctx, audit.Event{
		OrgID:      &orgID,
		ActorID:    actorID,
		Action:     "attestation.verify",
		TargetKind: "repository-scan-attestation",
		TargetID:   item.ID.String(),
		Before: map[string]any{
			"status":  item.VerificationStatus,
			"trusted": item.Trusted,
		},
		After: after,
	})
}

func actorIPFromRequest(r *http.Request) net.IP {
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	return actorIP
}
