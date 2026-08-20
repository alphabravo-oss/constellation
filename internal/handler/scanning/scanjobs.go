// Scan-job queue endpoints.
//
//	POST /api/v1/scan-jobs            — enqueue (auth: user, verb=read-findings)
//	GET  /api/v1/scan-jobs            — list (auth: user, verb=read-findings)
//	POST /api/v1/scan-jobs/claim      — atomically claim one pending job (auth: scanner-token)
//	POST /api/v1/scan-jobs/{id}/renew — extend lease (auth: scanner-token)
//	POST /api/v1/scan-jobs/{id}/complete — write results (auth: scanner-token)
//	POST /api/v1/scan-jobs/{id}/fail     — record failure (auth: scanner-token)
//
// Scanner-token auth is separate from user JWT auth: scanner tokens are per-org service
// credentials with a narrow privilege envelope (queue claim + result write only). Their
// hash is stored in scanner_tokens.token_hash; the raw token is shown to the admin once.
package scanning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/imageid"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/responserule"
	"github.com/alphabravocompany/constellation/pkg/sbom"
	"github.com/alphabravocompany/constellation/pkg/vulnprofile"
)

// ScanJobs handler.
type ScanJobs struct {
	db    *db.DB
	audit *audit.Logger

	// evalResponseRules, when non-nil, is the E1 declarative response-rule evaluator
	// (pkg/responserule). It is invoked once per completed scan with the scan result folded
	// down to an EventScan responserule.Event; it returns the ordered matching actions and
	// fires any webhook actions through the notify dispatcher as a side effect. Injected by
	// the API server (which owns response_rules loading); nil disables E1 scan evaluation.
	// This is the server-side half of E1 that closes "a scan-typed rule fires on a matching
	// scan ingest" (NeuVector's EventCVEReport parity).
	evalResponseRules func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error)
}

const scannerJobBaseRetryDelay = 2 * time.Minute
const scannerJobMaxRetryDelay = 30 * time.Minute

func NewScanJobs(d *db.DB, a *audit.Logger) *ScanJobs {
	return &ScanJobs{db: d, audit: a}
}

// WithResponseRuleEngine attaches the E1 declarative response-rule evaluator (pkg/responserule).
// The hook is called once per completed scan so the org's enabled EventScan rules can match and
// fire their ordered actions (quarantine/suppress_log/tag) and webhooks. Returns the receiver
// for chaining.
func (h *ScanJobs) WithResponseRuleEngine(eval func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error)) *ScanJobs {
	h.evalResponseRules = eval
	return h
}

// EnqueueRequest is the user-facing POST body.
type EnqueueRequest struct {
	TargetType      string          `json:"target_type"`
	TargetRef       string          `json:"target_ref"`
	TargetClusterID *uuid.UUID      `json:"target_cluster_id,omitempty"`
	SourceType      string          `json:"source_type,omitempty"`
	SourceRef       string          `json:"source_ref,omitempty"`
	Platform        string          `json:"platform,omitempty"`
	InventoryHash   string          `json:"inventory_hash,omitempty"`
	Metadata        json.RawMessage `json:"metadata,omitempty"`
	MaxAttempts     int             `json:"max_attempts,omitempty"`
}

// JobView is the response shape.
type JobView struct {
	ID                  uuid.UUID               `json:"id"`
	OrgID               uuid.UUID               `json:"org_id"`
	TargetID            uuid.UUID               `json:"target_id"`
	TargetType          string                  `json:"target_type"`
	TargetRef           string                  `json:"target_ref"`
	TargetClusterID     *uuid.UUID              `json:"target_cluster_id,omitempty"`
	SourceType          string                  `json:"source_type,omitempty"`
	SourceRef           string                  `json:"source_ref,omitempty"`
	ImageRef            string                  `json:"image_ref,omitempty"`
	Platform            string                  `json:"platform,omitempty"`
	InventoryHash       string                  `json:"inventory_hash,omitempty"`
	RegistryID          *uuid.UUID              `json:"registry_id,omitempty"`
	ImageDigest         string                  `json:"image_digest,omitempty"`
	Metadata            json.RawMessage         `json:"metadata,omitempty"`
	EnqueueReason       string                  `json:"enqueue_reason,omitempty"`
	RegistryPolicyHash  string                  `json:"registry_policy_hash,omitempty"`
	VulnDBBundleVersion string                  `json:"vulndb_bundle_version,omitempty"`
	Status              string                  `json:"status"`
	WorkerID            string                  `json:"worker_id,omitempty"`
	Error               string                  `json:"error,omitempty"`
	AttemptCount        int                     `json:"attempt_count"`
	MaxAttempts         int                     `json:"max_attempts"`
	PackageCount        int                     `json:"package_count,omitempty"`
	FindingCount        int                     `json:"finding_count,omitempty"`
	BundleMetadata      *scanner.BundleMetadata `json:"bundle_metadata,omitempty"`
	RequestedAt         time.Time               `json:"requested_at"`
	ClaimedAt           *time.Time              `json:"claimed_at,omitempty"`
	LeaseExpiresAt      *time.Time              `json:"lease_expires_at,omitempty"`
	NextAttemptAt       *time.Time              `json:"next_attempt_at,omitempty"`
	LastAttemptAt       *time.Time              `json:"last_attempt_at,omitempty"`
	LastErrorAt         *time.Time              `json:"last_error_at,omitempty"`
	FinishedAt          *time.Time              `json:"finished_at,omitempty"`
}

type scanStatusDTO struct {
	Scanned         int    `json:"scanned"`
	Scheduled       int    `json:"scheduled"`
	Scanning        int    `json:"scanning"`
	Failed          int    `json:"failed"`
	Paused          int    `json:"paused,omitempty"`
	Canceled        int    `json:"canceled,omitempty"`
	CVEDBVersion    string `json:"cvedb_version,omitempty"`
	CVEDBCreateTime string `json:"cvedb_create_time,omitempty"`
}

type completeScanRequest struct {
	ImageRef       string                       `json:"image_ref,omitempty"`
	ImageDigest    string                       `json:"image_digest,omitempty"`
	Platform       string                       `json:"platform,omitempty"`
	ScannerProfile string                       `json:"scanner_profile,omitempty"`
	PackageCount   int                          `json:"package_count"`
	Packages       []scanner.Package            `json:"packages,omitempty"`
	Secrets        []scanner.SecretFinding      `json:"secrets,omitempty"`
	Signature      *scanner.SignatureResult     `json:"signature,omitempty"`
	Layers         *scanner.ImageLayerMetadata  `json:"layers,omitempty"`
	FileRisks      *scanner.ImageFileRiskReport `json:"file_risks,omitempty"`
	ConfigChecks   *scanner.ImageConfigCheckReport `json:"config_checks,omitempty"`
	Findings       []scanner.Finding            `json:"findings"`
	Engines        []completeScanEngine         `json:"engines,omitempty"`
	BundleMetadata *scanner.BundleMetadata      `json:"bundle_metadata,omitempty"`
}

type completeScanEngine struct {
	Engine   string        `json:"engine"`
	Duration time.Duration `json:"duration_ns,omitempty"`
	Error    string        `json:"error,omitempty"`
}

type scanImageIdentity struct {
	Ref            string
	NormalizedRef  string
	Repository     string
	Tag            string
	Digest         string
	Platform       string
	ScannerProfile string
	BundleVersion  string
	BundleHash     string
	BundleMetadata string
}

func sanitizeSecretFindings(secrets []scanner.SecretFinding) []scanner.SecretFinding {
	if len(secrets) == 0 {
		return nil
	}
	out := make([]scanner.SecretFinding, 0, len(secrets))
	for _, secret := range secrets {
		secret.Engine = strings.TrimSpace(secret.Engine)
		secret.RuleID = strings.TrimSpace(secret.RuleID)
		secret.Category = strings.TrimSpace(secret.Category)
		secret.Severity = strings.ToLower(strings.TrimSpace(secret.Severity))
		secret.Title = strings.TrimSpace(secret.Title)
		secret.Target = strings.TrimSpace(secret.Target)
		secret.Path = strings.TrimSpace(secret.Path)
		secret.MatchSHA256 = normalizeSecretSHA256(secret.MatchSHA256)
		secret.MatchRedacted = normalizeSecretRedacted(secret.MatchRedacted)
		out = append(out, secret)
	}
	return out
}

func normalizeSecretSHA256(value string) string {
	value = strings.TrimSpace(value)
	raw, ok := strings.CutPrefix(value, "sha256:")
	if !ok || len(raw) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return ""
	}
	return "sha256:" + strings.ToLower(raw)
}

func normalizeSecretRedacted(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if value == "[redacted]" {
		return value
	}
	size, ok := strings.CutPrefix(value, "[redacted:")
	if ok && strings.HasSuffix(size, "]") {
		size = strings.TrimSuffix(size, "]")
		if _, err := strconv.Atoi(size); err == nil {
			return value
		}
	}
	return "[redacted]"
}

func sanitizeSignatureResult(signature *scanner.SignatureResult) *scanner.SignatureResult {
	if signature == nil {
		return nil
	}
	out := *signature
	out.ImageRef = strings.TrimSpace(out.ImageRef)
	out.Status = normalizeSignatureStatus(out.Status, out.Signed, out.Trusted)
	out.Identity = strings.TrimSpace(out.Identity)
	out.Issuer = strings.TrimSpace(out.Issuer)
	out.RekorLog = strings.TrimSpace(out.RekorLog)
	out.Reason = strings.TrimSpace(out.Reason)
	out.Error = strings.TrimSpace(out.Error)
	attestations := make([]string, 0, len(out.Attestations))
	for _, attestation := range out.Attestations {
		attestation = strings.TrimSpace(attestation)
		if attestation != "" {
			attestations = append(attestations, attestation)
		}
	}
	out.Attestations = attestations
	return &out
}

func normalizeSignatureStatus(status string, signed, trusted bool) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "trusted", "untrusted", "unsigned", "unavailable", "skipped", "error":
		return strings.ToLower(strings.TrimSpace(status))
	}
	if trusted {
		return "trusted"
	}
	if signed {
		return "untrusted"
	}
	return "unsigned"
}

// Enqueue creates a pending scan job.
func (h *ScanJobs) Enqueue(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	var req EnqueueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.TargetType = normalizeScanTargetType(req.TargetType)
	req.TargetRef = strings.TrimSpace(req.TargetRef)
	req.SourceType = handler.NormalizeScanSourceType(req.SourceType, req.TargetType)
	req.SourceRef = strings.TrimSpace(req.SourceRef)
	req.Platform = strings.TrimSpace(req.Platform)
	req.InventoryHash = strings.TrimSpace(req.InventoryHash)
	req.MaxAttempts = normalizeScanJobMaxAttempts(req.MaxAttempts)
	if req.TargetRef == "" {
		jsonError(w, http.StatusBadRequest, "target_ref required")
		return
	}
	if !validScanTargetType(req.TargetType) {
		jsonError(w, http.StatusBadRequest, "unsupported target_type")
		return
	}
	if !handler.ValidScanSourceType(req.SourceType) {
		jsonError(w, http.StatusBadRequest, "unsupported source_type")
		return
	}
	if err := validateExecutableScanRequest(req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, err := h.upsertScanTarget(r.Context(), nil, subj.OrgID, handler.ScanTargetUpsert{
		TargetType:      req.TargetType,
		TargetRef:       req.TargetRef,
		TargetClusterID: req.TargetClusterID,
		SourceType:      req.SourceType,
		SourceRef:       req.SourceRef,
		ImageRef:        imageRefForTarget(req.TargetType, req.TargetRef, ""),
		Platform:        req.Platform,
		InventoryHash:   req.InventoryHash,
		Metadata:        req.Metadata,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "scan target: "+err.Error())
		return
	}

	id := uuid.New()
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO scan_jobs (id, org_id, target_id, status, requested_by, max_attempts)
VALUES ($1, $2, $3, 'pending', $4, $5)`,
		id, subj.OrgID, target.ID, subj.UserID, req.MaxAttempts); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "scan-job.enqueue",
		TargetKind: "scan-job",
		TargetID:   id.String(),
		After: map[string]any{
			"target_id":         target.ID.String(),
			"target_type":       target.Type,
			"target_ref":        target.Ref,
			"target_cluster_id": target.ClusterID,
			"source_type":       target.SourceType,
			"source_ref":        target.SourceRef,
			"image_ref":         target.ImageRef,
			"platform":          target.Platform,
			"inventory_hash":    target.InventoryHash,
			"max_attempts":      req.MaxAttempts,
		},
	})
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"id": id, "status": "pending", "target_id": target.ID, "target_type": target.Type, "target_ref": target.Ref,
	})
}

func (h *ScanJobs) upsertScanTarget(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, req handler.ScanTargetUpsert) (handler.ScanTarget, error) {
	return handler.UpsertScanTarget(ctx, h.db.Pool(), tx, orgID, req)
}

func (h *ScanJobs) loadScanTarget(ctx context.Context, tx pgx.Tx, id uuid.UUID) (handler.ScanTarget, error) {
	return handler.LoadScanTarget(ctx, h.db.Pool(), tx, id)
}

// List returns recent scan jobs for the calling org.
func (h *ScanJobs) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	targetType := strings.TrimSpace(r.URL.Query().Get("target_type"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	var clusterID *uuid.UUID
	if raw := strings.TrimSpace(r.URL.Query().Get("cluster_id")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid cluster_id")
			return
		}
		clusterID = &parsed
	}
	if targetType != "" && !validScanTargetType(targetType) {
		jsonError(w, http.StatusBadRequest, "unsupported target_type")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT sj.id, sj.org_id, st.id, st.type, st.ref, st.cluster_id,
       st.source_type, COALESCE(st.source_ref, ''),
       COALESCE(st.image_ref, ''),
       COALESCE(st.platform, ''),
       COALESCE(st.inventory_hash, ''),
       st.registry_id, COALESCE(st.image_digest, ''), st.metadata,
       COALESCE(sj.enqueue_reason,''), COALESCE(sj.registry_policy_hash,''), COALESCE(sj.vulndb_bundle_version,''),
       sj.status, COALESCE(sj.worker_id,''), COALESCE(sj.error,''),
       COALESCE(sj.attempt_count,0), COALESCE(sj.max_attempts,3),
       COALESCE(sj.package_count,0), COALESCE(sj.finding_count,0),
       sj.bundle_metadata, sj.requested_at, sj.claimed_at, sj.lease_expires_at,
       sj.next_attempt_at, sj.last_attempt_at, sj.last_error_at, sj.finished_at
  FROM scan_jobs sj
  JOIN scan_targets st ON st.id = sj.target_id
 WHERE sj.org_id = $1
   AND ($2 = '' OR st.type = $2)
   AND ($3 = '' OR sj.status = $3)
   AND ($4::uuid IS NULL OR st.cluster_id = $4)
 ORDER BY sj.requested_at DESC
 LIMIT 200`, subj.OrgID, targetType, status, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []JobView{}
	for rows.Next() {
		var j JobView
		var bundleRaw, metadataRaw []byte
		if err := rows.Scan(&j.ID, &j.OrgID, &j.TargetID, &j.TargetType, &j.TargetRef, &j.TargetClusterID,
			&j.SourceType, &j.SourceRef, &j.ImageRef, &j.Platform, &j.InventoryHash,
			&j.RegistryID, &j.ImageDigest, &metadataRaw, &j.EnqueueReason, &j.RegistryPolicyHash, &j.VulnDBBundleVersion,
			&j.Status, &j.WorkerID, &j.Error, &j.AttemptCount, &j.MaxAttempts, &j.PackageCount, &j.FindingCount,
			&bundleRaw,
			&j.RequestedAt, &j.ClaimedAt, &j.LeaseExpiresAt, &j.NextAttemptAt, &j.LastAttemptAt, &j.LastErrorAt, &j.FinishedAt); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(bundleRaw) > 0 {
			var metadata scanner.BundleMetadata
			if err := json.Unmarshal(bundleRaw, &metadata); err != nil {
				jsonError(w, http.StatusInternalServerError, "invalid scan job bundle metadata")
				return
			}
			j.BundleMetadata = &metadata
		}
		j.Metadata = handler.NormalizedJSONRaw(metadataRaw)
		out = append(out, j)
	}
	metrics, err := handler.ScanQueueMetrics(r.Context(), h.db.Pool(), subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"jobs": out, "queue_metrics": metrics})
}

// Status returns NeuVector-style aggregate scan lifecycle status for the caller's org.
func (h *ScanJobs) Status(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	out := scanStatusDTO{}
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT COUNT(*) FILTER (WHERE status = 'completed')::int,
       COUNT(*) FILTER (WHERE status = 'pending')::int,
       COUNT(*) FILTER (WHERE status = 'running')::int,
       COUNT(*) FILTER (WHERE status = 'failed')::int,
       COUNT(*) FILTER (WHERE status = 'paused')::int,
       COUNT(*) FILTER (WHERE status = 'canceled')::int
  FROM scan_jobs
 WHERE org_id = $1`, subj.OrgID).Scan(&out.Scanned, &out.Scheduled, &out.Scanning, &out.Failed, &out.Paused, &out.Canceled); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.db.Pool().QueryRow(r.Context(), `
SELECT COALESCE(bundle_version, ''), COALESCE(exported_at, '')
  FROM (
        SELECT sj.bundle_metadata->>'bundle_version' AS bundle_version,
               sj.bundle_metadata->>'exported_at' AS exported_at,
               COALESCE(sj.finished_at, sj.requested_at) AS observed_at,
               1 AS priority
          FROM scan_jobs sj
         WHERE sj.org_id = $1
           AND sj.bundle_metadata IS NOT NULL
           AND sj.bundle_metadata <> '{}'::jsonb
        UNION ALL
        SELECT ch.metadata->'vulndb'->>'bundle_version' AS bundle_version,
               ch.metadata->'vulndb'->>'exported_at' AS exported_at,
               ch.last_seen_at AS observed_at,
               2 AS priority
          FROM component_heartbeats ch
         WHERE ch.org_id = $1
           AND ch.component = 'scanner'
           AND ch.last_seen_at > NOW() - INTERVAL '24 hours'
       ) bundle
 WHERE COALESCE(bundle_version, '') <> '' OR COALESCE(exported_at, '') <> ''
 ORDER BY priority, observed_at DESC
 LIMIT 1`, subj.OrgID).Scan(&out.CVEDBVersion, &out.CVEDBCreateTime)
	httpx.WriteJSON(w, http.StatusOK, out)
}

// Claim atomically claims one pending job for a worker.
func (h *ScanJobs) Claim(w http.ResponseWriter, r *http.Request) {
	token, ok := handler.ScannerTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "scanner token required")
		return
	}
	workerID := handler.ScannerWorkerIDFromRequest(token, r)
	targetTypes := scannerClaimTargetTypesFromRequest(r)

	var (
		id              uuid.UUID
		orgID           uuid.UUID
		targetID        uuid.UUID
		leaseExpiresAt  time.Time
		attemptCount    int
		maxAttempts     int
		platform        string
		targetType      string
		targetRef       string
		targetClusterID *uuid.UUID
		sourceType      string
		sourceRef       string
		imageDigest     string
		inventoryHash   string
		evidenceID      *uuid.UUID
	)
	row := h.db.Pool().QueryRow(r.Context(), `
WITH claimed AS (
UPDATE scan_jobs sj
   SET status           = 'running',
       worker_id        = $1,
       claimed_at       = NOW(),
       lease_expires_at = NOW() + $3::interval,
       attempt_count    = COALESCE(attempt_count, 0) + 1,
       last_attempt_at  = NOW(),
       next_attempt_at  = NULL,
       error            = NULL,
       finished_at      = NULL
 WHERE sj.id = (
   SELECT sj2.id
     FROM scan_jobs sj2
     JOIN scan_targets st2 ON st2.id = sj2.target_id
    WHERE sj2.org_id = $2
      AND (cardinality($4::text[]) = 0 OR st2.type = ANY($4::text[]))
      AND (
        (
          sj2.status = 'pending'
          AND COALESCE(sj2.attempt_count, 0) < COALESCE(sj2.max_attempts, 3)
          AND (sj2.next_attempt_at IS NULL OR sj2.next_attempt_at <= NOW())
        )
        OR (
          sj2.status = 'running'
          AND (
            (sj2.lease_expires_at IS NOT NULL AND sj2.lease_expires_at < NOW())
            OR (sj2.lease_expires_at IS NULL AND sj2.claimed_at IS NOT NULL AND sj2.claimed_at < NOW() - $3::interval)
          )
        )
      )
    ORDER BY sj2.requested_at, sj2.id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
 )
 RETURNING sj.*
)
SELECT c.id, c.org_id, st.id, c.lease_expires_at,
       COALESCE(c.attempt_count, 0), COALESCE(c.max_attempts, 3),
       COALESCE(st.platform, ''),
       st.type, st.ref, st.cluster_id,
       st.source_type, COALESCE(st.source_ref, ''), COALESCE(st.image_digest, ''), COALESCE(st.inventory_hash, ''),
       ev.id
  FROM claimed c
  JOIN scan_targets st ON st.id = c.target_id
  LEFT JOIN LATERAL (
      SELECT id
        FROM scan_evidence
       WHERE org_id = c.org_id
         AND evidence_type = 'package-inventory'
         AND (
              scan_target_id = st.id
              -- For image targets, also reuse package evidence collected for
              -- the SAME image under another target (e.g. the runtime-agent
              -- collected it off a running container, keyed by digest). Match
              -- on either the tag ref or the resolved digest. This lets a
              -- discoverer image target that isn't in any registry still be
              -- scanned from local evidence instead of failing on a registry
              -- pull. NOTE: requires st.image_digest to be populated for the
              -- digest path to connect to runtime-agent evidence (see plan F1).
              OR (st.type = 'image' AND target_ref = st.ref)
              OR (st.type = 'image' AND st.image_digest <> '' AND target_ref = st.image_digest)
             )
         AND (COALESCE(st.inventory_hash, '') = '' OR inventory_hash = st.inventory_hash)
       ORDER BY (scan_target_id = st.id) DESC, observed_at DESC
       LIMIT 1
  ) ev ON st.type IN ('host', 'workload', 'platform', 'serverless', 'repository')
      OR st.type = 'image'`,
		workerID, token.OrgID, handler.ScannerJobLeaseInterval, targetTypes)
	if err := row.Scan(&id, &orgID, &targetID, &leaseExpiresAt, &attemptCount, &maxAttempts, &platform, &targetType, &targetRef, &targetClusterID, &sourceType, &sourceRef, &imageDigest, &inventoryHash, &evidenceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{
		"id": id, "org_id": orgID, "target_id": targetID, "platform": platform,
		"target_type": targetType, "target_ref": targetRef, "target_cluster_id": targetClusterID,
		"source_type": sourceType, "source_ref": sourceRef, "image_digest": imageDigest, "inventory_hash": inventoryHash,
		"evidence_id": evidenceID, "lease_expires_at": leaseExpiresAt,
		"attempt_count": attemptCount, "max_attempts": maxAttempts,
	})
}

// RenewLease extends the lease for a running job owned by this scanner instance.
func (h *ScanJobs) RenewLease(w http.ResponseWriter, r *http.Request) {
	token, ok := handler.ScannerTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "scanner token required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	workerID := handler.ScannerWorkerIDFromRequest(token, r)
	var (
		leaseExpiresAt time.Time
		attemptCount   int
		maxAttempts    int
	)
	if err := h.db.Pool().QueryRow(r.Context(), `
UPDATE scan_jobs
   SET lease_expires_at = NOW() + $4::interval
 WHERE id = $1
   AND org_id = $2
   AND status = 'running'
   AND worker_id = $3
 RETURNING lease_expires_at, COALESCE(attempt_count, 0), COALESCE(max_attempts, 3)`,
		id, token.OrgID, workerID, handler.ScannerJobLeaseInterval).Scan(&leaseExpiresAt, &attemptCount, &maxAttempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusConflict, "job must be running and claimed by this worker before renewal")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":           "running",
		"lease_expires_at": leaseExpiresAt,
		"attempt_count":    attemptCount,
		"max_attempts":     maxAttempts,
	})
}

// Complete records scanner results. Image targets write canonical image scan
// result rows; non-image targets write directly to the general findings graph.
func (h *ScanJobs) Complete(w http.ResponseWriter, r *http.Request) {
	token, ok := handler.ScannerTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "scanner token required")
		return
	}
	requestWorkerID := handler.ScannerWorkerIDFromRequest(token, r)
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid job id")
		return
	}

	// Cap the request body like the sibling ingest handlers (workload_packages
	// uses 16MiB) so a scanner-token holder cannot OOM the API with a huge POST.
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)

	var body completeScanRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(body.Packages) > 0 && body.PackageCount == 0 {
		body.PackageCount = len(body.Packages)
	}
	body.Secrets = sanitizeSecretFindings(body.Secrets)
	body.Signature = sanitizeSignatureResult(body.Signature)

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var (
		orgID                  uuid.UUID
		status                 string
		workerID               string
		jobVulnDBBundleVersion string
		target                 handler.ScanTarget
	)
	if err := tx.QueryRow(r.Context(),
		`SELECT sj.org_id,
		        sj.status,
		        COALESCE(sj.worker_id, ''),
		        COALESCE(sj.vulndb_bundle_version, ''),
		        st.id, st.org_id, st.cluster_id, st.type, st.ref, st.source_type,
		        COALESCE(st.source_ref, ''), COALESCE(st.image_ref, ''),
		        COALESCE(st.image_digest, ''),
		        st.registry_id, COALESCE(st.platform, ''),
		        COALESCE(st.inventory_hash, '')
		   FROM scan_jobs sj
		   JOIN scan_targets st ON st.id = sj.target_id
		  WHERE sj.id = $1
		  FOR UPDATE OF sj`, id,
	).Scan(&orgID, &status, &workerID, &jobVulnDBBundleVersion,
		&target.ID, &target.OrgID, &target.ClusterID, &target.Type, &target.Ref, &target.SourceType,
		&target.SourceRef, &target.ImageRef, &target.ImageDigest, &target.RegistryID, &target.Platform, &target.InventoryHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "job not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if orgID != token.OrgID {
		jsonError(w, http.StatusForbidden, "wrong org")
		return
	}
	if status == "completed" {
		httpx.WriteJSON(w, 200, map[string]any{
			"status":            "completed",
			"findings_inserted": 0,
			"idempotent":        true,
		})
		return
	}
	if status == "canceled" {
		httpx.WriteJSON(w, 200, map[string]any{
			"status":  "canceled",
			"dropped": true,
		})
		return
	}
	if status != "running" {
		jsonError(w, http.StatusConflict, "job must be running before completion")
		return
	}
	if workerID != requestWorkerID {
		jsonError(w, http.StatusConflict, "job claimed by different worker")
		return
	}

	identity, err := scanCompletionImageIdentity(target, body, jobVulnDBBundleVersion)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if target.Type == "image" {
		// Node-local evidence scans (runtime-agent scans a RUNNING container by its
		// image DIGEST, NV-style) arrive with no registry ref → Repository/Tag empty
		// and Ref="sha256:…". Resolve the friendly repo:tag from the K8s workload map
		// so the asset + scan result are named (and collapse against any registry scan
		// of the same image) instead of showing as a bare hash.
		resolveEvidenceImageName(r.Context(), tx, orgID, &identity)
		target.ImageRef = identity.Ref
		target.ImageDigest = identity.Digest
		target.Platform = identity.Platform
	} else {
		if v := strings.TrimSpace(body.ImageRef); v != "" {
			target.ImageRef = v
		}
		if v := strings.TrimSpace(body.ImageDigest); v != "" {
			target.ImageDigest = v
		}
		if v := strings.TrimSpace(body.Platform); v != "" {
			target.Platform = v
		}
	}

	var bundleMetadataJSON *string
	if body.BundleMetadata != nil {
		raw, err := json.Marshal(body.BundleMetadata)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid bundle metadata")
			return
		}
		encoded := string(raw)
		bundleMetadataJSON = &encoded
	}

	if _, err := tx.Exec(r.Context(), `
UPDATE scan_targets
   SET last_seen_at = NOW(),
       image_ref = COALESCE(NULLIF($2, ''), image_ref),
       image_digest = COALESCE(NULLIF($3, ''), image_digest),
       platform = COALESCE(NULLIF($4, ''), platform),
       inventory_hash = COALESCE(NULLIF($5, ''), inventory_hash)
 WHERE id = $1`,
		target.ID, target.ImageRef, target.ImageDigest, target.Platform, target.InventoryHash); err != nil {
		jsonError(w, http.StatusInternalServerError, "target update: "+err.Error())
		return
	}

	assetID, err := upsertScanAsset(r.Context(), tx, orgID, target, identity, body.Signature, body.Layers)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "asset upsert: "+err.Error())
		return
	}

	var imageScanResultID uuid.UUID
	if target.Type == "image" {
		imageScanResultID, err = upsertImageScanResult(r.Context(), tx, orgID, id, target, identity, assetID, body.PackageCount, len(body.Findings))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "image scan result: "+err.Error())
			return
		}
		engines := completeScanEnginesToResults(body.Engines)
		if len(body.Packages) > 0 || len(body.Secrets) > 0 || body.Signature != nil || body.Layers != nil || body.FileRisks != nil || body.ConfigChecks != nil || successfulEngineRan(engines, "trivy") {
			if err := upsertImageScanArtifacts(r.Context(), tx, orgID, imageScanResultID, identity, scanner.ScanResult{
				ImageRef:       identity.Ref,
				Packages:       body.Packages,
				Secrets:        body.Secrets,
				Signature:      body.Signature,
				Layers:         body.Layers,
				FileRisks:      body.FileRisks,
				ConfigChecks:   body.ConfigChecks,
				Findings:       body.Findings,
				Engines:        engines,
				BundleMetadata: body.BundleMetadata,
			}); err != nil {
				jsonError(w, http.StatusInternalServerError, "image sbom: "+err.Error())
				return
			}
		}
	}

	activeVulnProfiles, err := loadActiveVulnerabilityProfiles(r.Context(), tx, orgID, target.ClusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "vulnerability profiles: "+err.Error())
		return
	}

	clusterScopes := []*uuid.UUID{}
	if target.Type != "image" {
		var err error
		clusterScopes, err = h.scanTargetClusters(r.Context(), tx, orgID, target, identity)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "cluster scope: "+err.Error())
			return
		}
	}

	findingsInserted := 0
	currentImageFindingKeys := make([]string, 0, len(body.Findings))
	for _, f := range body.Findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" || sev == "negligible" || sev == "unknown" {
			sev = "info"
		}
		risk := f.RiskScore
		if risk == 0 {
			risk = handler.SeverityToScore(sev, f.CVSSBase, f.KEVListed)
		}
		engines, _ := json.Marshal(f.Engines)
		findingKey := scanFindingStableKey(f)
		vulnProfileDecision := vulnerabilityProfileDecisionForFinding(activeVulnProfiles, target, identity, f, sev)
		// Apply the vuln-profile verdict, not just record it. Escalate bumps the stored
		// severity/risk (so it counts as critical and re-fires response rules); suppress maps
		// to a non-open lifecycle so the CVE drops out of the open critical/high rollups and
		// does not re-fire. The decision is also stuffed into detail_json below; the image
		// path carries the lifecycle through promoteImageFindingsToWorkloads (which reads that
		// decision), so only the non-image path needs the override threaded into the upsert.
		sev, risk = applyVulnProfileEscalation(vulnProfileDecision, sev, risk)
		lifecycleOverride := vulnProfileLifecycleOverride(vulnProfileDecision)
		imageScanFindingID := uuid.Nil
		imageScanFindingKey := findingKey
		if target.Type == "image" {
			currentImageFindingKeys = append(currentImageFindingKeys, imageScanFindingKey)
			imageScanFindingID = uuid.NewSHA1(uuid.NameSpaceURL, []byte("constellation:image-scan-finding:"+imageScanResultID.String()+":"+imageScanFindingKey))
		}
		detail, _ := json.Marshal(scannerFindingDetail(f, scanFindingContext{
			ScanFindingKey:      findingKey,
			ImageRef:            target.ImageRef,
			ImageDigest:         identity.Digest,
			Platform:            identity.Platform,
			ScannerProfile:      identity.ScannerProfile,
			ImageScanResultID:   imageScanResultID,
			ImageScanFindingID:  imageScanFindingID,
			ImageScanFindingKey: imageScanFindingKey,
			TargetID:            target.ID,
			TargetType:          target.Type,
			TargetRef:           target.Ref,
			TargetClusterID:     target.ClusterID,
			SourceType:          target.SourceType,
			SourceRef:           target.SourceRef,
			TargetMetadata:      target.Metadata,
			BundleMetadata:      body.BundleMetadata,
			VulnProfileDecision: vulnProfileDecision,
		}))
		title := f.Title
		if title == "" {
			title = f.VulnerabilityID
		}
		if title == "" {
			title = "vulnerability"
		}
		canonicalEngine := strings.TrimSpace(f.CanonicalEngine)
		if target.Type == "image" {
			if err := upsertImageScanFinding(r.Context(), tx, orgID, imageScanResultID, imageScanFindingID, imageScanFindingKey, f, sev, risk, canonicalEngine, engines, detail, title); err != nil {
				jsonError(w, http.StatusInternalServerError, "image scan finding: "+err.Error())
				return
			}
			continue
		}
		for _, clusterID := range clusterScopes {
			if err := upsertTargetFinding(r.Context(), tx, orgID, clusterID, assetID, target, findingKey, f, title, sev, risk, canonicalEngine, engines, detail, lifecycleOverride); err != nil {
				jsonError(w, http.StatusInternalServerError, "finding insert: "+err.Error())
				return
			}
			findingsInserted++
		}
	}

	if target.Type == "image" {
		if err := pruneStaleImageScanFindings(r.Context(), tx, orgID, imageScanResultID, currentImageFindingKeys); err != nil {
			jsonError(w, http.StatusInternalServerError, "image finding prune: "+err.Error())
			return
		}
		// Promote image-scan findings into the unified `findings` table, attributed to
		// each cluster running this image (via image_workload_links). This is what makes
		// image vulnerabilities surface on the cluster dashboard and Findings page, which
		// read only FROM findings. Mirrors NeuVector's per-asset vuln model where a CVE is
		// pivoted onto every affected running asset. Re-scans replace prior promotions.
		promoted, err := promoteImageFindingsToWorkloads(r.Context(), tx, orgID, imageScanResultID, target.ID, assetID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "image finding promotion: "+err.Error())
			return
		}
		findingsInserted += promoted
	}

	if _, err := tx.Exec(r.Context(), `
	UPDATE scan_jobs
	   SET status           = 'completed',
	       package_count    = $1,
	       finding_count    = $2,
	       bundle_metadata = COALESCE($3::jsonb, bundle_metadata),
	       finished_at      = NOW(),
	       lease_expires_at = NULL
	 WHERE id = $4`, body.PackageCount, len(body.Findings), bundleMetadataJSON, id); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	after := map[string]any{
		"finding_count":     len(body.Findings),
		"findings_inserted": findingsInserted,
		"asset_id":          assetID.String(),
		"target_id":         target.ID.String(),
		"target_type":       target.Type,
		"target_ref":        target.Ref,
	}
	if target.Type == "image" {
		after["image_scan_result_id"] = imageScanResultID.String()
		after["image_digest"] = identity.Digest
		after["platform"] = identity.Platform
		after["scanner_profile"] = identity.ScannerProfile
	}
	if body.BundleMetadata != nil {
		after["vulndb_bundle"] = body.BundleMetadata
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &token.OrgID,
		Action:     "scan-job.complete",
		TargetKind: "scan-job",
		TargetID:   id.String(),
		After:      after,
	})
	// E1: evaluate the org's enabled EventScan response rules against this scan result and
	// apply the ordered matching actions (NeuVector EventCVEReport parity). Runs after the
	// txn has committed so a buggy rule can never roll back the scan ingest; panic-isolated
	// and best-effort like the runtime path's dispatchResponseRules.
	if h.evalResponseRules != nil {
		h.dispatchScanResponseRules(r.Context(), token.OrgID, target, identity, body.Findings)
	}
	httpx.WriteJSON(w, 200, map[string]any{
		"status":               "completed",
		"asset_id":             assetID,
		"image_scan_result_id": imageScanResultID,
		"findings_inserted":    findingsInserted,
	})
}

func scanCompletionImageIdentity(target handler.ScanTarget, body completeScanRequest, jobBundleVersion string) (scanImageIdentity, error) {
	if target.Type != "image" {
		return scanImageIdentity{}, nil
	}
	ref := strings.TrimSpace(body.ImageRef)
	if ref == "" {
		ref = strings.TrimSpace(target.ImageRef)
	}
	if ref == "" {
		ref = strings.TrimSpace(target.Ref)
	}

	identity := imageid.Parse(ref)
	targetIdentity := imageid.Parse(target.Ref)
	digest := strings.TrimSpace(body.ImageDigest)
	if digest == "" {
		digest = identity.Digest
	}
	if digest == "" {
		digest = strings.TrimSpace(target.ImageDigest)
	}
	if digest == "" {
		digest = targetIdentity.Digest
	}
	if digest == "" {
		return scanImageIdentity{}, fmt.Errorf("image_digest required for image scan completion")
	}
	if !strings.HasPrefix(digest, "sha256:") {
		return scanImageIdentity{}, fmt.Errorf("image_digest must be sha256")
	}
	if identity.Repository == "" {
		identity = targetIdentity
	}
	normalized := identity.Normalized
	if identity.Repository != "" && identity.Digest == "" {
		normalized = identity.Repository + "@" + digest
	}
	if normalized == "" {
		normalized = ref
	}
	platform := strings.TrimSpace(body.Platform)
	if platform == "" {
		platform = strings.TrimSpace(target.Platform)
	}
	scannerProfile := strings.TrimSpace(body.ScannerProfile)
	if scannerProfile == "" {
		scannerProfile = "default"
	}
	bundleVersion := strings.TrimSpace(jobBundleVersion)
	bundleHash := ""
	bundleMetadata := "{}"
	if body.BundleMetadata != nil {
		if v := strings.TrimSpace(body.BundleMetadata.BundleVersion); v != "" {
			bundleVersion = v
		}
		bundleHash = strings.TrimSpace(body.BundleMetadata.PayloadHash)
		if raw, err := json.Marshal(body.BundleMetadata); err == nil {
			bundleMetadata = string(raw)
		}
	}
	return scanImageIdentity{
		Ref:            ref,
		NormalizedRef:  normalized,
		Repository:     identity.Repository,
		Tag:            identity.Tag,
		Digest:         digest,
		Platform:       platform,
		ScannerProfile: scannerProfile,
		BundleVersion:  bundleVersion,
		BundleHash:     bundleHash,
		BundleMetadata: bundleMetadata,
	}, nil
}

func upsertScanAsset(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, target handler.ScanTarget, identity scanImageIdentity, signature *scanner.SignatureResult, layers *scanner.ImageLayerMetadata) (uuid.UUID, error) {
	assetID := uuid.New()
	kind := assetKindForScanTarget(target.Type)
	name := target.Ref
	digest := "scan-target:" + target.ID.String()
	labels := map[string]any{
		"scan_target_id": target.ID.String(),
		"target_type":    target.Type,
		"target_ref":     target.Ref,
		"source_type":    target.SourceType,
	}
	if target.SourceRef != "" {
		labels["source_ref"] = target.SourceRef
	}
	if metadata := handler.NormalizedJSONRaw(target.Metadata); len(metadata) > 0 {
		labels["scan_target_metadata"] = metadata
	}
	if target.Type == "image" {
		name = identity.Digest
		digest = identity.Digest
		labels["image_ref"] = identity.Ref
		labels["image_digest"] = identity.Digest
		labels["image_ref_normalized"] = identity.NormalizedRef
		labels["image_repository"] = identity.Repository
		labels["image_tag"] = identity.Tag
		labels["platform"] = identity.Platform
		labels["scanner_profile"] = identity.ScannerProfile
	}
	labelsRaw, _ := json.Marshal(labels)
	if err := tx.QueryRow(ctx, `
INSERT INTO assets (id, org_id, cluster_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'medium')
ON CONFLICT (org_id, kind, name, digest) DO UPDATE
    SET cluster_id = COALESCE(EXCLUDED.cluster_id, assets.cluster_id),
        labels = assets.labels || EXCLUDED.labels,
        last_seen_at = NOW()
RETURNING id`, assetID, orgID, target.ClusterID, kind, name, digest, string(labelsRaw)).Scan(&assetID); err != nil {
		return uuid.Nil, err
	}
	if target.Type == "image" {
		registryHost, repositoryName := registryAndRepository(identity.Repository)
		if registryHost == "" {
			registryHost = "unknown"
		}
		if repositoryName == "" {
			repositoryName = identity.Repository
		}
		if repositoryName == "" {
			repositoryName = identity.Digest
		}
		layersJSON, architecturesJSON, sizeBytes, layersPresent := imageLayerInfo(layers)
		signed, signatureInfo := imageSignatureInfo(signature)
		signaturePresent := signature != nil
		if _, err := tx.Exec(ctx, `
INSERT INTO images (asset_id, registry, repository, tag, digest, layers, architectures, size_bytes, signed, signature_info, pulled_at)
VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6::jsonb, $7::jsonb, NULLIF($8, 0), $9, $10::jsonb, NOW())
ON CONFLICT (asset_id) DO UPDATE
   SET registry = EXCLUDED.registry,
       repository = EXCLUDED.repository,
       tag = EXCLUDED.tag,
       digest = EXCLUDED.digest,
       layers = CASE WHEN $11 THEN EXCLUDED.layers ELSE images.layers END,
       architectures = CASE WHEN $11 THEN EXCLUDED.architectures ELSE images.architectures END,
       size_bytes = CASE WHEN $11 THEN EXCLUDED.size_bytes ELSE images.size_bytes END,
       signed = CASE WHEN $12 THEN EXCLUDED.signed ELSE images.signed END,
       signature_info = CASE WHEN $12 THEN EXCLUDED.signature_info ELSE images.signature_info END,
       pulled_at = NOW()`,
			assetID, registryHost, repositoryName, identity.Tag, identity.Digest, layersJSON, architecturesJSON, sizeBytes, signed, signatureInfo, layersPresent, signaturePresent); err != nil {
			return uuid.Nil, err
		}
	}
	return assetID, nil
}

func imageLayerInfo(layers *scanner.ImageLayerMetadata) (string, string, int64, bool) {
	if layers == nil || layers.Status != "observed" {
		return "[]", "[]", 0, false
	}
	layersRaw, err := json.Marshal(layers.Layers)
	if err != nil {
		layersRaw = []byte("[]")
	}
	architecturesRaw, err := json.Marshal(layers.Architectures)
	if err != nil {
		architecturesRaw = []byte("[]")
	}
	return string(layersRaw), string(architecturesRaw), layers.TotalSizeBytes, true
}

func imageSignatureInfo(signature *scanner.SignatureResult) (bool, string) {
	if signature == nil {
		return false, "{}"
	}
	raw, err := json.Marshal(signature)
	if err != nil {
		return signature.Signed, "{}"
	}
	return signature.Signed, string(raw)
}

// resolveEvidenceImageName fills a human repo:tag for an evidence-scanned image whose
// ref is only a content digest. The node-local evidence path has no registry ref, so
// identity arrives with Repository/Tag empty and Ref="sha256:…". K8s knows the friendly
// name via image_workload_links (digest → repository/tag); look it up so the asset and
// scan result are named. Best-effort: unresolvable digests (e.g. a container already
// gone) are left as-is and get swept by the orphan retention monitor.
func resolveEvidenceImageName(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, identity *scanImageIdentity) {
	if identity == nil || identity.Repository != "" || identity.Digest == "" {
		return
	}
	// Two sources, in order:
	//  1. a workload link that already carries a repo:tag (digests match).
	//  2. the link's DEPLOYMENT image_refs — needed because the runtime-agent keys
	//     evidence by the image's content/config digest while K8s records the registry
	//     manifest digest; the two differ for pulled images, so digest-equality alone
	//     misses them. The workload relationship (link.deployment_id) is stable, so we
	//     pull the deployment's named ref regardless of which digest form it holds.
	var named string
	err := tx.QueryRow(ctx, `
SELECT COALESCE(
  (SELECT l.image_ref FROM image_workload_links l
    WHERE l.org_id = $1 AND (l.image_digest = $2 OR l.image_digest = $3)
      AND COALESCE(l.image_repository,'') <> '' AND l.image_ref !~ '^sha256:'
    ORDER BY length(l.image_ref) LIMIT 1),
  (SELECT ref FROM image_workload_links l
     JOIN deployments d ON d.id = l.deployment_id
     CROSS JOIN LATERAL unnest(d.image_refs) AS ref
    WHERE l.org_id = $1 AND (l.image_digest = $2 OR l.image_digest = $3 OR l.image_ref = $2 OR l.image_ref = $3)
      AND ref !~ '^sha256:'
    ORDER BY (ref ~ '/[^/@]+:[^/@]+') DESC, length(ref) LIMIT 1),
  '')`, orgID, identity.Digest, identity.Ref).Scan(&named)
	if err != nil {
		return // transient — leave digest-only
	}
	named = strings.TrimSpace(named)
	if named == "" {
		return // unresolvable (e.g. a true infra/pause container) — leave digest-only
	}
	parsed := imageid.Parse(named)
	if parsed.Repository == "" {
		return
	}
	// Keep OUR evidence digest as the identity (it keys the scan result); take only the
	// human repo:tag from the resolved ref.
	identity.Repository = parsed.Repository
	identity.Tag = parsed.Tag
	if parsed.Tag != "" {
		identity.Ref = parsed.Repository + ":" + parsed.Tag
	} else {
		identity.Ref = parsed.Repository
	}
	identity.NormalizedRef = parsed.Repository + "@" + identity.Digest
}

func upsertImageScanResult(ctx context.Context, tx pgx.Tx, orgID, jobID uuid.UUID, target handler.ScanTarget, identity scanImageIdentity, assetID uuid.UUID, packageCount, findingCount int) (uuid.UUID, error) {
	resultID := uuid.New()
	err := tx.QueryRow(ctx, `
INSERT INTO image_scan_results (
    id, org_id, scan_target_id, last_scan_job_id, asset_id,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest,
    platform, scanner_profile, vulndb_bundle_version, vulndb_bundle_hash,
    source_type, source_ref, package_count, finding_count, bundle_metadata, last_scanned_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, NULLIF($9, ''), $10,
    $11, $12, $13, $14,
    NULLIF($15, ''), NULLIF($16, ''), $17, $18, $19::jsonb, NOW(), NOW()
)
ON CONFLICT (
    org_id, image_digest, platform, scanner_profile, vulndb_bundle_version, vulndb_bundle_hash
) DO UPDATE SET
    scan_target_id = EXCLUDED.scan_target_id,
    last_scan_job_id = EXCLUDED.last_scan_job_id,
    asset_id = EXCLUDED.asset_id,
    image_ref = EXCLUDED.image_ref,
    image_ref_normalized = EXCLUDED.image_ref_normalized,
    image_repository = EXCLUDED.image_repository,
    image_tag = EXCLUDED.image_tag,
    source_type = EXCLUDED.source_type,
    source_ref = EXCLUDED.source_ref,
    package_count = EXCLUDED.package_count,
    finding_count = EXCLUDED.finding_count,
    bundle_metadata = EXCLUDED.bundle_metadata,
    last_scanned_at = NOW(),
    updated_at = NOW()
RETURNING id`,
		resultID, orgID, target.ID, jobID, assetID,
		identity.Ref, identity.NormalizedRef, identity.Repository, identity.Tag, identity.Digest,
		identity.Platform, identity.ScannerProfile, identity.BundleVersion, identity.BundleHash,
		target.SourceType, target.SourceRef, packageCount, findingCount, identity.BundleMetadata).Scan(&resultID)
	return resultID, err
}

func completeScanEnginesToResults(engines []completeScanEngine) []scanner.EngineResult {
	if len(engines) == 0 {
		return nil
	}
	out := make([]scanner.EngineResult, 0, len(engines))
	for _, engine := range engines {
		name := strings.ToLower(strings.TrimSpace(engine.Engine))
		if name == "" {
			continue
		}
		out = append(out, scanner.EngineResult{
			Engine:   name,
			Duration: engine.Duration,
			Error:    strings.TrimSpace(engine.Error),
		})
	}
	return out
}

func successfulEngineRan(engines []scanner.EngineResult, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, engine := range engines {
		if strings.ToLower(strings.TrimSpace(engine.Engine)) == name && strings.TrimSpace(engine.Error) == "" {
			return true
		}
	}
	return false
}

func upsertImageScanArtifacts(ctx context.Context, tx pgx.Tx, orgID, resultID uuid.UUID, identity scanImageIdentity, res scanner.ScanResult) error {
	type artifactRecord struct {
		artifactType string
		format       string
		payload      map[string]interface{}
		rowCount     int
	}
	artifacts := []artifactRecord{}
	if len(res.Packages) > 0 {
		packageCount := len(res.Packages)
		inventory := map[string]interface{}{
			"schema_version":  "constellation.package-inventory.v1",
			"image_ref":       identity.Ref,
			"image_digest":    identity.Digest,
			"platform":        identity.Platform,
			"scanner_profile": identity.ScannerProfile,
			"package_count":   packageCount,
			"packages":        res.Packages,
		}
		if res.BundleMetadata != nil {
			inventory["vulndb_bundle"] = res.BundleMetadata
		}
		artifacts = append(artifacts,
			artifactRecord{artifactType: "package-inventory", format: "constellation-package-inventory-v1", payload: inventory, rowCount: packageCount},
			artifactRecord{artifactType: "sbom", format: "cyclonedx-1.6", payload: sbom.CycloneDX1_6("v0.1.0", &res), rowCount: packageCount},
			artifactRecord{artifactType: "sbom", format: "spdx-2.3", payload: sbom.SPDX2_3("v0.1.0", &res), rowCount: packageCount},
		)
	}
	if len(res.Secrets) > 0 || successfulEngineRan(res.Engines, "trivy") {
		secretPayload := map[string]interface{}{
			"schema_version":  "constellation.image-secrets.v1",
			"image_ref":       identity.Ref,
			"image_digest":    identity.Digest,
			"platform":        identity.Platform,
			"scanner_profile": identity.ScannerProfile,
			"status":          "observed",
			"engine":          "trivy",
			"secret_count":    len(res.Secrets),
			"secrets":         res.Secrets,
		}
		if res.BundleMetadata != nil {
			secretPayload["vulndb_bundle"] = res.BundleMetadata
		}
		artifacts = append(artifacts, artifactRecord{artifactType: "secret-scan", format: "constellation-image-secrets-v1", payload: secretPayload, rowCount: len(res.Secrets)})
	}
	if res.Signature != nil {
		signaturePayload := map[string]interface{}{
			"schema_version":  "constellation.image-signature.v1",
			"image_ref":       identity.Ref,
			"image_digest":    identity.Digest,
			"platform":        identity.Platform,
			"scanner_profile": identity.ScannerProfile,
			"signature":       res.Signature,
			"status":          res.Signature.Status,
			"signed":          res.Signature.Signed,
			"trusted":         res.Signature.Trusted,
		}
		if res.BundleMetadata != nil {
			signaturePayload["vulndb_bundle"] = res.BundleMetadata
		}
		artifacts = append(artifacts, artifactRecord{artifactType: "signature-scan", format: "constellation-image-signature-v1", payload: signaturePayload, rowCount: 1})
	}
	if res.Layers != nil {
		layerPayload := map[string]interface{}{
			"schema_version":    "constellation.image-layers.v1",
			"image_ref":         identity.Ref,
			"image_digest":      identity.Digest,
			"platform":          identity.Platform,
			"scanner_profile":   identity.ScannerProfile,
			"layer_count":       len(res.Layers.Layers),
			"layers":            res.Layers.Layers,
			"architectures":     res.Layers.Architectures,
			"manifest_digest":   res.Layers.ManifestDigest,
			"index_digest":      res.Layers.IndexDigest,
			"media_type":        res.Layers.MediaType,
			"config_digest":     res.Layers.ConfigDigest,
			"config_media_type": res.Layers.ConfigMediaType,
			"config_size_bytes": res.Layers.ConfigSizeBytes,
			"selected_platform": res.Layers.SelectedPlatform,
			"total_size_bytes":  res.Layers.TotalSizeBytes,
			"status":            res.Layers.Status,
			"reason":            res.Layers.Reason,
			"error":             res.Layers.Error,
		}
		if res.BundleMetadata != nil {
			layerPayload["vulndb_bundle"] = res.BundleMetadata
		}
		artifacts = append(artifacts, artifactRecord{artifactType: "layer-metadata", format: "constellation-image-layers-v1", payload: layerPayload, rowCount: len(res.Layers.Layers)})
	}
	if res.FileRisks != nil {
		fileRiskPayload := map[string]interface{}{
			"schema_version":  "constellation.image-file-risk.v1",
			"image_ref":       identity.Ref,
			"image_digest":    identity.Digest,
			"platform":        identity.Platform,
			"scanner_profile": identity.ScannerProfile,
			"file_risk_count": len(res.FileRisks.Findings),
			"findings":        res.FileRisks.Findings,
			"manifest_digest": res.FileRisks.ManifestDigest,
			"entry_count":     res.FileRisks.EntryCount,
			"max_findings":    res.FileRisks.MaxFindings,
			"truncated":       res.FileRisks.Truncated,
			"status":          res.FileRisks.Status,
			"reason":          res.FileRisks.Reason,
			"error":           res.FileRisks.Error,
		}
		if res.BundleMetadata != nil {
			fileRiskPayload["vulndb_bundle"] = res.BundleMetadata
		}
		artifacts = append(artifacts, artifactRecord{artifactType: "file-risk", format: "constellation-image-file-risk-v1", payload: fileRiskPayload, rowCount: len(res.FileRisks.Findings)})
	}

	if res.ConfigChecks != nil {
		configChecksPayload := map[string]interface{}{
			"schema_version": "constellation.image-config-checks.v1",
			"image_ref":      identity.Ref,
			"image_digest":   identity.Digest,
			"platform":       identity.Platform,
			"checks":         res.ConfigChecks.Checks,
			"pass_count":     res.ConfigChecks.PassCount,
			"fail_count":     res.ConfigChecks.FailCount,
			"warn_count":     res.ConfigChecks.WarnCount,
			"status":         res.ConfigChecks.Status,
			"reason":         res.ConfigChecks.Reason,
			"error":          res.ConfigChecks.Error,
		}
		artifacts = append(artifacts, artifactRecord{artifactType: "config-checks", format: "constellation-image-config-checks-v1", payload: configChecksPayload, rowCount: len(res.ConfigChecks.Checks)})
	}
	for _, artifact := range artifacts {
		raw, err := json.Marshal(artifact.payload)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		hash := "sha256:" + hex.EncodeToString(sum[:])
		if _, err := tx.Exec(ctx, `
INSERT INTO image_scan_artifacts (
    org_id, image_scan_result_id, artifact_type, format, payload, sha256, package_count
) VALUES (
    $1, $2, $3, $4, $5::jsonb, $6, $7
)
ON CONFLICT (org_id, image_scan_result_id, artifact_type, format) DO UPDATE SET
    payload = EXCLUDED.payload,
    sha256 = EXCLUDED.sha256,
    package_count = EXCLUDED.package_count,
    created_at = NOW()`,
			orgID, resultID, artifact.artifactType, artifact.format, string(raw), hash, artifact.rowCount); err != nil {
			return err
		}
	}
	return nil
}

func upsertImageScanFinding(ctx context.Context, tx pgx.Tx, orgID, resultID, findingID uuid.UUID, findingKey string, f scanner.Finding, severity string, risk int, canonicalEngine string, engines, detail []byte, title string) error {
	_, err := tx.Exec(ctx, `
INSERT INTO image_scan_findings (
    id, org_id, image_scan_result_id, finding_key, external_id, title, description,
    severity, risk_score, canonical_engine, engines,
    package_ecosystem, package_name, package_version, package_purl, fixed_version,
    detail_json, last_seen_at
) VALUES (
    $1, $2, $3, $4, NULLIF($5, ''), $6, $7,
    $8, $9, NULLIF($10, ''), $11::jsonb,
    NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''), NULLIF($16, ''),
    $17::jsonb, NOW()
)
ON CONFLICT (org_id, image_scan_result_id, finding_key) DO UPDATE SET
    external_id = EXCLUDED.external_id,
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    severity = EXCLUDED.severity,
    risk_score = EXCLUDED.risk_score,
    canonical_engine = EXCLUDED.canonical_engine,
    engines = EXCLUDED.engines,
    package_ecosystem = EXCLUDED.package_ecosystem,
    package_name = EXCLUDED.package_name,
    package_version = EXCLUDED.package_version,
    package_purl = EXCLUDED.package_purl,
    fixed_version = EXCLUDED.fixed_version,
    detail_json = EXCLUDED.detail_json,
    last_seen_at = NOW()`,
		findingID, orgID, resultID, findingKey, f.VulnerabilityID, title, f.Description,
		severity, risk, canonicalEngine, string(engines),
		f.Package.Ecosystem, f.Package.Name, f.Package.Version, f.Package.Purl, f.FixedVersion,
		string(detail))
	return err
}

// upsertTargetFinding inserts/updates a unified vulnerability finding for a non-image scan
// target. lifecycleOverride is the vuln-profile suppress verdict ('accepted'/'suppressed', or
// "" for none): on insert it replaces the default 'open'; on update it is applied only when the
// row is still 'open'/'resolved' (i.e. never clobbers a user's manual triage), so a suppressed
// CVE drops out of the open rollups instead of re-opening on every rescan.
func upsertTargetFinding(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, clusterID *uuid.UUID, assetID uuid.UUID, target handler.ScanTarget, findingKey string, f scanner.Finding, title, severity string, risk int, canonicalEngine string, engines, detail []byte, lifecycleOverride string) error {
	var clusterArg any
	if clusterID != nil {
		clusterArg = *clusterID
	}
	var existing uuid.UUID
	err := tx.QueryRow(ctx, `
SELECT id
  FROM findings
 WHERE org_id = $1
   AND kind = 'vulnerability'
   AND COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid) = COALESCE($2::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
   AND scan_target_id = $3
   AND detail_json->>'scan_finding_key' = $4
 ORDER BY last_seen_at DESC
 LIMIT 1`, orgID, clusterArg, target.ID, findingKey).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
UPDATE findings
   SET asset_id = $2,
       cluster_id = $3,
       external_id = NULLIF($4, ''),
       title = $5,
       description = $6,
       severity = $7,
       risk_score = $8,
       canonical_engine = NULLIF($9, ''),
       engines = $10::jsonb,
       detail_json = $11::jsonb,
       scan_target_id = $12,
       target_type = NULLIF($13, ''),
       target_ref = NULLIF($14, ''),
       target_cluster_id = $15,
       source_type = NULLIF($16, ''),
       risk_inputs = CASE WHEN $18::boolean IS NULL THEN risk_inputs
                          ELSE COALESCE(risk_inputs, '{}'::jsonb) || jsonb_build_object('reachable_static', $18::boolean) END,
       last_seen_at = NOW(),
       lifecycle = CASE
                       -- A user accept-risk decision (which stamps accepted_until) always wins
                       -- and survives rescans. A profile-set lifecycle has no accepted_until, so
                       -- it is RE-DERIVED from the current scan's verdict ($19): this lets a
                       -- changed decision take effect (e.g. a prior suppress that is now escalate
                       -- — $19 empty — drops back to 'open' instead of staying 'accepted').
                       WHEN accepted_until IS NOT NULL THEN lifecycle
                       WHEN NULLIF($19, '') IS NOT NULL THEN $19
                       ELSE 'open' END
 WHERE id = $1 AND org_id = $17`,
			existing, assetID, clusterArg, f.VulnerabilityID, title, f.Description,
			severity, risk, canonicalEngine, string(engines), string(detail),
			target.ID, target.Type, target.Ref, target.ClusterID, target.SourceType, orgID, f.Reachable, lifecycleOverride)
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO findings (org_id, cluster_id, asset_id, kind, external_id, title, description,
                      severity, risk_score, lifecycle, canonical_engine, engines, detail_json,
                      scan_target_id, target_type, target_ref, target_cluster_id, source_type,
                      risk_inputs, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, 'vulnerability', NULLIF($4,''), $5, $6,
        $7, $8, COALESCE(NULLIF($18, ''), 'open'), NULLIF($9,''), $10::jsonb, $11::jsonb,
        $12, NULLIF($13,''), NULLIF($14,''), $15, NULLIF($16,''),
        CASE WHEN $17::boolean IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('reachable_static', $17::boolean) END,
        NOW(), NOW())`,
		orgID, clusterArg, assetID, f.VulnerabilityID, title, f.Description,
		severity, risk, canonicalEngine, string(engines), string(detail),
		target.ID, target.Type, target.Ref, target.ClusterID, target.SourceType, f.Reachable, lifecycleOverride)
	return err
}

// promoteImageFindingsToWorkloads mirrors the just-upserted image_scan_findings for a
// scan result into the unified `findings` table, one row per (finding, distinct running
// cluster) that has a workload using the image (per image_workload_links). Only LINKED,
// running images produce rows — non-running registry images are ignored, so the dashboard
// isn't polluted with images nobody is running.
//
// Idempotency + triage preservation: promoted rows are tagged target_type = 'image-workload'
// and scan_target_id = the image's scan target. A single statement DELETEs the prior promotions
// for that scan target (CTE `prior`) and re-inserts the current set, LEFT JOINing each new row
// back to the deleted row with the same (scan_finding_key, cluster_id) so the user's triage —
// lifecycle, assignee_id, accepted_until, priority — and the original first_seen_at carry
// forward instead of being reset to a fresh open finding on every rescan. The DELETE+INSERT in
// one CTE statement (single snapshot) plus single-writer completion (worker lease + status
// guard, all in one tx) keeps this duplicate-free without a unique constraint on the partitioned
// findings table.
//
// Lifecycle precedence per promoted row:
//  1. the prior row's user triage, if any (anything other than 'open'/'resolved' is preserved;
//     'resolved' re-opens so a reintroduced CVE re-fires, mirroring upsertTargetFinding);
//  2. else the vuln-profile verdict recorded in detail_json (suppress_accept -> 'accepted',
//     suppress_defer -> 'suppressed') so a suppressed CVE never inflates the open rollups;
//  3. else 'open'. Escalate already bumped f.severity/risk in image_scan_findings, so the
//     promoted row inherits the raised severity directly.
//
// The vuln is attributed to the image's asset (assetID) but cluster_id is the running
// workload's cluster, so the dashboard's per-cluster severity rollup counts it correctly.
//
// Params: $1=orgID, $2=resultID, $3=assetID, $4=imageTargetID.
func promoteImageFindingsToWorkloads(ctx context.Context, tx pgx.Tx, orgID, resultID, imageTargetID, assetID uuid.UUID) (int, error) {
	// Insert one finding per (image_scan_finding, distinct running cluster), restricting to
	// image_scan_findings that map to a cluster running the image — joined the same way
	// internal/handler/cve.go correlates image scans to workloads.
	var inserted int
	err := tx.QueryRow(ctx, `
WITH deleted AS (
    -- Supersede by the IMAGE ASSET, not the scan_target_id: the same image can be
    -- scanned via several targets (registry ref, resolved digest, discoverer/runtime-
    -- agent), each producing its own image_scan_result. Deleting only this target's
    -- prior findings left the OTHER targets' identical findings behind → the same CVE
    -- on the same image duplicated 2-6x. Keying the supersede on asset_id collapses
    -- every path for an image to the latest scan's findings. User triage decisions are
    -- still preserved below (matched by scan_finding_key + cluster_id).
    DELETE FROM findings
     WHERE org_id = $1
       AND target_type = 'image-workload'
       AND asset_id = $3
    RETURNING detail_json->>'scan_finding_key' AS finding_key, cluster_id,
              lifecycle, assignee_id, accepted_until, priority, first_seen_at
),
prior AS (
    -- Collapse any pre-existing duplicate rows for the same (finding_key, cluster) to a
    -- SINGLE prior. The LEFT JOIN below joins prior back onto each re-inserted finding;
    -- if two dup rows already existed for a key, joining BOTH re-created two rows every
    -- rescan — a self-perpetuating doubling loop that promote-by-asset alone never broke.
    -- DISTINCT ON guarantees ≤1 prior per (key, cluster) so the re-insert can't multiply.
    -- Winner keeps a real triage decision (accepted_until set, else an assignee) and the
    -- earliest true first_seen_at.
    SELECT DISTINCT ON (finding_key, cluster_id)
           finding_key, cluster_id, lifecycle, assignee_id, accepted_until, priority, first_seen_at
      FROM deleted
     ORDER BY finding_key, cluster_id,
              (accepted_until IS NOT NULL) DESC,
              (assignee_id IS NOT NULL) DESC,
              first_seen_at ASC
),
promoted AS (
INSERT INTO findings (
    id, org_id, cluster_id, asset_id, kind, external_id, title, description,
    severity, risk_score, lifecycle, assignee_id, accepted_until, priority,
    canonical_engine, engines, detail_json,
    scan_target_id, target_type, target_ref, target_cluster_id, source_type,
    risk_inputs, first_seen_at, last_seen_at)
SELECT gen_random_uuid(),
       $1, l.cluster_id, $3, 'vulnerability', f.external_id, f.title, f.description,
       f.severity, f.risk_score,
       CASE
           -- User accept-risk (stamps accepted_until) is preserved across rescans; a profile-set
           -- lifecycle is re-derived from THIS scan's verdict so a changed decision takes effect
           -- (a prior 'accepted' from suppress_accept becomes 'open' once the verdict is escalate).
           WHEN p.accepted_until IS NOT NULL THEN COALESCE(p.lifecycle, 'open')
           ELSE COALESCE(
               CASE f.detail_json->'vulnerability_profile'->>'decision'
                    WHEN 'suppress_accept' THEN 'accepted'
                    WHEN 'suppress_defer'  THEN 'suppressed'
                    ELSE NULL END,
               'open')
       END,
       p.assignee_id, p.accepted_until, p.priority,
       f.canonical_engine, f.engines,
       f.detail_json || jsonb_build_object(
           'promoted_from_image_scan_result_id', r.id::text,
           'scan_finding_key', f.finding_key,
           'image_workload_count', COUNT(DISTINCT l.workload_id)),
       $4, 'image-workload', MAX(l.image_ref), l.cluster_id, 'cluster',
       CASE WHEN f.detail_json ? 'reachable_static'
            THEN jsonb_build_object('reachable_static', (f.detail_json->>'reachable_static')::boolean)
            ELSE '{}'::jsonb END,
       COALESCE(p.first_seen_at, NOW()), NOW()
  FROM image_scan_findings f
  JOIN image_scan_results r ON r.id = f.image_scan_result_id AND r.org_id = $1
  JOIN image_workload_links l
    ON l.org_id = $1
   AND (
        (COALESCE(r.image_digest, '') <> '' AND l.image_digest = r.image_digest)
     OR (COALESCE(r.image_ref, '') <> '' AND l.image_ref = r.image_ref)
     OR (COALESCE(r.image_ref_normalized, '') <> '' AND l.image_ref_normalized = r.image_ref_normalized)
     OR (COALESCE(r.image_repository, '') <> '' AND l.image_repository = r.image_repository
         AND (COALESCE(r.image_tag, '') = '' OR l.image_tag = r.image_tag))
   )
  LEFT JOIN prior p ON p.finding_key = f.finding_key AND p.cluster_id = l.cluster_id
 WHERE f.org_id = $1
   AND f.image_scan_result_id = $2
 GROUP BY r.id, f.finding_key, f.external_id, f.title, f.description, f.severity,
          f.risk_score, f.canonical_engine, f.engines, f.detail_json, l.cluster_id,
          p.lifecycle, p.assignee_id, p.accepted_until, p.priority, p.first_seen_at
RETURNING 1
)
SELECT COUNT(*)::int FROM promoted`,
		orgID, resultID, assetID, imageTargetID).Scan(&inserted)
	if err != nil {
		return 0, err
	}
	return inserted, nil
}

func pruneStaleImageScanFindings(ctx context.Context, tx pgx.Tx, orgID, resultID uuid.UUID, currentKeys []string) error {
	if len(currentKeys) == 0 {
		_, err := tx.Exec(ctx, `DELETE FROM image_scan_findings WHERE org_id = $1 AND image_scan_result_id = $2`, orgID, resultID)
		return err
	}
	_, err := tx.Exec(ctx, `
DELETE FROM image_scan_findings
 WHERE org_id = $1
   AND image_scan_result_id = $2
   AND NOT (finding_key = ANY($3::text[]))`, orgID, resultID, currentKeys)
	return err
}

func scanFindingStableKey(f scanner.Finding) string {
	pkg := f.Package
	pkg.Locations = nil
	key := struct {
		VulnerabilityID string
		Package         scanner.Package
		FixedVersion    string
		AffectedRange   *scanner.AffectedRange
	}{
		VulnerabilityID: strings.TrimSpace(f.VulnerabilityID),
		Package:         pkg,
		FixedVersion:    strings.TrimSpace(f.FixedVersion),
		AffectedRange:   f.AffectedRange,
	}
	raw, _ := json.Marshal(key)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func registryAndRepository(repository string) (string, string) {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return "", ""
	}
	parts := strings.SplitN(repository, "/", 2)
	if len(parts) != 2 {
		return "", repository
	}
	return parts[0], parts[1]
}

func (h *ScanJobs) deployedImageClusters(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, imageRef string) ([]*uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
SELECT DISTINCT cluster_id
  FROM deployments
 WHERE org_id = $1
   AND cluster_id IS NOT NULL
   AND $2 = ANY(image_refs)
 ORDER BY cluster_id`, orgID, imageRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scopes := []*uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		idCopy := id
		scopes = append(scopes, &idCopy)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		return []*uuid.UUID{nil}, nil
	}
	return scopes, nil
}

func (h *ScanJobs) scanTargetClusters(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, target handler.ScanTarget, identity scanImageIdentity) ([]*uuid.UUID, error) {
	if target.ClusterID != nil {
		idCopy := *target.ClusterID
		return []*uuid.UUID{&idCopy}, nil
	}
	if target.Type == "image" {
		scopes, err := h.imageWorkloadClusters(ctx, tx, orgID, target, identity)
		if err != nil {
			return nil, err
		}
		if len(scopes) > 0 {
			return scopes, nil
		}
		imageRef := strings.TrimSpace(identity.Ref)
		if imageRef == "" {
			imageRef = strings.TrimSpace(target.ImageRef)
		}
		if imageRef == "" {
			imageRef = target.Ref
		}
		return h.deployedImageClusters(ctx, tx, orgID, imageRef)
	}
	return []*uuid.UUID{nil}, nil
}

func (h *ScanJobs) imageWorkloadClusters(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, target handler.ScanTarget, identity scanImageIdentity) ([]*uuid.UUID, error) {
	ref := strings.TrimSpace(identity.Ref)
	if ref == "" {
		ref = strings.TrimSpace(target.ImageRef)
	}
	if ref == "" {
		ref = strings.TrimSpace(target.Ref)
	}
	normalized := strings.TrimSpace(identity.NormalizedRef)
	if normalized == "" {
		normalized = imageid.Parse(ref).Normalized
	}
	rows, err := tx.Query(ctx, `
SELECT DISTINCT cluster_id
  FROM image_workload_links
 WHERE org_id = $1
   AND cluster_id IS NOT NULL
   AND (
        ($2 <> '' AND image_digest = $2)
     OR ($3 <> '' AND image_ref = $3)
     OR ($4 <> '' AND image_ref_normalized = $4)
     OR ($5 <> '' AND image_repository = $5 AND ($6 = '' OR image_tag = $6))
   )
 ORDER BY cluster_id`,
		orgID, identity.Digest, ref, normalized, identity.Repository, identity.Tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scopes := []*uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		idCopy := id
		scopes = append(scopes, &idCopy)
	}
	return scopes, rows.Err()
}

func loadActiveVulnerabilityProfiles(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, clusterID *uuid.UUID) ([]vulnprofile.Profile, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, name, COALESCE(description, ''), active, entries, domain_scope
  FROM vuln_profiles
 WHERE org_id = $1
   AND active = TRUE
   AND (cluster_id IS NULL OR ($2::uuid IS NOT NULL AND cluster_id = $2))
 ORDER BY updated_at DESC, name`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	profiles := []vulnprofile.Profile{}
	for rows.Next() {
		var profile vulnprofile.Profile
		var entriesRaw, domainRaw []byte
		if err := rows.Scan(&profile.ID, &profile.Name, &profile.Description, &profile.Active, &entriesRaw, &domainRaw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(entriesRaw, &profile.Entries)
		_ = json.Unmarshal(domainRaw, &profile.DomainScope)
		profiles = append(profiles, profile)
	}
	return profiles, rows.Err()
}

func vulnerabilityProfileDecisionForFinding(profiles []vulnprofile.Profile, target handler.ScanTarget, identity scanImageIdentity, finding scanner.Finding, severity string) map[string]any {
	if len(profiles) == 0 || strings.TrimSpace(finding.VulnerabilityID) == "" {
		return nil
	}
	cv := vulnprofile.CVE{
		ID:        finding.VulnerabilityID,
		Severity:  severity,
		BaseScore: finding.CVSSBase,
		Image:     vulnerabilityProfileImageRef(target, identity),
		Cluster:   vulnerabilityProfileCluster(target),
		Namespace: vulnerabilityProfileNamespace(target),
	}
	for _, profile := range profiles {
		if !profile.Active {
			continue
		}
		outcome := profile.Evaluate([]vulnprofile.CVE{cv})[0]
		if outcome.Decision == vulnprofile.DecisionNone {
			continue
		}
		return map[string]any{
			"profile_id":   profile.ID,
			"profile_name": profile.Name,
			"decision":     outcome.Decision,
			"entry_name":   outcome.EntryName,
			"reason":       outcome.Reason,
		}
	}
	return nil
}

// vulnProfileDecisionKind extracts the decision verdict from the map produced by
// vulnerabilityProfileDecisionForFinding. The in-memory value is a vulnprofile.Decision; a value
// round-tripped through JSON (detail_json) decodes to a string — both are handled.
func vulnProfileDecisionKind(decision map[string]any) string {
	if decision == nil {
		return ""
	}
	switch v := decision["decision"].(type) {
	case string:
		return v
	case vulnprofile.Decision:
		return string(v)
	}
	return ""
}

// applyVulnProfileEscalation raises a finding to critical (severity and risk floor) when the
// profile decision is escalate, so the stored finding counts in the critical rollup and re-fires
// escalating response rules. Non-escalate decisions leave severity/risk untouched.
func applyVulnProfileEscalation(decision map[string]any, severity string, risk int) (string, int) {
	if vulnProfileDecisionKind(decision) != string(vulnprofile.DecisionEscalate) {
		return severity, risk
	}
	if score := handler.SeverityToScore("critical", 0, false); score > risk {
		risk = score
	}
	return "critical", risk
}

// vulnProfileLifecycleOverride maps a suppress verdict to the finding lifecycle that drops the
// CVE out of the open critical/high rollups: suppress_accept -> 'accepted' (acknowledged),
// suppress_defer -> 'suppressed' (grace window). Escalate/none return "" (caller keeps default).
func vulnProfileLifecycleOverride(decision map[string]any) string {
	switch vulnProfileDecisionKind(decision) {
	case string(vulnprofile.DecisionSuppressAccept):
		return "accepted"
	case string(vulnprofile.DecisionSuppressDefer):
		return "suppressed"
	}
	return ""
}

func vulnerabilityProfileImageRef(target handler.ScanTarget, identity scanImageIdentity) string {
	for _, value := range []string{identity.Ref, identity.NormalizedRef, target.ImageRef, target.Ref, identity.Repository, identity.Digest, target.ImageDigest} {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func vulnerabilityProfileCluster(target handler.ScanTarget) string {
	if target.ClusterID == nil {
		return ""
	}
	return target.ClusterID.String()
}

func vulnerabilityProfileNamespace(target handler.ScanTarget) string {
	var metadata map[string]any
	if len(target.Metadata) == 0 || json.Unmarshal(target.Metadata, &metadata) != nil {
		return ""
	}
	for _, key := range []string{"namespace", "pod_namespace", "workload_namespace", "kubernetes_namespace"} {
		if value, ok := metadata[key].(string); ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

type scanFindingContext struct {
	ScanFindingKey      string
	ImageRef            string
	ImageDigest         string
	Platform            string
	ScannerProfile      string
	ImageScanResultID   uuid.UUID
	ImageScanFindingID  uuid.UUID
	ImageScanFindingKey string
	TargetID            uuid.UUID
	TargetType          string
	TargetRef           string
	TargetClusterID     *uuid.UUID
	SourceType          string
	SourceRef           string
	TargetMetadata      json.RawMessage
	BundleMetadata      *scanner.BundleMetadata
	VulnProfileDecision map[string]any
}

func scannerFindingDetail(f scanner.Finding, ctx scanFindingContext) map[string]any {
	detail := map[string]any{
		"package":     f.Package,
		"cvss_base":   f.CVSSBase,
		"cvss_vector": f.CVSSVector,
		"fixed":       f.FixedVersion,
		"references":  f.References,
		"epss":        f.EPSSProbability,
		"kev":         f.KEVListed,
		"aliases":     f.Aliases,
		"image_ref":   ctx.ImageRef,
		"target_id":   ctx.TargetID.String(),
		"target_type": ctx.TargetType,
		"target_ref":  ctx.TargetRef,
		"source_type": ctx.SourceType,
	}
	// A4: persist the CVE publish date so the admission grace-window
	// (detail_json->>'published') can exclude freshly-disclosed CVEs. Omitted
	// when unknown — the grace SQL treats absent as "count it" (safe).
	if f.Published != "" {
		detail["published"] = f.Published
	}
	if ctx.SourceRef != "" {
		detail["source_ref"] = ctx.SourceRef
	}
	if metadata := handler.NormalizedJSONRaw(ctx.TargetMetadata); len(metadata) > 0 {
		detail["scan_target_metadata"] = metadata
	}
	if ctx.ScanFindingKey != "" {
		detail["scan_finding_key"] = ctx.ScanFindingKey
	}
	if ctx.ImageDigest != "" {
		detail["image_digest"] = ctx.ImageDigest
	}
	if ctx.Platform != "" {
		detail["platform"] = ctx.Platform
	}
	if ctx.ScannerProfile != "" {
		detail["scanner_profile"] = ctx.ScannerProfile
	}
	if ctx.ImageScanResultID != uuid.Nil {
		detail["image_scan_result_id"] = ctx.ImageScanResultID.String()
	}
	if ctx.ImageScanFindingID != uuid.Nil {
		detail["image_scan_finding_id"] = ctx.ImageScanFindingID.String()
	}
	if ctx.ImageScanFindingKey != "" {
		detail["image_scan_finding_key"] = ctx.ImageScanFindingKey
	}
	if ctx.TargetClusterID != nil {
		detail["target_cluster_id"] = ctx.TargetClusterID.String()
	}
	if f.CanonicalEngine != "" {
		detail["canonical_engine"] = f.CanonicalEngine
	}
	// G1: surface govulncheck reachability. nil = not computed (non-Go, or analysis
	// skipped) and is left absent so it reads as "unknown", not "unreachable".
	if f.Reachable != nil {
		detail["reachable_static"] = *f.Reachable
	}
	if f.AffectedRange != nil {
		detail["affected_range"] = f.AffectedRange
	}
	if len(f.Reconciliation) > 0 {
		detail["reconciliation"] = f.Reconciliation
	}
	if ctx.BundleMetadata != nil {
		detail["vulndb_bundle"] = ctx.BundleMetadata
	}
	if len(ctx.VulnProfileDecision) > 0 {
		detail["vulnerability_profile"] = ctx.VulnProfileDecision
	}
	return detail
}

func normalizeScanTargetType(targetType string) string {
	targetType = strings.ToLower(strings.TrimSpace(targetType))
	if targetType == "" {
		return "image"
	}
	return targetType
}

func imageRefForTarget(targetType, targetRef, imageRef string) string {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef != "" {
		return imageRef
	}
	if targetType == "image" {
		return strings.TrimSpace(targetRef)
	}
	return ""
}

func validScanTargetType(targetType string) bool {
	switch targetType {
	case "image", "workload", "host", "platform", "registry", "repository", "serverless":
		return true
	default:
		return false
	}
}

func scannerClaimTargetTypesFromRequest(r *http.Request) []string {
	seen := map[string]struct{}{}
	out := []string{}
	values := append([]string{}, r.URL.Query()["target_type"]...)
	values = append(values, r.URL.Query()["target_types"]...)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			targetType := normalizeScanTargetType(part)
			if !validScanTargetType(targetType) {
				continue
			}
			if _, ok := seen[targetType]; ok {
				continue
			}
			seen[targetType] = struct{}{}
			out = append(out, targetType)
		}
	}
	return out
}

func normalizeScanJobMaxAttempts(maxAttempts int) int {
	switch {
	case maxAttempts <= 0:
		return 3
	case maxAttempts > 10:
		return 10
	default:
		return maxAttempts
	}
}

func validateExecutableScanRequest(req EnqueueRequest) error {
	if req.TargetType == "repository" {
		return fmt.Errorf("repository scans must be created from repository package evidence")
	}
	if req.TargetType == "image" && req.SourceType == "repository" && req.SourceRef == "" {
		return fmt.Errorf("source_ref required for repository-sourced image scans")
	}
	return nil
}

func assetKindForScanTarget(targetType string) string {
	switch targetType {
	case "host":
		return "host"
	case "platform":
		return "platform"
	case "workload":
		return "workload"
	case "serverless":
		return "serverless"
	case "repository":
		return "repository"
	default:
		return "image"
	}
}

// Fail records that a worker could not complete a job.
func (h *ScanJobs) Fail(w http.ResponseWriter, r *http.Request) {
	token, ok := handler.ScannerTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "scanner token required")
		return
	}
	workerID := handler.ScannerWorkerIDFromRequest(token, r)
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	var body struct {
		Error     string `json:"error"`
		Retryable bool   `json:"retryable"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	var (
		updatedID     uuid.UUID
		status        string
		attemptCount  int
		maxAttempts   int
		nextAttemptAt *time.Time
	)
	if err := h.db.Pool().QueryRow(r.Context(), `
WITH current_job AS (
	SELECT id, COALESCE(attempt_count, 0) AS attempt_count, COALESCE(max_attempts, 3) AS max_attempts
	  FROM scan_jobs
	 WHERE id = $2
	   AND org_id = $3
	   AND status = 'running'
	   AND worker_id = $4
	 FOR UPDATE
),
updated AS (
	UPDATE scan_jobs
	   SET status           = CASE WHEN $5 AND current_job.attempt_count < current_job.max_attempts THEN 'pending' ELSE 'failed' END,
	       error            = $1,
	       worker_id        = CASE WHEN $5 AND current_job.attempt_count < current_job.max_attempts THEN NULL ELSE scan_jobs.worker_id END,
	       claimed_at       = CASE WHEN $5 AND current_job.attempt_count < current_job.max_attempts THEN NULL ELSE scan_jobs.claimed_at END,
	       finished_at      = CASE WHEN $5 AND current_job.attempt_count < current_job.max_attempts THEN NULL ELSE NOW() END,
	       lease_expires_at = NULL,
	       last_error_at    = NOW(),
	       next_attempt_at  = CASE
	           WHEN $5 AND current_job.attempt_count < current_job.max_attempts
	           THEN NOW() + make_interval(secs => LEAST(
	               ($6::int * POWER(2, GREATEST(current_job.attempt_count - 1, 0)))::int,
	               $7::int
	           ))
	           ELSE NULL
	       END
	  FROM current_job
	 WHERE scan_jobs.id = current_job.id
	 RETURNING scan_jobs.id, scan_jobs.status, scan_jobs.attempt_count, scan_jobs.max_attempts, scan_jobs.next_attempt_at
)
SELECT id, status, attempt_count, max_attempts, next_attempt_at
  FROM updated`, body.Error, id, token.OrgID, workerID, body.Retryable, int(scannerJobBaseRetryDelay/time.Second), int(scannerJobMaxRetryDelay/time.Second)).Scan(&updatedID, &status, &attemptCount, &maxAttempts, &nextAttemptAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if scanJobWasCanceledByOperator(r.Context(), h.db.Pool(), id, token.OrgID, workerID) {
				httpx.WriteJSON(w, 200, map[string]any{
					"status":  "canceled",
					"dropped": true,
				})
				return
			}
			jsonError(w, http.StatusConflict, "job must be running and claimed by this worker before failure")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID:      &token.OrgID,
			Action:     "scan-job.fail",
			TargetKind: "scan-job",
			TargetID:   id.String(),
			After: map[string]any{
				"error":           body.Error,
				"status":          status,
				"retryable":       body.Retryable,
				"retry_scheduled": status == "pending",
				"attempt_count":   attemptCount,
				"max_attempts":    maxAttempts,
				"next_attempt_at": nextAttemptAt,
			},
		})
	}
	httpx.WriteJSON(w, 200, map[string]any{
		"status":          status,
		"retry_scheduled": status == "pending",
		"attempt_count":   attemptCount,
		"max_attempts":    maxAttempts,
		"next_attempt_at": nextAttemptAt,
	})
}

func scanJobWasCanceledByOperator(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, orgID uuid.UUID, workerID string) bool {
	var status, owner string
	if err := pool.QueryRow(ctx, `
SELECT status, COALESCE(worker_id, '')
  FROM scan_jobs
 WHERE id = $1 AND org_id = $2`, id, orgID).Scan(&status, &owner); err != nil {
		return false
	}
	return status == "canceled" && (owner == "" || owner == workerID)
}
