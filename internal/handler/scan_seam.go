package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This file hosts the scan-core seams shared between package handler and the
// extracted handler/scanning sub-package. The canonical (unexported)
// declarations live here so the non-moved parent files that consume them
// (clusters_cross_scan, host_packages, platform_facts, registries,
// repository_packages, repository_inventory, connector_coverage,
// asset_vuln_summary, cluster_init_bundles, events_ingest, heartbeats,
// scan_evidence) keep compiling unchanged, while exported aliases/wrappers let
// the scanning sub-package reach the same logic without an import cycle.

// jsonError writes a {"error": msg} JSON body with the given status. It
// formerly lived in scanjobs.go (now relocated to the handler/scanning
// sub-package); kept here so the rest of package handler still resolves it.
func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// scannerJobLeaseInterval is the worker lease window used by the scan-job queue
// and the queue-metrics aggregation.
const scannerJobLeaseInterval = "30 minutes"

// ScannerJobLeaseInterval is the exported seam over scannerJobLeaseInterval.
const ScannerJobLeaseInterval = scannerJobLeaseInterval

// scanTarget is a row in scan_targets.
type scanTarget struct {
	ID            uuid.UUID
	OrgID         uuid.UUID
	ClusterID     *uuid.UUID
	Type          string
	Ref           string
	SourceType    string
	SourceRef     string
	ImageRef      string
	ImageDigest   string
	RegistryID    *uuid.UUID
	Platform      string
	InventoryHash string
	Metadata      json.RawMessage
}

type scanTargetUpsert struct {
	TargetType      string
	TargetRef       string
	TargetClusterID *uuid.UUID
	SourceType      string
	SourceRef       string
	ImageRef        string
	ImageDigest     string
	RegistryID      *uuid.UUID
	Platform        string
	InventoryHash   string
	Metadata        json.RawMessage
}

// ScanTarget / ScanTargetUpsert are exported seams over scanTarget /
// scanTargetUpsert for the scanning sub-package.
type ScanTarget = scanTarget

type ScanTargetUpsert = scanTargetUpsert

func upsertScanTarget(ctx context.Context, pool *pgxpool.Pool, tx pgx.Tx, orgID uuid.UUID, req scanTargetUpsert) (scanTarget, error) {
	if req.TargetClusterID != nil {
		var exists bool
		if tx != nil {
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE id = $1 AND org_id = $2)`, *req.TargetClusterID, orgID).Scan(&exists); err != nil {
				return scanTarget{}, err
			}
		} else {
			if pool == nil {
				return scanTarget{}, fmt.Errorf("database pool required")
			}
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE id = $1 AND org_id = $2)`, *req.TargetClusterID, orgID).Scan(&exists); err != nil {
				return scanTarget{}, err
			}
		}
		if !exists {
			return scanTarget{}, fmt.Errorf("target cluster not found")
		}
	}

	metadata := "{}"
	if len(req.Metadata) > 0 {
		var tmp any
		if err := json.Unmarshal(req.Metadata, &tmp); err != nil {
			return scanTarget{}, fmt.Errorf("invalid metadata")
		}
		metadata = string(req.Metadata)
	}
	imageRef := req.ImageRef
	if req.TargetType == "image" && imageRef == "" {
		imageRef = req.TargetRef
	}

	var id uuid.UUID
	findSQL := `
SELECT id
  FROM scan_targets
 WHERE org_id = $1
   AND COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid) = COALESCE($2::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
   AND type = $3
   AND ref = $4
   AND source_type = $5
   AND COALESCE(source_ref, '') = COALESCE($6, '')
 LIMIT 1`
	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, findSQL, orgID, req.TargetClusterID, req.TargetType, req.TargetRef, req.SourceType, req.SourceRef).Scan(&id)
	} else {
		if pool == nil {
			return scanTarget{}, fmt.Errorf("database pool required")
		}
		err = pool.QueryRow(ctx, findSQL, orgID, req.TargetClusterID, req.TargetType, req.TargetRef, req.SourceType, req.SourceRef).Scan(&id)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return scanTarget{}, err
	}

	if errors.Is(err, pgx.ErrNoRows) {
		insertSQL := `
INSERT INTO scan_targets (
    org_id, cluster_id, type, ref, source_type, source_ref,
    image_ref, image_digest, registry_id, platform, inventory_hash, metadata
) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''),
          NULLIF($7, ''), NULLIF($8, ''), $9, NULLIF($10, ''), NULLIF($11, ''), $12::jsonb)
RETURNING id`
		if tx != nil {
			err = tx.QueryRow(ctx, insertSQL, orgID, req.TargetClusterID, req.TargetType, req.TargetRef, req.SourceType, req.SourceRef,
				imageRef, req.ImageDigest, req.RegistryID, req.Platform, req.InventoryHash, metadata).Scan(&id)
		} else {
			err = pool.QueryRow(ctx, insertSQL, orgID, req.TargetClusterID, req.TargetType, req.TargetRef, req.SourceType, req.SourceRef,
				imageRef, req.ImageDigest, req.RegistryID, req.Platform, req.InventoryHash, metadata).Scan(&id)
		}
		if err != nil {
			return scanTarget{}, err
		}
	} else {
		updateSQL := `
UPDATE scan_targets
   SET image_ref = COALESCE(NULLIF($2, ''), image_ref),
       image_digest = COALESCE(NULLIF($3, ''), image_digest),
       registry_id = COALESCE($4, registry_id),
       platform = COALESCE(NULLIF($5, ''), platform),
       inventory_hash = COALESCE(NULLIF($6, ''), inventory_hash),
       metadata = CASE WHEN $7::jsonb = '{}'::jsonb THEN metadata ELSE $7::jsonb END,
       last_seen_at = NOW()
 WHERE id = $1`
		if tx != nil {
			_, err = tx.Exec(ctx, updateSQL, id, imageRef, req.ImageDigest, req.RegistryID, req.Platform, req.InventoryHash, metadata)
		} else {
			_, err = pool.Exec(ctx, updateSQL, id, imageRef, req.ImageDigest, req.RegistryID, req.Platform, req.InventoryHash, metadata)
		}
		if err != nil {
			return scanTarget{}, err
		}
	}
	return loadScanTarget(ctx, pool, tx, id)
}

func loadScanTarget(ctx context.Context, pool *pgxpool.Pool, tx pgx.Tx, id uuid.UUID) (scanTarget, error) {
	query := `
SELECT id, org_id, cluster_id, type, ref, source_type, COALESCE(source_ref, ''),
       COALESCE(image_ref, ''), COALESCE(image_digest, ''), registry_id,
       COALESCE(platform, ''), COALESCE(inventory_hash, ''), metadata
  FROM scan_targets
 WHERE id = $1`
	var target scanTarget
	var metadataRaw []byte
	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, query, id).Scan(&target.ID, &target.OrgID, &target.ClusterID, &target.Type, &target.Ref, &target.SourceType,
			&target.SourceRef, &target.ImageRef, &target.ImageDigest, &target.RegistryID, &target.Platform, &target.InventoryHash, &metadataRaw)
	} else {
		if pool == nil {
			return scanTarget{}, fmt.Errorf("database pool required")
		}
		err = pool.QueryRow(ctx, query, id).Scan(&target.ID, &target.OrgID, &target.ClusterID, &target.Type, &target.Ref, &target.SourceType,
			&target.SourceRef, &target.ImageRef, &target.ImageDigest, &target.RegistryID, &target.Platform, &target.InventoryHash, &metadataRaw)
	}
	target.Metadata = normalizedJSONRaw(metadataRaw)
	return target, err
}

// UpsertScanTarget / LoadScanTarget are exported seams for the scanning
// sub-package.
func UpsertScanTarget(ctx context.Context, pool *pgxpool.Pool, tx pgx.Tx, orgID uuid.UUID, req ScanTargetUpsert) (ScanTarget, error) {
	return upsertScanTarget(ctx, pool, tx, orgID, req)
}

func LoadScanTarget(ctx context.Context, pool *pgxpool.Pool, tx pgx.Tx, id uuid.UUID) (ScanTarget, error) {
	return loadScanTarget(ctx, pool, tx, id)
}

func normalizedJSONRaw(raw []byte) json.RawMessage {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		return nil
	}
	var decoded any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil
	}
	return json.RawMessage(trimmed)
}

// NormalizedJSONRaw is the exported seam over normalizedJSONRaw.
func NormalizedJSONRaw(raw []byte) json.RawMessage { return normalizedJSONRaw(raw) }

func validScanSourceType(sourceType string) bool {
	switch sourceType {
	case "manual", "registry", "repository", "runtime-agent", "discoverer", "platform", "host", "serverless":
		return true
	default:
		return false
	}
}

// ValidScanSourceType is the exported seam over validScanSourceType.
func ValidScanSourceType(sourceType string) bool { return validScanSourceType(sourceType) }

func normalizeScanSourceType(sourceType, targetType string) string {
	sourceType = strings.ToLower(strings.TrimSpace(sourceType))
	if sourceType != "" {
		return sourceType
	}
	switch targetType {
	case "host":
		return "host"
	case "platform":
		return "platform"
	case "workload":
		return "runtime-agent"
	case "repository":
		return "repository"
	case "serverless":
		return "serverless"
	default:
		return "manual"
	}
}

// NormalizeScanSourceType is the exported seam over normalizeScanSourceType.
func NormalizeScanSourceType(sourceType, targetType string) string {
	return normalizeScanSourceType(sourceType, targetType)
}

// severityToScore is a deterministic fallback when the engine didn't pre-compute risk_score.
// Mirrors pkg/risk's high-level shape but stays local so we don't pull pkg/risk into the
// handler dep tree.
func severityToScore(sev string, cvss float64, kev bool) int {
	base := 0
	switch sev {
	case "critical":
		base = 90
	case "high":
		base = 70
	case "medium":
		base = 50
	case "low":
		base = 25
	default:
		base = 10
	}
	if cvss > 0 {
		bonus := int(cvss * 2)
		if bonus > 0 {
			base += bonus
		}
	}
	if kev {
		base += 10
	}
	if base > 100 {
		base = 100
	}
	return base
}

// SeverityToScore is the exported seam over severityToScore.
func SeverityToScore(sev string, cvss float64, kev bool) int { return severityToScore(sev, cvss, kev) }

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// FirstNonEmpty is the exported seam over firstNonEmpty.
func FirstNonEmpty(values ...string) string { return firstNonEmpty(values...) }

// Exported aliases/wrappers consumed only by the handler/scanning sub-package's
// tests (cross-domain integration assertions that decode dashboard/image/
// repository response bodies). Kept here so those tests stay self-contained
// without an import cycle.
type ImageScanResultDTO = imageScanResultDTO

type ImageScanFindingDTO = imageScanFindingDTO

type DashboardSummaryDTO = dashboardSummaryDTO

type RepositoryScanDTO = repositoryScanDTO

// Itoa is the exported seam over itoa.
func Itoa(n int) string { return itoa(n) }

// ImpactedWorkload is a workload affected by a scanned image. It is shared
// between the parent package (image_scan_results.go, enterprise.go) and the
// scanning sub-package (scan_impacts.go), so it lives here.
type ImpactedWorkload struct {
	ClusterID          uuid.UUID `json:"cluster_id"`
	DeploymentID       uuid.UUID `json:"deployment_id"`
	WorkloadID         string    `json:"workload_id"`
	Namespace          string    `json:"namespace"`
	Name               string    `json:"name"`
	Kind               string    `json:"kind"`
	ImageRef           string    `json:"image_ref"`
	ImageRefNormalized string    `json:"image_ref_normalized"`
	ImageRepository    string    `json:"image_repository,omitempty"`
	ImageTag           string    `json:"image_tag,omitempty"`
	ImageDigest        string    `json:"image_digest,omitempty"`
	RiskScore          int       `json:"risk_score"`
	FindingCount       int       `json:"finding_count"`
	CriticalCount      int       `json:"critical_count"`
	HighCount          int       `json:"high_count"`
	LastSeenAt         time.Time `json:"last_seen_at"`
}

// scanQueueMetricDTO is the per-target-type scan queue depth summary.
type scanQueueMetricDTO struct {
	TargetType           string `json:"target_type"`
	Pending              int    `json:"pending"`
	RetryDelayed         int    `json:"retry_delayed"`
	Exhausted            int    `json:"exhausted"`
	Running              int    `json:"running"`
	StaleRunning         int    `json:"stale_running"`
	Paused               int    `json:"paused"`
	Canceled             int    `json:"canceled"`
	Failed               int    `json:"failed"`
	CompletedLastHour    int    `json:"completed_last_hour"`
	OldestPendingSeconds int    `json:"oldest_pending_seconds"`
}

// ScanQueueMetricDTO is the exported seam over scanQueueMetricDTO.
type ScanQueueMetricDTO = scanQueueMetricDTO

func scanQueueMetrics(ctx context.Context, pool *pgxpool.Pool, orgID any) ([]scanQueueMetricDTO, error) {
	rows, err := pool.Query(ctx, `
SELECT st.type,
       COUNT(*) FILTER (WHERE sj.status = 'pending')::int,
       COUNT(*) FILTER (
           WHERE sj.status = 'pending'
             AND sj.next_attempt_at IS NOT NULL
             AND sj.next_attempt_at > NOW()
       )::int,
       COUNT(*) FILTER (
           WHERE sj.status = 'pending'
             AND COALESCE(sj.attempt_count, 0) >= COALESCE(sj.max_attempts, 3)
       )::int,
       COUNT(*) FILTER (WHERE sj.status = 'running')::int,
       COUNT(*) FILTER (
           WHERE sj.status = 'running'
             AND (
               (sj.lease_expires_at IS NOT NULL AND sj.lease_expires_at < NOW())
               OR (sj.lease_expires_at IS NULL AND sj.claimed_at IS NOT NULL AND sj.claimed_at < NOW() - $2::interval)
             )
       )::int,
       COUNT(*) FILTER (WHERE sj.status = 'paused')::int,
       COUNT(*) FILTER (WHERE sj.status = 'canceled')::int,
       COUNT(*) FILTER (WHERE sj.status = 'failed')::int,
       COUNT(*) FILTER (WHERE sj.status = 'completed' AND sj.finished_at > NOW() - INTERVAL '1 hour')::int,
       COALESCE(EXTRACT(EPOCH FROM NOW() - MIN(sj.requested_at) FILTER (
           WHERE sj.status = 'pending'
             AND COALESCE(sj.attempt_count, 0) < COALESCE(sj.max_attempts, 3)
             AND (sj.next_attempt_at IS NULL OR sj.next_attempt_at <= NOW())
       ))::int, 0)
  FROM scan_jobs sj
  JOIN scan_targets st ON st.id = sj.target_id
 WHERE sj.org_id = $1
 GROUP BY st.type
 ORDER BY
       COUNT(*) FILTER (WHERE sj.status = 'pending') DESC,
       COUNT(*) FILTER (WHERE sj.status = 'running') DESC,
       st.type`, orgID, scannerJobLeaseInterval)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []scanQueueMetricDTO{}
	for rows.Next() {
		var item scanQueueMetricDTO
		if err := rows.Scan(&item.TargetType, &item.Pending, &item.RetryDelayed, &item.Exhausted, &item.Running, &item.StaleRunning, &item.Paused, &item.Canceled, &item.Failed, &item.CompletedLastHour, &item.OldestPendingSeconds); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ScanQueueMetrics is the exported seam over scanQueueMetrics.
func ScanQueueMetrics(ctx context.Context, pool *pgxpool.Pool, orgID any) ([]ScanQueueMetricDTO, error) {
	return scanQueueMetrics(ctx, pool, orgID)
}

// ScannerToken is the subject for scanner-token-authenticated calls.
type ScannerToken struct {
	ID    uuid.UUID
	OrgID uuid.UUID
	Name  string
}

func (t *ScannerToken) workerID() string {
	return "scanner:" + t.Name + ":" + t.ID.String()
}

func scannerWorkerIDFromRequest(t *ScannerToken, r *http.Request) string {
	base := t.workerID()
	instance := strings.TrimSpace(r.Header.Get("X-Constellation-Scanner-Instance"))
	if instance == "" {
		return base
	}
	instance = sanitizeScannerInstanceID(instance)
	if instance == "" {
		return base
	}
	return base + ":" + instance
}

// ScannerWorkerIDFromRequest is the exported seam over
// scannerWorkerIDFromRequest.
func ScannerWorkerIDFromRequest(t *ScannerToken, r *http.Request) string {
	return scannerWorkerIDFromRequest(t, r)
}

func sanitizeScannerInstanceID(instance string) string {
	var b strings.Builder
	for _, ch := range instance {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '.', ch == '_', ch == '-':
			b.WriteRune(ch)
		}
		if b.Len() >= 64 {
			break
		}
	}
	return b.String()
}

type scannerTokenKey struct{}

func scannerTokenFrom(ctx context.Context) (*ScannerToken, bool) {
	t, ok := ctx.Value(scannerTokenKey{}).(*ScannerToken)
	return t, ok
}

// ScannerTokenFrom is the exported seam over scannerTokenFrom.
func ScannerTokenFrom(ctx context.Context) (*ScannerToken, bool) { return scannerTokenFrom(ctx) }

// ScannerTokenMiddleware validates the "Bearer <raw-token>" header against scanner_tokens
// by comparing sha256(raw) to token_hash.
func ScannerTokenMiddleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractBearer(r)
			if raw == "" {
				jsonError(w, http.StatusUnauthorized, "scanner bearer token required")
				return
			}
			sum := sha256.Sum256([]byte(raw))
			hash := hex.EncodeToString(sum[:])

			var tok ScannerToken
			err := pool.QueryRow(r.Context(), `
SELECT id, org_id, name
  FROM scanner_tokens
 WHERE token_hash = $1
   AND revoked_at IS NULL
   AND (expires_at IS NULL OR expires_at > NOW())`,
				hash).Scan(&tok.ID, &tok.OrgID, &tok.Name)
			if err != nil {
				jsonError(w, http.StatusUnauthorized, "invalid scanner token")
				return
			}
			_, _ = pool.Exec(r.Context(),
				`UPDATE scanner_tokens SET last_used_at = NOW() WHERE id = $1`, tok.ID)
			ctx := context.WithValue(r.Context(), scannerTokenKey{}, &tok)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractBearer pulls "<token>" from a "Bearer <token>" Authorization header. Lives here
// (rather than reusing server.bearerToken) so the handler package has no inverse import.
func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// IssueScannerToken creates a new scanner token. Returns (raw_token, id, error).
func IssueScannerToken(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, name string, ttl time.Duration) (string, uuid.UUID, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", uuid.Nil, err
	}
	token := "cst_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	id := uuid.New()
	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scanner_tokens (id, org_id, name, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5)`, id, orgID, name, hex.EncodeToString(sum[:]), expires); err != nil {
		return "", uuid.Nil, fmt.Errorf("issue scanner token: %w", err)
	}
	return token, id, nil
}
