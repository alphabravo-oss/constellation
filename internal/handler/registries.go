// Package handler — container-registry CRUD + auto-discover (Wave N2).
//
// Endpoints (all require user JWT + the manage-registries verb except GETs
// which fall through to read-findings):
//
//	GET    /api/v1/registries              — list rows + status + last-sync metadata.
//	POST   /api/v1/registries              — create.
//	GET    /api/v1/registries/{id}         — detail (auth_secret never returned).
//	PATCH  /api/v1/registries/{id}         — update fields; auth_secret rotates only when
//	                                         creds.* are supplied.
//	DELETE /api/v1/registries/{id}         — delete.
//	POST   /api/v1/registries/{id}/test    — synchronous credential check.
//	POST   /api/v1/registries/{id}/sync-now — trigger a manual walker pass right now.
//	GET    /api/v1/registries/{id}/images   — list discovered images for this registry.
//
// The walker daemon (cmd/constellation-registry-walker) consumes the same DB
// rows on a 60s cadence; sync-now performs one inline pass via the same
// SyncOnce function so behaviour is identical between user-triggered and
// timer-triggered runs.
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/registry"
	"github.com/alphabravocompany/constellation/internal/syscfg"
	"github.com/alphabravocompany/constellation/pkg/audit"
	regsecrets "github.com/alphabravocompany/constellation/pkg/registry/secrets"
)

// Registries handles /api/v1/registries.
type Registries struct {
	db    *db.DB
	audit *audit.Logger
}

// NewRegistries constructs the handler.
func NewRegistries(d *db.DB, a *audit.Logger) *Registries {
	return &Registries{db: d, audit: a}
}

// validKinds is the closed set of registry kinds we accept.
var validKinds = map[string]bool{
	"docker-hub": true,
	"ghcr":       true,
	"ecr":        true,
	"gcr":        true,
	"acr":        true,
	"quay":       true,
	"harbor":     true,
	"gitlab":     true,
	"jfrog":      true,
}

// validAuthKinds enumerates the auth shapes the storage layer understands.
var validAuthKinds = map[string]bool{
	"static":              true,
	"aws-iam-role":        true,
	"gcp-service-account": true,
	"azure-managed-id":    true,
	"none":                true,
}

// validCadences enumerates scan_cadence values.
var validCadences = map[string]bool{
	"manual": true,
	"hourly": true,
	"6h":     true,
	"daily":  true,
	"weekly": true,
}

var validRegistryTagSelections = map[string]bool{
	"all":    true,
	"latest": true,
}

var validRegistryPromotionThresholds = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"none":     true,
}

func defaultRegistryScanPolicy(fallbackInclude []string) registryScanPolicy {
	include := compactStringSlice(fallbackInclude)
	if len(include) == 0 {
		include = []string{"*"}
	}
	return registryScanPolicy{
		IncludeRepos:            include,
		ExcludeRepos:            []string{},
		TagSelection:            "all",
		BlockPromotionThreshold: "critical",
	}
}

func normalizeRegistryScanPolicy(in *registryScanPolicy, fallbackInclude []string) registryScanPolicy {
	out := defaultRegistryScanPolicy(fallbackInclude)
	if in == nil {
		return out
	}
	if v := compactStringSlice(in.IncludeRepos); len(v) > 0 {
		out.IncludeRepos = v
	}
	out.ExcludeRepos = compactStringSlice(in.ExcludeRepos)
	if strings.TrimSpace(in.TagSelection) != "" {
		out.TagSelection = strings.TrimSpace(in.TagSelection)
	}
	if strings.TrimSpace(in.MaxAge) != "" {
		out.MaxAge = strings.TrimSpace(in.MaxAge)
	}
	if strings.TrimSpace(in.RescanInterval) != "" {
		out.RescanInterval = strings.TrimSpace(in.RescanInterval)
	}
	if strings.TrimSpace(in.BlockPromotionThreshold) != "" {
		out.BlockPromotionThreshold = strings.TrimSpace(in.BlockPromotionThreshold)
	}
	if !validRegistryTagSelections[out.TagSelection] {
		out.TagSelection = "all"
	}
	if !validRegistryPromotionThresholds[out.BlockPromotionThreshold] {
		out.BlockPromotionThreshold = "critical"
	}
	sort.Strings(out.IncludeRepos)
	sort.Strings(out.ExcludeRepos)
	return out
}

func decodeRegistryScanPolicy(raw []byte, fallbackInclude []string) registryScanPolicy {
	if len(raw) == 0 {
		return defaultRegistryScanPolicy(fallbackInclude)
	}
	var policy registryScanPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return defaultRegistryScanPolicy(fallbackInclude)
	}
	return normalizeRegistryScanPolicy(&policy, fallbackInclude)
}

func validateRegistryScanPolicy(policy registryScanPolicy) error {
	if policy.TagSelection != "" && !validRegistryTagSelections[policy.TagSelection] {
		return fmt.Errorf("invalid scan_policy.tag_selection")
	}
	if policy.BlockPromotionThreshold != "" && !validRegistryPromotionThresholds[policy.BlockPromotionThreshold] {
		return fmt.Errorf("invalid scan_policy.block_promotion_threshold")
	}
	if policy.MaxAge != "" {
		if _, err := time.ParseDuration(policy.MaxAge); err != nil {
			return fmt.Errorf("scan_policy.max_age must be a duration")
		}
	}
	if policy.RescanInterval != "" {
		if _, err := time.ParseDuration(policy.RescanInterval); err != nil {
			return fmt.Errorf("scan_policy.rescan_interval must be a duration")
		}
	}
	return nil
}

func registryPolicyHash(policy registryScanPolicy) string {
	normalized := normalizeRegistryScanPolicy(&policy, nil)
	raw, _ := json.Marshal(normalized)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func compactStringSlice(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// CadenceToInterval returns the polling interval for the given cadence.
// "manual" returns 0 — meaning "never auto-sync."
func CadenceToInterval(c string) time.Duration {
	switch c {
	case "hourly":
		return time.Hour
	case "6h":
		return 6 * time.Hour
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

// registryDTO is the JSON shape returned to the UI. auth_secret is NEVER
// included. Whether creds are configured is conveyed via the boolean flag.
type registryDTO struct {
	ID             uuid.UUID          `json:"id"`
	OrgID          uuid.UUID          `json:"org_id"`
	Name           string             `json:"name"`
	Kind           string             `json:"kind"`
	Endpoint       string             `json:"endpoint"`
	AuthKind       string             `json:"auth_kind"`
	HasSecret      bool               `json:"has_secret"`
	ScanCadence    string             `json:"scan_cadence"`
	ImageGlobs     []string           `json:"image_globs"`
	ScanPolicy     registryScanPolicy `json:"scan_policy"`
	LastSyncAt     *string            `json:"last_sync_at,omitempty"`
	LastSyncStatus string             `json:"last_sync_status,omitempty"`
	LastSyncError  string             `json:"last_sync_error,omitempty"`
	ImagesSeen     int                `json:"images_seen"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

// registryCreateRequest is the POST body. Credentials are the raw fields the
// chosen adapter needs; what we accept depends on `kind`.
type registryCreateRequest struct {
	Name        string              `json:"name"`
	Kind        string              `json:"kind"`
	Endpoint    string              `json:"endpoint"`
	AuthKind    string              `json:"auth_kind"`
	Credentials map[string]string   `json:"credentials,omitempty"` // optional; required when auth_kind != none
	ScanCadence string              `json:"scan_cadence,omitempty"`
	ImageGlobs  []string            `json:"image_globs,omitempty"`
	ScanPolicy  *registryScanPolicy `json:"scan_policy,omitempty"`
}

// registryUpdateRequest is the PATCH body. All fields optional; missing fields
// are not updated. Setting credentials rotates the encrypted secret.
type registryUpdateRequest struct {
	Name        *string             `json:"name,omitempty"`
	Endpoint    *string             `json:"endpoint,omitempty"`
	AuthKind    *string             `json:"auth_kind,omitempty"`
	Credentials *map[string]string  `json:"credentials,omitempty"`
	ScanCadence *string             `json:"scan_cadence,omitempty"`
	ImageGlobs  *[]string           `json:"image_globs,omitempty"`
	ScanPolicy  *registryScanPolicy `json:"scan_policy,omitempty"`
}

type registryScanPolicy struct {
	IncludeRepos            []string `json:"include_repos"`
	ExcludeRepos            []string `json:"exclude_repos"`
	TagSelection            string   `json:"tag_selection"`
	MaxAge                  string   `json:"max_age"`
	RescanInterval          string   `json:"rescan_interval"`
	BlockPromotionThreshold string   `json:"block_promotion_threshold"`
}

// List returns all registries for the calling org.
func (h *Registries) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, org_id, name, kind, endpoint, auth_kind,
       (auth_secret IS NOT NULL) AS has_secret,
       scan_cadence, image_globs, scan_policy,
       last_sync_at, COALESCE(last_sync_status, ''), COALESCE(last_sync_error, ''),
       images_seen, created_at, updated_at
  FROM registries
 WHERE org_id = $1
 ORDER BY created_at DESC`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	out := []registryDTO{}
	for rows.Next() {
		var dto registryDTO
		var lastSync *time.Time
		var policyRaw []byte
		if err := rows.Scan(&dto.ID, &dto.OrgID, &dto.Name, &dto.Kind, &dto.Endpoint, &dto.AuthKind,
			&dto.HasSecret, &dto.ScanCadence, &dto.ImageGlobs,
			&policyRaw,
			&lastSync, &dto.LastSyncStatus, &dto.LastSyncError,
			&dto.ImagesSeen, &dto.CreatedAt, &dto.UpdatedAt,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if lastSync != nil {
			s := lastSync.UTC().Format(time.RFC3339)
			dto.LastSyncAt = &s
		}
		if dto.ImageGlobs == nil {
			dto.ImageGlobs = []string{}
		}
		dto.ScanPolicy = decodeRegistryScanPolicy(policyRaw, dto.ImageGlobs)
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, map[string]any{"registries": out})
}

// Create inserts a new registry row, AES-GCM-sealing the credentials.
func (h *Registries) Create(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var req registryCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := validateCreate(&req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	sealed, err := sealCredentials(r.Context(), h.db.Pool(), req.AuthKind, req.Credentials)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "seal creds: "+err.Error())
		return
	}

	id := uuid.New()
	cadence := req.ScanCadence
	if cadence == "" {
		cadence = "manual"
	}
	globs := req.ImageGlobs
	if globs == nil {
		globs = []string{}
	}
	policy := normalizeRegistryScanPolicy(req.ScanPolicy, globs)
	policyRaw, _ := json.Marshal(policy)

	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO registries (id, org_id, name, kind, endpoint, auth_kind, auth_secret,
                        scan_cadence, image_globs, scan_policy, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)`,
		id, subj.OrgID, req.Name, req.Kind, req.Endpoint, req.AuthKind, sealed,
		cadence, globs, string(policyRaw), subj.UserID,
	); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			jsonError(w, http.StatusConflict, "registry name already in use")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "registry.create",
		TargetKind: "registry",
		TargetID:   id.String(),
		After: map[string]any{
			"name":         req.Name,
			"kind":         req.Kind,
			"endpoint":     req.Endpoint,
			"auth_kind":    req.AuthKind,
			"scan_cadence": cadence,
			"image_globs":  globs,
			"scan_policy":  policy,
		},
	})

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// Get returns one registry by id.
func (h *Registries) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	dto, err := loadRegistryDTO(r.Context(), h.db.Pool(), subj.OrgID, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

// Patch updates one or more fields. Sending `credentials` rotates the secret.
func (h *Registries) Patch(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req registryUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}

	sets := []string{}
	args := []any{}
	idx := 1
	addArg := func(col string, v any) {
		sets = append(sets, fmt.Sprintf("%s = $%d", col, idx))
		args = append(args, v)
		idx++
	}
	addJSONBArg := func(col string, raw []byte) {
		sets = append(sets, fmt.Sprintf("%s = $%d::jsonb", col, idx))
		args = append(args, string(raw))
		idx++
	}

	if req.Name != nil {
		addArg("name", *req.Name)
	}
	if req.Endpoint != nil {
		addArg("endpoint", *req.Endpoint)
	}
	if req.AuthKind != nil {
		if !validAuthKinds[*req.AuthKind] {
			jsonError(w, http.StatusBadRequest, "invalid auth_kind")
			return
		}
		addArg("auth_kind", *req.AuthKind)
	}
	if req.ScanCadence != nil {
		if !validCadences[*req.ScanCadence] {
			jsonError(w, http.StatusBadRequest, "invalid scan_cadence")
			return
		}
		addArg("scan_cadence", *req.ScanCadence)
	}
	if req.ImageGlobs != nil {
		addArg("image_globs", *req.ImageGlobs)
	}
	if req.ScanPolicy != nil {
		if err := validateRegistryScanPolicy(*req.ScanPolicy); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		fallbackGlobs := []string{}
		if req.ImageGlobs != nil {
			fallbackGlobs = *req.ImageGlobs
		}
		policy := normalizeRegistryScanPolicy(req.ScanPolicy, fallbackGlobs)
		raw, _ := json.Marshal(policy)
		addJSONBArg("scan_policy", raw)
	} else if req.ImageGlobs != nil {
		policy := normalizeRegistryScanPolicy(nil, *req.ImageGlobs)
		raw, _ := json.Marshal(policy)
		addJSONBArg("scan_policy", raw)
	}
	if req.Credentials != nil {
		// Determine final auth_kind (just-set or current).
		authKind := ""
		if req.AuthKind != nil {
			authKind = *req.AuthKind
		} else {
			if err := h.db.Pool().QueryRow(r.Context(),
				`SELECT auth_kind FROM registries WHERE id=$1 AND org_id=$2`, id, subj.OrgID,
			).Scan(&authKind); err != nil {
				jsonError(w, http.StatusNotFound, "not found")
				return
			}
		}
		sealed, err := sealCredentials(r.Context(), h.db.Pool(), authKind, *req.Credentials)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "seal creds: "+err.Error())
			return
		}
		addArg("auth_secret", sealed)
	}

	if len(sets) == 0 {
		jsonError(w, http.StatusBadRequest, "nothing to update")
		return
	}
	sets = append(sets, "updated_at = NOW()")

	args = append(args, id, subj.OrgID)
	sql := fmt.Sprintf(`UPDATE registries SET %s WHERE id = $%d AND org_id = $%d`,
		strings.Join(sets, ", "), idx, idx+1)
	tag, err := h.db.Pool().Exec(r.Context(), sql, args...)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}

	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "registry.update",
		TargetKind: "registry",
		TargetID:   id.String(),
		After:      map[string]any{"rotated_secret": req.Credentials != nil},
	})
	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a registry row.
func (h *Registries) Delete(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(),
		`DELETE FROM registries WHERE id = $1 AND org_id = $2`, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "registry.delete",
		TargetKind: "registry",
		TargetID:   id.String(),
	})
	w.WriteHeader(http.StatusNoContent)
}

// Test verifies that decrypted creds can reach the registry — synchronously,
// without writing anything to last_sync_*.
func (h *Registries) Test(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}

	kind, endpoint, authKind, sealed, err := loadRegistryRow(r.Context(), h.db.Pool(), subj.OrgID, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	conn, err := BuildConnector(r.Context(), h.db.Pool(), subj.OrgID, kind, endpoint, authKind, sealed)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	imgs, err := conn.ListImages(ctx)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "registry.test",
		TargetKind: "registry",
		TargetID:   id.String(),
		After:      map[string]any{"images_visible": len(imgs)},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"images_visible": len(imgs),
	})
}

// SyncNow runs one walker pass for this registry, inline. The result mirrors
// what the background walker would have written.
func (h *Registries) SyncNow(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	res, err := SyncOnce(r.Context(), h.db.Pool(), slog.Default(), subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "registry.sync-now",
		TargetKind: "registry",
		TargetID:   id.String(),
		After: map[string]any{
			"status":             res.Status,
			"images_seen":        res.ImagesSeen,
			"scan_jobs_enqueued": res.JobsEnqueued,
		},
	})
	writeJSON(w, http.StatusOK, res)
}

// Images returns the list of repositories last discovered for a registry.
func (h *Registries) Images(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT ri.id, ri.repository, ri.tags, COALESCE(ri.digests, '{}'::jsonb), COALESCE(ri.last_pushed_at, ''),
       ri.first_seen_at, ri.last_seen_at,
       (sr.id IS NOT NULL)                       AS scanned,
       COALESCE(sr.finding_count, 0)             AS finding_count,
       sr.last_scanned_at,
       COALESCE(sr.max_severity_critical, 0)     AS critical,
       COALESCE(sr.max_severity_high, 0)         AS high
  FROM registry_images ri
  LEFT JOIN LATERAL (
      SELECT r.id, r.finding_count, r.last_scanned_at,
             (SELECT count(*) FROM image_scan_findings f WHERE f.image_scan_result_id = r.id AND f.severity = 'critical') AS max_severity_critical,
             (SELECT count(*) FROM image_scan_findings f WHERE f.image_scan_result_id = r.id AND f.severity = 'high')     AS max_severity_high
        FROM image_scan_results r
       WHERE r.org_id = ri.org_id AND r.image_repository = ri.repository
       ORDER BY r.last_scanned_at DESC NULLS LAST
       LIMIT 1
  ) sr ON true
 WHERE ri.registry_id = $1 AND ri.org_id = $2
 ORDER BY sr.finding_count DESC NULLS LAST, ri.last_seen_at DESC
 LIMIT 500`, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type imgRow struct {
		ID            uuid.UUID         `json:"id"`
		Repository    string            `json:"repository"`
		Tags          []string          `json:"tags"`
		Digests       map[string]string `json:"digests"`
		LastPushedAt  string            `json:"last_pushed_at,omitempty"`
		FirstSeenAt   time.Time         `json:"first_seen_at"`
		LastSeenAt    time.Time         `json:"last_seen_at"`
		Scanned       bool              `json:"scanned"`
		FindingCount  int               `json:"finding_count"`
		LastScannedAt *time.Time        `json:"last_scanned_at,omitempty"`
		Critical      int               `json:"critical"`
		High          int               `json:"high"`
	}
	out := []imgRow{}
	for rows.Next() {
		var ir imgRow
		var digestsRaw []byte
		if err := rows.Scan(&ir.ID, &ir.Repository, &ir.Tags, &digestsRaw, &ir.LastPushedAt,
			&ir.FirstSeenAt, &ir.LastSeenAt, &ir.Scanned, &ir.FindingCount, &ir.LastScannedAt,
			&ir.Critical, &ir.High); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ir.Tags == nil {
			ir.Tags = []string{}
		}
		ir.Digests = map[string]string{}
		_ = json.Unmarshal(digestsRaw, &ir.Digests)
		out = append(out, ir)
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": out})
}

// -----------------------------------------------------------------------------
// internal helpers: validation, credential sealing, adapter dispatch
// -----------------------------------------------------------------------------

func validateCreate(req *registryCreateRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	req.Kind = strings.TrimSpace(req.Kind)
	req.Endpoint = strings.TrimSpace(req.Endpoint)
	req.AuthKind = strings.TrimSpace(req.AuthKind)
	if req.Name == "" {
		return errors.New("name required")
	}
	if !validKinds[req.Kind] {
		return errors.New("invalid kind")
	}
	if req.Endpoint == "" {
		return errors.New("endpoint required")
	}
	if !validAuthKinds[req.AuthKind] {
		return errors.New("invalid auth_kind")
	}
	if req.ScanCadence != "" && !validCadences[req.ScanCadence] {
		return errors.New("invalid scan_cadence")
	}
	if req.ScanPolicy != nil {
		if err := validateRegistryScanPolicy(*req.ScanPolicy); err != nil {
			return err
		}
	}
	policy := normalizeRegistryScanPolicy(req.ScanPolicy, req.ImageGlobs)
	if err := validateRegistryScanPolicy(policy); err != nil {
		return err
	}
	return nil
}

// sealCredentials JSON-marshals creds and seals them with the install KEK.
// Returns (nil, nil) when there are no creds (auth_kind="none").
func sealCredentials(ctx context.Context, pool *pgxpool.Pool, authKind string, creds map[string]string) ([]byte, error) {
	if authKind == "none" || len(creds) == 0 {
		return nil, nil
	}
	cipher, err := regsecrets.Default(ctx, pool, slog.Default())
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}
	pt, err := json.Marshal(creds)
	if err != nil {
		return nil, err
	}
	return cipher.Seal(pt)
}

// openCredentials inverts sealCredentials. Returns an empty map when sealed is
// nil/empty.
func openCredentials(ctx context.Context, pool *pgxpool.Pool, sealed []byte) (map[string]string, error) {
	if len(sealed) == 0 {
		return map[string]string{}, nil
	}
	cipher, err := regsecrets.Default(ctx, pool, slog.Default())
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}
	pt, err := cipher.Open(sealed)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if err := json.Unmarshal(pt, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// BuildConnector constructs the appropriate registry.Connector for `kind` using
// decrypted creds. Exported so the walker binary can reuse it.
//
// orgID selects the system_config row whose LIVE egress-proxy / TLS-verify / CA-bundle
// settings the connector's outbound HTTP client must honor. The client is built from the
// current DB row (syscfg.Provider.HTTPClient) on every call, so a PATCH to those knobs
// takes effect on the next registry walk or Test WITHOUT a restart — this is the B1
// "shared outbound HTTP client" consumer (a) wired to a real caller.
func BuildConnector(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, kind, endpoint, authKind string, sealedSecret []byte) (registry.Connector, error) {
	creds, err := openCredentials(ctx, pool, sealedSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypt creds: %w", err)
	}
	cfg := registry.Config{
		Username: creds["username"],
		Password: creds["password"],
		Token:    creds["token"],
		Region:   creds["region"],
		Endpoint: endpoint,
		// Live outbound client: honors the org's runtime egress-proxy / TLS knobs.
		HTTPClient: syscfg.NewProvider(pool).HTTPClient(ctx, orgID, 30*time.Second),
	}
	switch kind {
	case "docker-hub":
		return registry.NewDockerHub(cfg), nil
	case "ghcr":
		return registry.NewGHCR(cfg), nil
	case "ecr":
		if cfg.Region == "" {
			cfg.Region = creds["aws_region"]
		}
		return registry.NewECR(cfg), nil
	case "gcr":
		// Map "gcr" UI label to the existing artifact-registry adapter.
		// Endpoint here is the GCP path projects/<id>/locations/<region>/repositories/<repo>.
		cfg.Endpoint = creds["resource_path"]
		if cfg.Endpoint == "" {
			cfg.Endpoint = endpoint
		}
		return registry.NewArtifactRegistry(cfg), nil
	case "acr":
		cfg.Endpoint = stripScheme(endpoint)
		return registry.NewACR(cfg), nil
	case "quay":
		cfg.Endpoint = stripScheme(endpoint)
		return registry.NewQuay(cfg), nil
	case "harbor":
		return registry.NewHarbor(cfg), nil
	case "gitlab":
		return registry.NewGitLab(cfg), nil
	case "jfrog":
		return registry.NewJFrog(cfg), nil
	default:
		return nil, fmt.Errorf("unknown registry kind %q", kind)
	}
}

func stripScheme(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimRight(s, "/")
}

// -----------------------------------------------------------------------------
// DB lookups
// -----------------------------------------------------------------------------

func loadRegistryRow(ctx context.Context, pool *pgxpool.Pool, orgID, id uuid.UUID,
) (kind, endpoint, authKind string, sealedSecret []byte, err error) {
	err = pool.QueryRow(ctx, `
SELECT kind, endpoint, auth_kind, auth_secret
  FROM registries WHERE id = $1 AND org_id = $2`, id, orgID,
	).Scan(&kind, &endpoint, &authKind, &sealedSecret)
	return
}

func loadRegistryDTO(ctx context.Context, pool *pgxpool.Pool, orgID, id uuid.UUID) (*registryDTO, error) {
	var dto registryDTO
	var lastSync *time.Time
	var policyRaw []byte
	err := pool.QueryRow(ctx, `
SELECT id, org_id, name, kind, endpoint, auth_kind,
       (auth_secret IS NOT NULL),
       scan_cadence, image_globs, scan_policy,
       last_sync_at, COALESCE(last_sync_status, ''), COALESCE(last_sync_error, ''),
       images_seen, created_at, updated_at
  FROM registries
 WHERE id = $1 AND org_id = $2`, id, orgID).Scan(
		&dto.ID, &dto.OrgID, &dto.Name, &dto.Kind, &dto.Endpoint, &dto.AuthKind,
		&dto.HasSecret, &dto.ScanCadence, &dto.ImageGlobs,
		&policyRaw,
		&lastSync, &dto.LastSyncStatus, &dto.LastSyncError,
		&dto.ImagesSeen, &dto.CreatedAt, &dto.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if lastSync != nil {
		s := lastSync.UTC().Format(time.RFC3339)
		dto.LastSyncAt = &s
	}
	if dto.ImageGlobs == nil {
		dto.ImageGlobs = []string{}
	}
	dto.ScanPolicy = decodeRegistryScanPolicy(policyRaw, dto.ImageGlobs)
	return &dto, nil
}

// -----------------------------------------------------------------------------
// Walker core: SyncOnce
// -----------------------------------------------------------------------------

// SyncResult is what SyncOnce returns.
type SyncResult struct {
	RegistryID   uuid.UUID `json:"registry_id"`
	Status       string    `json:"status"` // ok | failed | partial
	ImagesSeen   int       `json:"images_seen"`
	JobsEnqueued int       `json:"scan_jobs_enqueued"`
	Error        string    `json:"error,omitempty"`
}

// SyncOnce runs a single discovery pass for one registry:
//   - takes an advisory lock so concurrent walkers don't double-enqueue
//   - decrypts creds, builds the adapter, calls ListImages
//   - upserts registry_images and diffs against the previous tag set
//   - enqueues a scan_jobs row for every newly-discovered tag
//   - updates last_sync_at/status/error/images_seen
//
// Audit-logging is the caller's responsibility (handler and walker do it
// differently — handler attributes the actor, walker attributes a daemon).
func SyncOnce(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, orgID, registryID uuid.UUID) (*SyncResult, error) {
	result := &SyncResult{RegistryID: registryID, Status: "failed"}

	lockKey := int64FromHash("reg:" + registryID.String())
	tx, err := pool.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockKey).Scan(&locked); err != nil {
		return result, fmt.Errorf("advisory lock: %w", err)
	}
	if !locked {
		result.Status = "partial"
		result.Error = "registry already syncing"
		return result, nil
	}

	var (
		kind, endpoint, authKind, name string
		sealed                         []byte
		globs                          []string
		policyRaw                      []byte
	)
	if err := tx.QueryRow(ctx, `
SELECT name, kind, endpoint, auth_kind, auth_secret, image_globs, scan_policy
  FROM registries WHERE id = $1 AND org_id = $2 FOR UPDATE`, registryID, orgID,
	).Scan(&name, &kind, &endpoint, &authKind, &sealed, &globs, &policyRaw); err != nil {
		return result, fmt.Errorf("load registry: %w", err)
	}
	policy := decodeRegistryScanPolicy(policyRaw, globs)
	policyHash := registryPolicyHash(policy)

	// Commit the lock+row read; the actual network calls happen outside the
	// transaction so we don't pin a connection for the full sync.
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("commit lock-read: %w", err)
	}

	logger.Info("registry sync start",
		slog.String("registry_id", registryID.String()),
		slog.String("kind", kind),
		slog.String("endpoint", endpoint))

	conn, err := BuildConnector(ctx, pool, orgID, kind, endpoint, authKind, sealed)
	if err != nil {
		recordSyncStatus(ctx, pool, registryID, "failed", err.Error(), 0)
		result.Error = err.Error()
		return result, nil
	}

	netCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	images, err := conn.ListImages(netCtx)
	if err != nil {
		recordSyncStatus(ctx, pool, registryID, "failed", err.Error(), 0)
		result.Error = err.Error()
		return result, nil
	}
	// Apply policy filtering before resolving tags/digests.
	filtered := filterImagesByScanPolicy(images, policy, time.Now())
	result.ImagesSeen = len(filtered)
	bundleVersion := currentVulnDBBundleVersion()

	// Diff & enqueue.
	jobs, perr := upsertImagesAndEnqueue(ctx, pool, orgID, registryID, filtered, conn, policy, policyHash, bundleVersion)
	result.JobsEnqueued = jobs
	if perr != nil {
		recordSyncStatus(ctx, pool, registryID, "partial", perr.Error(), len(filtered))
		result.Status = "partial"
		result.Error = perr.Error()
		return result, nil
	}

	recordSyncStatus(ctx, pool, registryID, "ok", "", len(filtered))
	result.Status = "ok"
	logger.Info("registry sync ok",
		slog.String("registry_id", registryID.String()),
		slog.Int("images_seen", len(filtered)),
		slog.Int("jobs_enqueued", jobs))
	return result, nil
}

// upsertImagesAndEnqueue writes one registry_images row per discovered image
// and queues a scan_job for every *new* repository (and for every newly-seen
// tag on previously-known repositories).
func upsertImagesAndEnqueue(ctx context.Context, pool *pgxpool.Pool, orgID, registryID uuid.UUID,
	imgs []registry.Image, conn registry.Connector, policy registryScanPolicy, policyHash, bundleVersion string,
) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	jobsEnqueued := 0
	for _, im := range imgs {
		var prevTags []string
		err := tx.QueryRow(ctx, `
SELECT tags FROM registry_images
 WHERE registry_id = $1 AND repository = $2`, registryID, im.Repository).Scan(&prevTags)
		isNew := false
		if errors.Is(err, pgx.ErrNoRows) {
			isNew = true
		} else if err != nil {
			return jobsEnqueued, err
		}

		tags := selectRegistryTags(im.Tags, policy)
		digests := map[string]string{}
		for _, tg := range tags {
			ref := registryTagRef(im.Repository, tg)
			resolved, err := conn.ResolveDigest(ctx, ref)
			if err == nil {
				if digest := digestFromResolvedRef(resolved); digest != "" {
					digests[tg] = digest
				}
			} else if strings.TrimSpace(im.Digest) != "" {
				digests[tg] = strings.TrimSpace(im.Digest)
			}
		}
		digestsRaw, _ := json.Marshal(digests)

		if _, err := tx.Exec(ctx, `
INSERT INTO registry_images (org_id, registry_id, repository, tags, digests, last_pushed_at, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5::jsonb, NULLIF($6,''), NOW(), NOW())
ON CONFLICT (registry_id, repository) DO UPDATE
  SET tags = EXCLUDED.tags,
      digests = EXCLUDED.digests,
      last_pushed_at = COALESCE(EXCLUDED.last_pushed_at, registry_images.last_pushed_at),
      last_seen_at = NOW()`,
			orgID, registryID, im.Repository, tags, string(digestsRaw), im.PushedAt); err != nil {
			return jobsEnqueued, fmt.Errorf("upsert image: %w", err)
		}

		// Evaluate all selected tags so policy or VulnDB bundle changes can
		// trigger rescans of existing tags. shouldEnqueueRegistryScan keeps the
		// common unchanged digest/policy/bundle case from requeueing.
		candidateTags := tags
		if isNew && len(candidateTags) == 0 {
			candidateTags = []string{"latest"}
		}
		_ = prevTags
		for _, tg := range candidateTags {
			ref := registryTagRef(im.Repository, tg)
			digest := digests[tg]
			scanRef := ref
			if digest != "" {
				scanRef = im.Repository + "@" + digest
			}
			target, err := upsertScanTarget(ctx, nil, tx, orgID, scanTargetUpsert{
				TargetType:  "image",
				TargetRef:   scanRef,
				SourceType:  "registry",
				SourceRef:   registryID.String(),
				ImageRef:    scanRef,
				ImageDigest: digest,
				RegistryID:  &registryID,
				Metadata: json.RawMessage(fmt.Sprintf(
					`{"registry_id":%q,"repository":%q,"tag":%q,"tag_ref":%q}`,
					registryID.String(), im.Repository, tg, ref,
				)),
			})
			if err != nil {
				return jobsEnqueued, fmt.Errorf("scan target: %w", err)
			}
			enqueue, reason, err := shouldEnqueueRegistryScan(ctx, tx, orgID, target.ID, policyHash, bundleVersion, policy.RescanInterval)
			if err != nil {
				return jobsEnqueued, fmt.Errorf("scan dedupe: %w", err)
			}
			if !enqueue {
				continue
			}
			id := uuid.New()
			if _, err := tx.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status, enqueue_reason, registry_policy_hash, vulndb_bundle_version)
VALUES ($1, $2, $3, 'pending', $4, $5, NULLIF($6,''))`,
				id, orgID, target.ID, reason, policyHash, bundleVersion); err != nil {
				return jobsEnqueued, fmt.Errorf("enqueue scan_job: %w", err)
			}
			jobsEnqueued++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return jobsEnqueued, err
	}
	return jobsEnqueued, nil
}

func diffTags(prev, curr []string) []string {
	seen := map[string]bool{}
	for _, t := range prev {
		seen[t] = true
	}
	out := []string{}
	for _, t := range curr {
		if !seen[t] {
			out = append(out, t)
		}
	}
	return out
}

func filterImagesByScanPolicy(in []registry.Image, policy registryScanPolicy, now time.Time) []registry.Image {
	out := make([]registry.Image, 0, len(in))
	for _, im := range in {
		if !matchesAnyGlob(im.Repository, policy.IncludeRepos) {
			continue
		}
		if len(policy.ExcludeRepos) > 0 && matchesAnyGlob(im.Repository, policy.ExcludeRepos) {
			continue
		}
		if policy.MaxAge != "" && im.PushedAt != "" {
			maxAge, err := time.ParseDuration(policy.MaxAge)
			if err == nil {
				pushedAt, err := time.Parse(time.RFC3339, im.PushedAt)
				if err == nil && now.Sub(pushedAt) > maxAge {
					continue
				}
			}
		}
		out = append(out, im)
	}
	return out
}

func selectRegistryTags(tags []string, policy registryScanPolicy) []string {
	tags = compactStringSlice(tags)
	if len(tags) == 0 {
		return []string{"latest"}
	}
	sort.Strings(tags)
	if policy.TagSelection != "latest" {
		return tags
	}
	for _, tag := range tags {
		if tag == "latest" {
			return []string{"latest"}
		}
	}
	return []string{tags[len(tags)-1]}
}

func registryTagRef(repository, tag string) string {
	if strings.TrimSpace(tag) == "" {
		return repository
	}
	return repository + ":" + tag
}

func digestFromResolvedRef(ref string) string {
	_, digest, ok := strings.Cut(ref, "@")
	if !ok {
		return ""
	}
	return strings.TrimSpace(digest)
}

// currentVulnDBBundleVersion previously reported the installed vulndb bundle
// version so registry rescans could requeue when the CVE DB changed. The vulndb
// bundle subsystem has been removed (cve_records is fed by the KEV+EPSS and NVD
// importers), so there is no bundle version to report. Retained as a stable seam
// for the requeue logic, which now simply never requeues on bundle change.
func currentVulnDBBundleVersion() string {
	return ""
}

func shouldEnqueueRegistryScan(ctx context.Context, tx pgx.Tx, orgID, targetID uuid.UUID, policyHash, bundleVersion, rescanInterval string) (bool, string, error) {
	var (
		status      string
		requestedAt time.Time
	)
	err := tx.QueryRow(ctx, `
SELECT status, requested_at
  FROM scan_jobs
 WHERE org_id = $1
   AND target_id = $2
   AND registry_policy_hash = $3
   AND COALESCE(vulndb_bundle_version, '') = $4
 ORDER BY requested_at DESC
 LIMIT 1`, orgID, targetID, policyHash, bundleVersion).Scan(&status, &requestedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, "digest-policy-or-vulndb-changed", nil
	}
	if err != nil {
		return false, "", err
	}
	switch status {
	case "pending", "running":
		return false, "", nil
	case "failed", "canceled":
		return true, "retry-" + status, nil
	}
	if rescanInterval != "" {
		interval, err := time.ParseDuration(rescanInterval)
		if err == nil && time.Since(requestedAt) >= interval {
			return true, "rescan-interval", nil
		}
	}
	return false, "", nil
}

func filterImages(in []registry.Image, globs []string) []registry.Image {
	if len(globs) == 0 {
		return in
	}
	out := make([]registry.Image, 0, len(in))
	for _, im := range in {
		if matchesAnyGlob(im.Repository, globs) {
			out = append(out, im)
		}
	}
	return out
}

// matchesAnyGlob does very simple glob matching: `*` matches any run of chars
// inside one repo segment, but for simplicity treats `*` as the wildcard.
func matchesAnyGlob(s string, globs []string) bool {
	for _, g := range globs {
		if globMatch(g, s) {
			return true
		}
	}
	return false
}

// GlobMatch is the exported seam over globMatch, consumed by the handler/scanning
// sub-package (attestation trust-policy pattern matching).
func GlobMatch(pattern, s string) bool { return globMatch(pattern, s) }

func globMatch(pattern, s string) bool {
	// Convert to a basic regex-y match: split on `*`, then ensure each piece
	// appears in order. Cheap and predictable.
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, p := range parts {
		if p == "" {
			continue
		}
		j := strings.Index(s[pos:], p)
		if j == -1 {
			return false
		}
		if i == 0 && j != 0 && !strings.HasPrefix(pattern, "*") {
			return false
		}
		pos += j + len(p)
	}
	if !strings.HasSuffix(pattern, "*") && pos != len(s) {
		return false
	}
	return true
}

func recordSyncStatus(ctx context.Context, pool *pgxpool.Pool, registryID uuid.UUID, status, errMsg string, imagesSeen int) {
	_, _ = pool.Exec(ctx, `
UPDATE registries
   SET last_sync_at = NOW(),
       last_sync_status = $1,
       last_sync_error = NULLIF($2, ''),
       images_seen = $3,
       updated_at = NOW()
 WHERE id = $4`, status, errMsg, imagesSeen, registryID)
}

// int64FromHash maps a string to a stable int64 advisory-lock key.
func int64FromHash(s string) int64 {
	// FNV-1a 64-bit, inline to avoid an extra dep.
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return int64(h)
}
