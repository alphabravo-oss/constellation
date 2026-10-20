package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

const (
	supportBundleJobPollInterval = 2 * time.Second
	supportBundleJobDBTimeout    = 5 * time.Second
	supportBundleJobBuildTimeout = 60 * time.Second
	supportBundleJobLease        = 90 * time.Second
	supportBundleJobRetention    = 7 * 24 * time.Hour
	supportBundleJobFailure      = "support bundle generation failed"
)

type SupportBundleJobs struct {
	db          *db.DB
	appendAudit func(context.Context, audit.Event) (int64, string, error)
	build       func(context.Context, Subject) (supportBundleDTO, error)
}

func NewSupportBundleJobs(database *db.DB, auditor *audit.Logger) *SupportBundleJobs {
	handler := &SupportBundleJobs{db: database, build: NewSupportBundle(database, auditor).build}
	if auditor != nil {
		handler.appendAudit = auditor.Log
	}
	return handler
}

type supportBundleJobDTO struct {
	ID           uuid.UUID  `json:"id"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	BundleID     *uuid.UUID `json:"bundle_id,omitempty"`
	Error        string     `json:"error,omitempty"`
	AuditEventID *int64     `json:"audit_event_id,omitempty"`
}

type supportBundleJobCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
}

func (h *SupportBundleJobs) CreateJob(w http.ResponseWriter, r *http.Request) {
	subject, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	if !h.ready(w) {
		return
	}
	if h.appendAudit == nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle job unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), supportBundleJobDBTimeout)
	defer cancel()
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle job unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var job supportBundleJobDTO
	err = tx.QueryRow(ctx, `
INSERT INTO support_bundle_jobs (org_id, requested_by)
VALUES ($1, $2)
RETURNING id, status, created_at`, subject.OrgID, subject.UserID).Scan(&job.ID, &job.Status, &job.CreatedAt)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle job unavailable")
		return
	}
	job.AuditEventID, err = h.logEvent(ctx, "support.bundle.job.create", job.ID, subject.OrgID, &subject.UserID, r, nil)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle job unavailable")
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE support_bundle_jobs SET audit_event_id = $1 WHERE id = $2`, *job.AuditEventID, job.ID); err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle job unavailable")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle job unavailable")
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (h *SupportBundleJobs) ListJobs(w http.ResponseWriter, r *http.Request) {
	subject, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	if !h.ready(w) {
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			jsonError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = min(parsed, 100)
	}
	var cursor *supportBundleJobCursor
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if len(raw) > 512 {
			jsonError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		encoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || json.Unmarshal(encoded, &cursor) != nil || cursor == nil || cursor.CreatedAt.IsZero() || cursor.ID == uuid.Nil {
			jsonError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), supportBundleJobDBTimeout)
	defer cancel()
	query := `SELECT id, CASE WHEN status = 'ready' AND audit_pending IS NOT NULL THEN 'running' ELSE status END,
created_at, started_at, finished_at, expires_at, bundle_id, error, audit_event_id
FROM support_bundle_jobs WHERE org_id = $1`
	args := []any{subject.OrgID}
	if cursor != nil {
		query += ` AND (created_at, id) < ($2, $3)`
		args = append(args, cursor.CreatedAt, cursor.ID)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, limit+1)
	rows, err := h.db.Pool().Query(ctx, query, args...)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle jobs unavailable")
		return
	}
	defer rows.Close()
	items := make([]supportBundleJobDTO, 0, limit)
	hasMore := false
	for rows.Next() {
		var job supportBundleJobDTO
		if err := scanSupportBundleJob(rows, &job); err != nil {
			jsonError(w, http.StatusServiceUnavailable, "support bundle jobs unavailable")
			return
		}
		if len(items) == limit {
			hasMore = true
			break
		}
		items = append(items, job)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle jobs unavailable")
		return
	}
	nextCursor := ""
	if hasMore {
		last := items[len(items)-1]
		encoded, _ := json.Marshal(supportBundleJobCursor{CreatedAt: last.CreatedAt, ID: last.ID})
		nextCursor = base64.RawURLEncoding.EncodeToString(encoded)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor})
}

func (h *SupportBundleJobs) GetJob(w http.ResponseWriter, r *http.Request) {
	subject, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	if !h.ready(w) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), supportBundleJobDBTimeout)
	defer cancel()
	var job supportBundleJobDTO
	err = scanSupportBundleJob(h.db.Pool().QueryRow(ctx, `
SELECT id, CASE WHEN status = 'ready' AND audit_pending IS NOT NULL THEN 'running' ELSE status END,
created_at, started_at, finished_at, expires_at, bundle_id, error, audit_event_id
FROM support_bundle_jobs WHERE id = $1 AND org_id = $2`, id, subject.OrgID), &job)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "support bundle job not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle job unavailable")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (h *SupportBundleJobs) DownloadJob(w http.ResponseWriter, r *http.Request) {
	subject, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	if !h.ready(w) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), supportBundleJobDBTimeout)
	defer cancel()
	var status string
	var expiresAt *time.Time
	var payload []byte
	var auditPending *string
	err = h.db.Pool().QueryRow(ctx, `
SELECT status, expires_at, payload, audit_pending FROM support_bundle_jobs WHERE id = $1 AND org_id = $2`, id, subject.OrgID).
		Scan(&status, &expiresAt, &payload, &auditPending)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "support bundle job not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle job unavailable")
		return
	}
	if status == "expired" || expiresAt != nil && !time.Now().Before(*expiresAt) {
		jsonError(w, http.StatusGone, "support bundle job expired")
		return
	}
	if status != "ready" {
		jsonError(w, http.StatusConflict, "support bundle job not ready")
		return
	}
	if auditPending != nil || h.appendAudit == nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle unavailable")
		return
	}
	var bundle supportBundleDTO
	if err := json.Unmarshal(payload, &bundle); err != nil || bundle.OrgID != subject.OrgID.String() || verifySupportBundleIntegrity(bundle) != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle unavailable")
		return
	}
	eventID, err := h.logEvent(ctx, "support.bundle.job.download", id, subject.OrgID, &subject.UserID, r,
		map[string]any{"bundle_id": bundle.BundleID})
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle unavailable")
		return
	}
	if _, err := h.db.Pool().Exec(ctx, `UPDATE support_bundle_jobs SET audit_event_id = $1 WHERE id = $2 AND org_id = $3 AND status = 'ready'`, *eventID, id, subject.OrgID); err != nil {
		slog.Warn("support bundle job audit link failed", slog.String("err", err.Error()))
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, supportBundleFilename(bundle.GeneratedAt)))
	writeJSON(w, http.StatusOK, bundle)
}

func (h *SupportBundleJobs) RunWorker(ctx context.Context) {
	if h == nil || h.db == nil || h.db.Pool() == nil {
		return
	}
	ticker := time.NewTicker(supportBundleJobPollInterval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if err := h.reconcileAudit(ctx, nil); err != nil && ctx.Err() == nil {
			slog.Warn("support bundle job audit retry failed", slog.String("err", err.Error()))
		}
		if err := h.expireJobs(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("support bundle job expiry failed", slog.String("err", err.Error()))
		}
		processed, err := h.runOne(ctx)
		if err != nil && ctx.Err() == nil {
			slog.Warn("support bundle job worker failed", slog.String("err", err.Error()))
		}
		if processed && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type supportBundleJobClaim struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	RequestedBy *uuid.UUID
	Attempts    int
}

func (h *SupportBundleJobs) runOne(ctx context.Context) (bool, error) {
	claimCtx, cancel := context.WithTimeout(ctx, supportBundleJobDBTimeout)
	defer cancel()
	var job supportBundleJobClaim
	err := h.db.Pool().QueryRow(claimCtx, `
WITH candidate AS (
    SELECT id FROM support_bundle_jobs
    WHERE status = 'queued' OR (status = 'running' AND lease_expires_at < now())
    ORDER BY created_at, id
    FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE support_bundle_jobs AS job
SET status = 'running', started_at = now(), lease_expires_at = now() + $1 * interval '1 second',
    attempts = job.attempts + 1, error = NULL
FROM candidate WHERE job.id = candidate.id
RETURNING job.id, job.org_id, job.requested_by, job.attempts`, int(supportBundleJobLease.Seconds())).
		Scan(&job.ID, &job.OrgID, &job.RequestedBy, &job.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	buildCtx, buildCancel := context.WithTimeout(ctx, supportBundleJobBuildTimeout)
	defer buildCancel()
	bundle, buildErr := h.build(buildCtx, Subject{OrgID: job.OrgID})
	if buildErr == nil && buildCtx.Err() != nil {
		buildErr = buildCtx.Err()
	}
	if buildErr == nil {
		buildErr = verifySupportBundleIntegrity(bundle)
	}
	if buildErr == nil {
		var redacted map[string]any
		redacted, buildErr = redactSupportBundleSections(bundle.Sections)
		if buildErr == nil {
			var hash string
			hash, buildErr = supportBundleHash(redacted)
			if buildErr == nil && (!bundle.Redaction.Applied || bundle.OrgID != job.OrgID.String() || hash != bundle.Integrity.SHA256) {
				buildErr = errors.New("support bundle redaction required")
			}
		}
	}
	var payload []byte
	var bundleID uuid.UUID
	if buildErr == nil {
		bundleID, buildErr = uuid.Parse(bundle.BundleID)
	}
	if buildErr == nil {
		payload, buildErr = json.Marshal(bundle)
	}
	if buildErr != nil {
		slog.Warn("support bundle job generation failed", slog.String("job_id", job.ID.String()))
	}
	finishCtx, finishCancel := context.WithTimeout(ctx, supportBundleJobDBTimeout)
	defer finishCancel()
	var tag pgconn.CommandTag
	if buildErr != nil {
		tag, err = h.db.Pool().Exec(finishCtx, `
UPDATE support_bundle_jobs SET status = 'failed', finished_at = now(), expires_at = now() + $1 * interval '1 second',
    lease_expires_at = NULL, error = $2, payload = NULL, audit_pending = 'failed', audit_event_id = NULL
WHERE id = $3 AND status = 'running' AND attempts = $4`, int(supportBundleJobRetention.Seconds()), supportBundleJobFailure, job.ID, job.Attempts)
	} else {
		tag, err = h.db.Pool().Exec(finishCtx, `
UPDATE support_bundle_jobs SET status = 'ready', finished_at = now(), expires_at = now() + $1 * interval '1 second',
    lease_expires_at = NULL, bundle_id = $2, payload = $3::jsonb, error = NULL,
    audit_pending = 'ready', audit_event_id = NULL
WHERE id = $4 AND status = 'running' AND attempts = $5`, int(supportBundleJobRetention.Seconds()), bundleID, payload, job.ID, job.Attempts)
	}
	if err != nil || tag.RowsAffected() == 0 {
		return true, err
	}
	return true, h.reconcileAudit(ctx, &job.ID)
}

func (h *SupportBundleJobs) reconcileAudit(ctx context.Context, jobID *uuid.UUID) error {
	if h.appendAudit == nil {
		return errors.New("support bundle audit unavailable")
	}
	queryCtx, cancel := context.WithTimeout(ctx, supportBundleJobDBTimeout)
	defer cancel()
	tx, err := h.db.Pool().Begin(queryCtx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(queryCtx) }()
	query := `SELECT id, org_id, requested_by, audit_pending, bundle_id
FROM support_bundle_jobs WHERE audit_pending IS NOT NULL`
	args := []any{}
	if jobID != nil {
		query += ` AND id = $1`
		args = append(args, *jobID)
	}
	query += ` ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1`
	var id, orgID uuid.UUID
	var actorID, bundleID *uuid.UUID
	var pending string
	err = tx.QueryRow(queryCtx, query, args...).Scan(&id, &orgID, &actorID, &pending, &bundleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	action := "support.bundle.job." + pending
	after := map[string]any{}
	if pending == "ready" && bundleID != nil {
		after["bundle_id"] = bundleID.String()
	} else {
		after["error"] = supportBundleJobFailure
	}
	eventID, err := h.logEvent(queryCtx, action, id, orgID, actorID, nil, after)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(queryCtx, `UPDATE support_bundle_jobs SET audit_pending = NULL, audit_event_id = $1 WHERE id = $2`, *eventID, id); err != nil {
		return err
	}
	return tx.Commit(queryCtx)
}

func (h *SupportBundleJobs) expireJobs(ctx context.Context) error {
	queryCtx, cancel := context.WithTimeout(ctx, supportBundleJobDBTimeout)
	defer cancel()
	_, err := h.db.Pool().Exec(queryCtx, `
WITH candidate AS (
    SELECT id FROM support_bundle_jobs
    WHERE status IN ('ready', 'failed') AND expires_at <= now()
    ORDER BY expires_at, id FOR UPDATE SKIP LOCKED LIMIT 100
)
UPDATE support_bundle_jobs AS job
SET status = 'expired', payload = NULL, error = NULL, lease_expires_at = NULL
FROM candidate WHERE job.id = candidate.id`)
	return err
}

func (h *SupportBundleJobs) ready(w http.ResponseWriter) bool {
	if h == nil || h.db == nil || h.db.Pool() == nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle jobs unavailable")
		return false
	}
	return true
}

type supportBundleJobScanner interface {
	Scan(...any) error
}

func scanSupportBundleJob(row supportBundleJobScanner, job *supportBundleJobDTO) error {
	var message *string
	if err := row.Scan(&job.ID, &job.Status, &job.CreatedAt, &job.StartedAt, &job.FinishedAt,
		&job.ExpiresAt, &job.BundleID, &message, &job.AuditEventID); err != nil {
		return err
	}
	if message != nil {
		job.Error = *message
	}
	if job.ExpiresAt != nil && !time.Now().Before(*job.ExpiresAt) {
		job.Status = "expired"
		job.Error = ""
	}
	return nil
}

func (h *SupportBundleJobs) logEvent(ctx context.Context, action string, jobID, orgID uuid.UUID, actorID *uuid.UUID, request *http.Request, after any) (*int64, error) {
	if h.appendAudit == nil {
		return nil, errors.New("support bundle audit unavailable")
	}
	event := audit.Event{OrgID: &orgID, ActorID: actorID, Action: action, TargetKind: "support_bundle_job", TargetID: jobID.String(), After: after}
	if request != nil {
		event.ActorIP = actorIPFromRequest(request)
		event.RequestID = chimw.GetReqID(request.Context())
	}
	id, _, err := h.appendAudit(ctx, event)
	if err != nil {
		slog.Warn("support bundle job audit failed", slog.String("job_id", jobID.String()))
		return nil, err
	}
	return &id, nil
}
