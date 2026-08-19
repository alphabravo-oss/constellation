// Wave N8: DB-backed compliance scheduling.
//
// ComplianceSchedulesDB is the production handler wired by server.go. It
// reads/writes the compliance_schedules + compliance_runs tables introduced by
// migration 039 and is consumed by the constellation-compliance-scheduler
// daemon.
//
// Endpoints:
//
//	GET    /api/v1/compliance/schedules                  list (?cluster_id= optional)
//	POST   /api/v1/compliance/schedules                  create
//	GET    /api/v1/compliance/schedules/{id}             get
//	PATCH  /api/v1/compliance/schedules/{id}             update
//	DELETE /api/v1/compliance/schedules/{id}             delete
//	POST   /api/v1/compliance/schedules/{id}/run-now     enqueue an immediate run
//	GET    /api/v1/compliance/schedules/{id}/runs        run history
//	GET    /api/v1/compliance/runs/{id}/artifact         stream the PDF/JSON
package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/robfig/cron/v3"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// ComplianceSchedulesDB is the production handler backed by Postgres.
type ComplianceSchedulesDB struct {
	db    *db.DB
	audit *audit.Logger
}

// NewComplianceSchedulesDB constructs the production handler.
func NewComplianceSchedulesDB(d *db.DB, a *audit.Logger) *ComplianceSchedulesDB {
	return &ComplianceSchedulesDB{db: d, audit: a}
}

// DeliveryTarget is one entry in the schedule's delivery jsonb array.
type DeliveryTarget struct {
	Kind       string `json:"kind"` // email | s3 | webhook | file
	Target     string `json:"target,omitempty"`
	Bucket     string `json:"bucket,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"` // S3 endpoint (MinIO compatible)
	ReceiverID string `json:"receiver_id,omitempty"`
	URL        string `json:"url,omitempty"`
}

type complianceScheduleRow struct {
	ID              uuid.UUID        `json:"id"`
	OrgID           uuid.UUID        `json:"org_id"`
	ClusterID       *uuid.UUID       `json:"cluster_id,omitempty"`
	Name            string           `json:"name"`
	Description     string           `json:"description"`
	Framework       string           `json:"framework"`
	CronExpression  string           `json:"cron_expression"`
	Timezone        string           `json:"timezone"`
	Enabled         bool             `json:"enabled"`
	Delivery        []DeliveryTarget `json:"delivery"`
	ReportFormat    string           `json:"report_format"`
	ReportTemplate  string           `json:"report_template"`
	LastRunAt       *time.Time       `json:"last_run_at,omitempty"`
	NextRunAt       *time.Time       `json:"next_run_at,omitempty"`
	LastStatus      string           `json:"last_status,omitempty"`
	LastArtifactURI string           `json:"last_artifact_uri,omitempty"`
	LastError       string           `json:"last_error,omitempty"`
	CreatedBy       *uuid.UUID       `json:"created_by,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

type complianceRunRow struct {
	ID                uuid.UUID      `json:"id"`
	OrgID             uuid.UUID      `json:"org_id"`
	ClusterID         *uuid.UUID     `json:"cluster_id,omitempty"`
	ScheduleID        *uuid.UUID     `json:"schedule_id,omitempty"`
	Framework         string         `json:"framework"`
	StartedAt         time.Time      `json:"started_at"`
	CompletedAt       *time.Time     `json:"completed_at,omitempty"`
	Status            string         `json:"status"`
	Summary           map[string]any `json:"summary"`
	ArtifactURI       string         `json:"artifact_uri,omitempty"`
	ArtifactSignature string         `json:"artifact_signature,omitempty"`
	ArtifactSizeBytes int64          `json:"artifact_size_bytes,omitempty"`
	TriggeredBy       string         `json:"triggered_by"`
	ErrorMessage      string         `json:"error_message,omitempty"`
}

// NextRunFromCron computes the next fire time from a cron expression in the given timezone.
// Standard 5-field cron. Returns a non-nil time and a nil error on success.
func NextRunFromCron(expr, tz string, from time.Time) (time.Time, error) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	sched, err := parser.Parse(expr)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse cron %q: %w", expr, err)
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	from = from.In(loc)
	next := sched.Next(from)
	// robfig/cron returns the zero time for a parseable-but-impossible spec
	// (e.g. "0 0 30 2 *"). Reject it so callers never persist a zero next_run_at
	// that would make the scheduler fire on every tick.
	if next.IsZero() || !next.After(from) {
		return time.Time{}, fmt.Errorf("cron %q has no future occurrences", expr)
	}
	return next.UTC(), nil
}

// List returns the org's schedules. ?cluster_id= filters to that cluster's schedules
// (and includes org-wide schedules with cluster_id=NULL when ?include_org_wide=1).
func (h *ComplianceSchedulesDB) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// When ?cluster_id is set, return rows for that cluster OR org-wide (cluster_id IS NULL).
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, org_id, cluster_id, name, description, framework, cron_expression, timezone, enabled,
       COALESCE(delivery,'[]'::jsonb), report_format, report_template,
       last_run_at, next_run_at, COALESCE(last_status,''), COALESCE(last_artifact_uri,''),
       COALESCE(last_error,''), created_by, created_at, updated_at
  FROM compliance_schedules
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2 OR cluster_id IS NULL)
 ORDER BY name`, subj.OrgID, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	out := []complianceScheduleRow{}
	for rows.Next() {
		row, err := scanScheduleRow(rows)
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, row)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"schedules": out,
		"summary": map[string]int{
			"total":    len(out),
			"enabled":  countEnabled(out),
			"disabled": len(out) - countEnabled(out),
		},
		"frameworks":     defaultFrameworkIDs(),
		"report_formats": []string{"pdf", "json", "sarif", "csv"},
	})
}

// Get returns a single schedule by id.
func (h *ComplianceSchedulesDB) Get(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	row, err := h.loadSchedule(r.Context(), subj.OrgID, id)
	if err != nil {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, row)
}

type createScheduleReq struct {
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	ClusterID      *string          `json:"cluster_id"`
	Framework      string           `json:"framework"`
	CronExpression string           `json:"cron_expression"`
	Timezone       string           `json:"timezone"`
	Enabled        *bool            `json:"enabled"`
	Delivery       []DeliveryTarget `json:"delivery"`
	ReportFormat   string           `json:"report_format"`
	ReportTemplate string           `json:"report_template"`
}

// Create inserts a schedule and computes its first next_run_at.
func (h *ComplianceSchedulesDB) Create(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	var req createScheduleReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Framework) == "" || strings.TrimSpace(req.CronExpression) == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "name, framework, cron_expression are required"})
		return
	}
	if req.Timezone == "" {
		req.Timezone = "UTC"
	}
	if req.ReportFormat == "" {
		req.ReportFormat = "pdf"
	}
	if req.ReportTemplate == "" {
		req.ReportTemplate = "compliance-detailed"
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	next, err := NextRunFromCron(req.CronExpression, req.Timezone, time.Now())
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var clusterArg any
	if req.ClusterID != nil && *req.ClusterID != "" {
		cid, err := uuid.Parse(*req.ClusterID)
		if err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster_id"})
			return
		}
		clusterArg = cid
	}
	if req.Delivery == nil {
		req.Delivery = []DeliveryTarget{}
	}
	deliveryRaw, _ := json.Marshal(req.Delivery)

	var id uuid.UUID
	err = h.db.Pool().QueryRow(r.Context(), `
INSERT INTO compliance_schedules (org_id, cluster_id, name, description, framework,
                                  cron_expression, timezone, enabled, delivery,
                                  report_format, report_template, next_run_at, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13)
RETURNING id`,
		subj.OrgID, clusterArg, req.Name, req.Description, req.Framework,
		req.CronExpression, req.Timezone, enabled, deliveryRaw,
		req.ReportFormat, req.ReportTemplate, next, subj.UserID).Scan(&id)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action:     "compliance.schedule.create",
		TargetKind: "compliance_schedule",
		TargetID:   id.String(),
		After:      map[string]any{"name": req.Name, "framework": req.Framework, "cron": req.CronExpression},
	})
	row, _ := h.loadSchedule(r.Context(), subj.OrgID, id)
	httpx.WriteJSON(w, http.StatusCreated, row)
}

type patchScheduleReq struct {
	Name           *string           `json:"name"`
	Description    *string           `json:"description"`
	Enabled        *bool             `json:"enabled"`
	CronExpression *string           `json:"cron_expression"`
	Timezone       *string           `json:"timezone"`
	Delivery       *[]DeliveryTarget `json:"delivery"`
	ReportFormat   *string           `json:"report_format"`
	ReportTemplate *string           `json:"report_template"`
	Framework      *string           `json:"framework"`
}

// Patch updates a subset of the schedule fields.
func (h *ComplianceSchedulesDB) Patch(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	existing, err := h.loadSchedule(r.Context(), subj.OrgID, id)
	if err != nil {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	var req patchScheduleReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.CronExpression != nil {
		existing.CronExpression = *req.CronExpression
	}
	if req.Timezone != nil {
		existing.Timezone = *req.Timezone
	}
	if req.Delivery != nil {
		existing.Delivery = *req.Delivery
	}
	if req.ReportFormat != nil {
		existing.ReportFormat = *req.ReportFormat
	}
	if req.ReportTemplate != nil {
		existing.ReportTemplate = *req.ReportTemplate
	}
	if req.Framework != nil {
		existing.Framework = *req.Framework
	}
	next, err := NextRunFromCron(existing.CronExpression, existing.Timezone, time.Now())
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	deliveryRaw, _ := json.Marshal(existing.Delivery)
	_, err = h.db.Pool().Exec(r.Context(), `
UPDATE compliance_schedules
   SET name=$1, description=$2, enabled=$3, cron_expression=$4, timezone=$5,
       delivery=$6::jsonb, report_format=$7, report_template=$8, framework=$9,
       next_run_at=$10, updated_at=NOW()
 WHERE id=$11 AND org_id=$12`,
		existing.Name, existing.Description, existing.Enabled, existing.CronExpression,
		existing.Timezone, deliveryRaw, existing.ReportFormat, existing.ReportTemplate,
		existing.Framework, next, id, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action:     "compliance.schedule.update",
		TargetKind: "compliance_schedule",
		TargetID:   id.String(),
		After:      map[string]any{"enabled": existing.Enabled, "cron": existing.CronExpression},
	})
	row, _ := h.loadSchedule(r.Context(), subj.OrgID, id)
	httpx.WriteJSON(w, http.StatusOK, row)
}

// Delete removes a schedule.
func (h *ComplianceSchedulesDB) Delete(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	ct, err := h.db.Pool().Exec(r.Context(), `DELETE FROM compliance_schedules WHERE id=$1 AND org_id=$2`, id, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if ct.RowsAffected() == 0 {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action:     "compliance.schedule.delete",
		TargetKind: "compliance_schedule",
		TargetID:   id.String(),
	})
	w.WriteHeader(http.StatusNoContent)
}

// RunNow forces the schedule's next_run_at to NOW() so the daemon picks it up immediately.
// Returns the schedule envelope; the actual run row is inserted by the worker.
func (h *ComplianceSchedulesDB) RunNow(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	ct, err := h.db.Pool().Exec(r.Context(), `
UPDATE compliance_schedules
   SET next_run_at = NOW(), enabled = TRUE, updated_at = NOW()
 WHERE id=$1 AND org_id=$2`, id, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if ct.RowsAffected() == 0 {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action:     "compliance.schedule.run_now",
		TargetKind: "compliance_schedule",
		TargetID:   id.String(),
	})
	row, _ := h.loadSchedule(r.Context(), subj.OrgID, id)
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"schedule": row,
		"queued":   true,
		"message":  "schedule queued for immediate run; the constellation-compliance-scheduler daemon will pick it up within 30s",
	})
}

// Runs returns the recent run history for a schedule.
func (h *ComplianceSchedulesDB) Runs(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, org_id, cluster_id, schedule_id, framework, started_at, completed_at,
       status, COALESCE(summary,'{}'::jsonb), COALESCE(artifact_uri,''),
       COALESCE(artifact_signature,''), COALESCE(artifact_size_bytes,0),
       triggered_by, COALESCE(error_message,'')
  FROM compliance_runs
 WHERE org_id=$1 AND schedule_id=$2
 ORDER BY started_at DESC
 LIMIT $3`, subj.OrgID, id, limit)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []complianceRunRow{}
	for rows.Next() {
		row, err := scanRunRow(rows)
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, row)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"runs": out})
}

// Artifact streams the PDF/JSON artifact bytes for one run. file:// URIs are read from
// disk; s3:// URIs are returned as a 302 redirect (S3 presigning is out of scope for v1
// — callers with S3 creds can fetch directly).
func (h *ComplianceSchedulesDB) Artifact(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var uri, sig, format string
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT COALESCE(artifact_uri,''), COALESCE(artifact_signature,''),
       (SELECT report_format FROM compliance_schedules s WHERE s.id = r.schedule_id)
  FROM compliance_runs r
 WHERE r.id=$1 AND r.org_id=$2`, id, subj.OrgID).Scan(&uri, &sig, &format)
	if err != nil {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "run not found"})
		return
	}
	if uri == "" {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "no artifact for this run"})
		return
	}
	if sig != "" {
		w.Header().Set("X-Constellation-Cosign-Signature", sig)
	}
	if strings.HasPrefix(uri, "file://") {
		path := strings.TrimPrefix(uri, "file://")
		f, err := os.Open(path)
		if err != nil {
			httpx.WriteJSON(w, http.StatusGone, map[string]string{"error": "artifact file missing"})
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", contentTypeFor(format))
		w.Header().Set("Content-Disposition", `inline; filename="compliance-`+id.String()+`.`+strings.ToLower(format)+`"`)
		_, _ = io.Copy(w, f)
		return
	}
	if strings.HasPrefix(uri, "s3://") {
		// Best-effort: return the URI so the UI can deep-link via the operator's
		// S3 console. Pre-signing requires bucket-scoped creds we don't hold here.
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"artifact_uri": uri, "signature": sig})
		return
	}
	// Unknown scheme — return metadata.
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"artifact_uri": uri, "signature": sig})
}

// loadSchedule fetches a single schedule scoped to org.
func (h *ComplianceSchedulesDB) loadSchedule(ctx context.Context, orgID, id uuid.UUID) (complianceScheduleRow, error) {
	row := h.db.Pool().QueryRow(ctx, `
SELECT id, org_id, cluster_id, name, description, framework, cron_expression, timezone, enabled,
       COALESCE(delivery,'[]'::jsonb), report_format, report_template,
       last_run_at, next_run_at, COALESCE(last_status,''), COALESCE(last_artifact_uri,''),
       COALESCE(last_error,''), created_by, created_at, updated_at
  FROM compliance_schedules
 WHERE id = $1 AND org_id = $2`, id, orgID)
	return scanScheduleRow(row)
}

func scanScheduleRow(s rowScanner) (complianceScheduleRow, error) {
	var row complianceScheduleRow
	var clusterID, createdBy *uuid.UUID
	var deliveryRaw []byte
	if err := s.Scan(&row.ID, &row.OrgID, &clusterID, &row.Name, &row.Description, &row.Framework,
		&row.CronExpression, &row.Timezone, &row.Enabled, &deliveryRaw, &row.ReportFormat,
		&row.ReportTemplate, &row.LastRunAt, &row.NextRunAt, &row.LastStatus,
		&row.LastArtifactURI, &row.LastError, &createdBy, &row.CreatedAt, &row.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return row, errors.New("schedule not found")
		}
		return row, err
	}
	row.ClusterID = clusterID
	row.CreatedBy = createdBy
	if len(deliveryRaw) > 0 {
		_ = json.Unmarshal(deliveryRaw, &row.Delivery)
	}
	if row.Delivery == nil {
		row.Delivery = []DeliveryTarget{}
	}
	return row, nil
}

func scanRunRow(s rowScanner) (complianceRunRow, error) {
	var row complianceRunRow
	var clusterID, scheduleID *uuid.UUID
	var summaryRaw []byte
	if err := s.Scan(&row.ID, &row.OrgID, &clusterID, &scheduleID, &row.Framework,
		&row.StartedAt, &row.CompletedAt, &row.Status, &summaryRaw, &row.ArtifactURI,
		&row.ArtifactSignature, &row.ArtifactSizeBytes, &row.TriggeredBy, &row.ErrorMessage); err != nil {
		return row, err
	}
	row.ClusterID = clusterID
	row.ScheduleID = scheduleID
	if len(summaryRaw) > 0 {
		_ = json.Unmarshal(summaryRaw, &row.Summary)
	}
	return row, nil
}

func countEnabled(rows []complianceScheduleRow) int {
	n := 0
	for _, r := range rows {
		if r.Enabled {
			n++
		}
	}
	return n
}

func defaultFrameworkIDs() []string {
	return []string{
		"cis-k8s-1.9", "cis-docker-1.6", "nsa-cisa-k8s", "nist-800-53-rev5",
		"nist-800-190", "pci-dss-4.0", "hipaa", "soc-2", "stig", "fedramp-moderate",
		"nis2-eu", "dora-eu", "iso-27001", "iso-27017", "iso-27018", "csa-ccm",
	}
}

func contentTypeFor(format string) string {
	switch strings.ToLower(format) {
	case "pdf":
		return "application/pdf"
	case "json":
		return "application/json"
	case "sarif":
		return "application/sarif+json"
	case "csv":
		return "text/csv"
	default:
		return "application/octet-stream"
	}
}

// urlEscape is unused now but reserved for the future S3 pre-signer path. Keeping
// it here so go vet stays quiet if a build wires it next iteration.
var _ = url.QueryEscape
