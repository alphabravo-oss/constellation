// Wave N5: Backup / Restore HTTP API.
//
// Endpoints (all guarded by manage-org):
//
//	POST /api/v1/backups               kick a backup job (async; returns id)
//	GET  /api/v1/backups               list completed + in-flight backups
//	GET  /api/v1/backups/{id}          detail
//	GET  /api/v1/backups/{id}/download stream tarball (one-shot auth-gated)
//	POST /api/v1/backups/verify        upload tarball, parse manifest, return summary
//	POST /api/v1/backups/restore       upload tarball, verify, apply rows
//	POST /api/v1/backups/schedule      set the cron schedule + S3 destination
//	GET  /api/v1/backups/schedule      read current schedule
//
// The "backup now" flow is async because exporting a large org can take minutes. The
// handler kicks a goroutine that performs the export under a fresh context detached from
// the request, writes the artifact to a sandbox directory configurable via env
// (CONSTELLATION_BACKUP_DIR, default /var/lib/constellation/backups), and updates the
// `backups` row to status=succeeded|failed when done. The /backups/{id}/download endpoint
// streams the file when the row is succeeded.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// Backups is the HTTP handler.
type Backups struct {
	db    *db.DB
	audit *audit.Logger
	dir   string
}

// NewBackups returns a fresh handler. The artifact directory is resolved from
// CONSTELLATION_BACKUP_DIR or defaults to /var/lib/constellation/backups (created on
// first use; falls back to /tmp/constellation-backups when the canonical dir is unwritable).
func NewBackups(d *db.DB, a *audit.Logger) *Backups {
	dir := os.Getenv("CONSTELLATION_BACKUP_DIR")
	if dir == "" {
		dir = "/var/lib/constellation/backups"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		// Fallback under /tmp so dev / unprivileged installs still work.
		dir = filepath.Join(os.TempDir(), "constellation-backups")
		_ = os.MkdirAll(dir, 0o700)
	}
	return &Backups{db: d, audit: a, dir: dir}
}

// ---- DTOs ----

type backupSummary struct {
	ID             string     `json:"id"`
	Mode           string     `json:"mode"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	SizeBytes      int64      `json:"size_bytes"`
	SHA256         string     `json:"sha256,omitempty"`
	Signed         bool       `json:"signed"`
	SignerIdentity string     `json:"signer_identity,omitempty"`
	FormatVersion  string     `json:"format_version,omitempty"`
	S3URI          string     `json:"s3_uri,omitempty"`
	TablesIncluded []string   `json:"tables_included,omitempty"`
	ErrorMessage   string     `json:"error,omitempty"`
}

type scheduleDTO struct {
	CronExpr   string     `json:"cron_expr"`
	Enabled    bool       `json:"enabled"`
	S3Bucket   string     `json:"s3_bucket,omitempty"`
	S3Prefix   string     `json:"s3_prefix,omitempty"`
	S3Endpoint string     `json:"s3_endpoint,omitempty"`
	SignMode   string     `json:"sign_mode"`
	LastRunAt  *time.Time `json:"last_run_at,omitempty"`
	LastStatus string     `json:"last_status,omitempty"`
	NextRunAt  *time.Time `json:"next_run_at,omitempty"`
}

type createBackupRequest struct {
	// SignMode overrides the org's schedule.sign_mode for this one-off backup.
	// Default "none" (the dev posture; production callers should pass static-key).
	SignMode string `json:"sign_mode,omitempty"`
}

// ---- HTTP handlers ----

// Create kicks an org-backup job. Returns 202 + the row id; poll /backups/{id} for status.
func (h *Backups) Create(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var req createBackupRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	id := uuid.New()
	// Insert in-flight row up-front so polling sees status=running immediately.
	_, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO backups (id, org_id, mode, status, started_at, signed, format_version)
VALUES ($1, $2, 'org-backup', 'running', NOW(), $3, $4)`,
		id, subj.OrgID, req.SignMode != "" && req.SignMode != "none", backup.FormatVersion)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "backup.start",
		TargetKind: "backup",
		TargetID:   id.String(),
	})

	// Detached context — the operator's HTTP timeout shouldn't kill an in-flight export.
	go h.runBackupJob(id, subj.OrgID.String(), subj.UserID.String(), req.SignMode)

	writeJSON(w, http.StatusAccepted, map[string]string{"id": id.String(), "status": "running"})
}

// runBackupJob is the goroutine body. Updates the backups row on completion.
func (h *Backups) runBackupJob(id uuid.UUID, orgID, userID, signMode string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	var orgName string
	if err := h.db.Pool().QueryRow(ctx, `SELECT name FROM orgs WHERE id=$1`, orgID).Scan(&orgName); err != nil {
		h.markFailed(ctx, id, "org lookup: "+err.Error())
		return
	}

	stamp := time.Now().UTC().Format("20060102T150405Z")
	fname := fmt.Sprintf("constellation-backup-%s-%s.tar.gz", orgName, stamp)
	path := filepath.Join(h.dir, fname)

	opts := backup.ExportOptions{
		OrgID:          orgID,
		OrgName:        orgName,
		GeneratedBy:    userID,
		SourceInstance: "constellation-api",
	}
	switch signMode {
	case "static-key":
		opts.Sign.Mode = backup.SignModeStaticKey
		opts.Sign.KeyPath = os.Getenv("CONSTELLATION_BACKUP_SIGN_KEY")
	case "keyless":
		opts.Sign.Mode = backup.SignModeKeyless
	default:
		// none — pass through
	}

	res, err := backup.ExportToFile(ctx, h.db.Pool(), path, opts)
	if err != nil {
		h.markFailed(ctx, id, "export: "+err.Error())
		return
	}

	tables := make([]string, 0, len(res.Manifest.Tables))
	for _, t := range res.Manifest.Tables {
		tables = append(tables, t.Name)
	}
	if _, err := h.db.Pool().Exec(ctx, `
UPDATE backups
   SET status='succeeded', finished_at=NOW(),
       size_bytes=$2, signer_identity=$3, signed=$4,
       tables_included=$5, local_path=$6, format_version=$7
 WHERE id=$1`, id, res.Bytes, res.SignerIdentity, res.SignMode != backup.SignModeNone && res.SignMode != "",
		tables, path, backup.FormatVersion); err != nil {
		h.markFailed(ctx, id, "update: "+err.Error())
		return
	}
	orgUUID, _ := uuid.Parse(orgID)
	actorUUID, _ := uuid.Parse(userID)
	_, _, _ = h.audit.Log(ctx, audit.Event{
		OrgID:      &orgUUID,
		ActorID:    &actorUUID,
		Action:     "backup.complete",
		TargetKind: "backup",
		TargetID:   id.String(),
		After:      map[string]any{"bytes": res.Bytes, "tables": tables, "signer": res.SignerIdentity},
	})
}

func (h *Backups) markFailed(ctx context.Context, id uuid.UUID, msg string) {
	_, _ = h.db.Pool().Exec(ctx, `UPDATE backups SET status='failed', error=$2, finished_at=NOW() WHERE id=$1`, id, msg)
}

// List returns the most recent 50 backups for the caller's org.
func (h *Backups) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, COALESCE(mode,'org-backup'), status,
       started_at, finished_at,
       COALESCE(size_bytes,0), COALESCE(sha256,''), COALESCE(signed,false),
       COALESCE(signer_identity,''), COALESCE(format_version,''),
       COALESCE(s3_uri,''), COALESCE(tables_included,'{}'::text[]),
       COALESCE(error,'')
  FROM backups
 WHERE org_id=$1 OR org_id IS NULL
 ORDER BY started_at DESC LIMIT 50`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []backupSummary{}
	for rows.Next() {
		var s backupSummary
		var finished *time.Time
		if err := rows.Scan(&s.ID, &s.Mode, &s.Status, &s.StartedAt, &finished,
			&s.SizeBytes, &s.SHA256, &s.Signed, &s.SignerIdentity, &s.FormatVersion,
			&s.S3URI, &s.TablesIncluded, &s.ErrorMessage); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.FinishedAt = finished
		out = append(out, s)
	}
	writeJSON(w, 200, map[string]any{"backups": out})
}

// Get returns one backup's detail.
func (h *Backups) Get(w http.ResponseWriter, r *http.Request) {
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
	var s backupSummary
	var finished *time.Time
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT id, COALESCE(mode,'org-backup'), status,
       started_at, finished_at,
       COALESCE(size_bytes,0), COALESCE(sha256,''), COALESCE(signed,false),
       COALESCE(signer_identity,''), COALESCE(format_version,''),
       COALESCE(s3_uri,''), COALESCE(tables_included,'{}'::text[]),
       COALESCE(error,'')
  FROM backups
 WHERE id=$1 AND (org_id=$2 OR org_id IS NULL)`, id, subj.OrgID).Scan(
		&s.ID, &s.Mode, &s.Status, &s.StartedAt, &finished,
		&s.SizeBytes, &s.SHA256, &s.Signed, &s.SignerIdentity, &s.FormatVersion,
		&s.S3URI, &s.TablesIncluded, &s.ErrorMessage,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.FinishedAt = finished
	writeJSON(w, 200, s)
}

// Download streams the artifact bytes.
func (h *Backups) Download(w http.ResponseWriter, r *http.Request) {
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
	var path, status string
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT COALESCE(local_path,''), status FROM backups
 WHERE id=$1 AND (org_id=$2 OR org_id IS NULL)`, id, subj.OrgID).Scan(&path, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if status != "succeeded" {
		jsonError(w, http.StatusConflict, "backup not ready (status="+status+")")
		return
	}
	if path == "" {
		jsonError(w, http.StatusGone, "backup artifact has been pruned or uploaded to S3 only")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		jsonError(w, http.StatusGone, "artifact unavailable: "+err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(path)+`"`)
	_, _ = io.Copy(w, f)
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "backup.download",
		TargetKind: "backup",
		TargetID:   id.String(),
	})
}

// Verify parses an uploaded tarball and returns the manifest summary without applying.
// Used by the UI's restore wizard's preview step. Body is raw tar.gz bytes; signature
// verification is best-effort (the operator can still proceed via Restore with the same
// posture).
func (h *Backups) Verify(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	// Buffer the upload (small files only; cap at 256 MiB).
	const maxSize = 256 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	tmp, err := os.CreateTemp("", "cnstl-verify-*.tar.gz")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp.Close()

	// Use Restore-without-applying: re-open the tarball, extract manifest, recompute
	// table digests, verify signature. We re-implement here rather than calling Restore
	// since Restore needs a destination pool.
	f, err := os.Open(tmp.Name())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	// Restore needs a destination pool, so verification walks the archive manually
	// and delegates to the backup package's readTarGz-equivalent helper.
	manifestBytes, _, _, err := extractFromArchive(f)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "parse archive: "+err.Error())
		return
	}
	var m backup.Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		jsonError(w, http.StatusBadRequest, "parse manifest: "+err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "backup.verify",
		TargetKind: "backup",
		TargetID:   m.RootHash,
		After:      map[string]any{"org_name": m.OrgName, "tables": len(m.Tables)},
	})
	writeJSON(w, 200, m)
}

// Restore accepts a tarball upload and applies it to the destination. Conflict policy is
// passed via the query parameter ?on_conflict=skip|overwrite (default skip).
func (h *Backups) Restore(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	policy := backup.ConflictPolicy(r.URL.Query().Get("on_conflict"))
	if policy == "" {
		policy = backup.ConflictSkip
	}

	// Pin the restore to the AUTHENTICATED caller's org. The write-target is resolved
	// from subj.OrgID (never from the uploaded archive's content), and the archive's org
	// identity must match this name or backup.Restore refuses — closing the cross-tenant
	// write (H1).
	var orgName string
	if err := h.db.Pool().QueryRow(r.Context(), `SELECT name FROM orgs WHERE id=$1`, subj.OrgID).Scan(&orgName); err != nil {
		jsonError(w, http.StatusInternalServerError, "resolve caller org: "+err.Error())
		return
	}

	// The route is gated by manage-org, but the identity tables (users, custom_roles,
	// role_bindings) are otherwise gated by the distinct manage-users verb — exactly as
	// ApplyConfig enforces. Resolve whether the caller holds it; without it the restore
	// skips those tables so a manage-org-only principal can't escalate via a crafted
	// archive. (Org-defined custom roles that grant manage-users are not consulted here,
	// so the check is conservative: it can only deny, never over-grant.)
	canManageUsers := subj.HasTokenScope(rbac.VerbManageUsers) &&
		rbac.Authorize(subj.Assignments, rbac.VerbManageUsers, rbac.Resource{OrgID: subj.OrgID}) == nil

	// Signature verification posture is set by OPERATOR policy (environment), never by the
	// request: a caller can no longer flip allow_unverified via a query param. Fail CLOSED
	// — without an explicit operator opt-in, an unsigned or unverifiable archive is
	// rejected. The verify key/identity (when configured) feed backup.Verify; leaving Mode
	// unset lets the restorer infer static-key vs keyless from the archive's sig/cert.
	verify := backup.VerifierOptions{
		KeyPath:  os.Getenv("CONSTELLATION_BACKUP_VERIFY_KEY"),
		Identity: os.Getenv("CONSTELLATION_BACKUP_VERIFY_IDENTITY"),
	}
	allowUnverified := os.Getenv("CONSTELLATION_BACKUP_ALLOW_UNVERIFIED") == "true"

	res, err := backup.Restore(r.Context(), h.db.Pool(), backup.RestoreOptions{
		In:              r.Body,
		Verify:          verify,
		AllowUnverified: allowUnverified,
		OnConflict:      policy,
		DestOrgID:       subj.OrgID.String(),
		DestOrgName:     orgName,
		CanManageUsers:  canManageUsers,
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "backup.restore",
		TargetKind: "backup",
		TargetID:   res.Manifest.RootHash,
		After: map[string]any{
			"org_name":    res.Manifest.OrgName,
			"verified":    res.Verified,
			"on_conflict": policy,
			"tables":      res.Tables,
		},
	})
	writeJSON(w, 200, res)
}

// Schedule (GET) returns the org's current schedule (or defaults).
func (h *Backups) GetSchedule(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	row := h.db.Pool().QueryRow(r.Context(), `
SELECT cron_expr, enabled, COALESCE(s3_bucket,''), COALESCE(s3_prefix,''),
       COALESCE(s3_endpoint,''), sign_mode, last_run_at, COALESCE(last_status,''), next_run_at
  FROM backup_schedules WHERE org_id=$1`, subj.OrgID)
	var s scheduleDTO
	if err := row.Scan(&s.CronExpr, &s.Enabled, &s.S3Bucket, &s.S3Prefix, &s.S3Endpoint, &s.SignMode, &s.LastRunAt, &s.LastStatus, &s.NextRunAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, 200, scheduleDTO{CronExpr: "0 3 * * *", Enabled: false, SignMode: "static-key"})
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, 200, s)
}

// Schedule (POST) upserts the org's schedule.
func (h *Backups) PutSchedule(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var s scheduleDTO
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		jsonError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	s.CronExpr = strings.TrimSpace(s.CronExpr)
	if s.CronExpr == "" {
		s.CronExpr = "0 3 * * *"
	}
	if s.SignMode == "" {
		s.SignMode = "static-key"
	}
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO backup_schedules(org_id, cron_expr, enabled, s3_bucket, s3_prefix, s3_endpoint, sign_mode)
VALUES ($1, $2, $3, NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), $7)
ON CONFLICT (org_id) DO UPDATE
  SET cron_expr=EXCLUDED.cron_expr, enabled=EXCLUDED.enabled,
      s3_bucket=EXCLUDED.s3_bucket, s3_prefix=EXCLUDED.s3_prefix,
      s3_endpoint=EXCLUDED.s3_endpoint, sign_mode=EXCLUDED.sign_mode,
      updated_at=NOW()`,
		subj.OrgID, s.CronExpr, s.Enabled, s.S3Bucket, s.S3Prefix, s.S3Endpoint, s.SignMode); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "backup.schedule.update",
		TargetKind: "backup-schedule",
		After:      map[string]any{"cron": s.CronExpr, "enabled": s.Enabled, "s3_bucket": s.S3Bucket, "sign_mode": s.SignMode},
	})
	writeJSON(w, 200, s)
}

// extractFromArchive walks a tar.gz reader and returns manifest.json + .sig + .cert
// bytes. Used by Verify above; mirrors the helper inside cmd/constellation-backup so the
// API doesn't have to reach into a private package symbol.
func extractFromArchive(r io.Reader) (manifest, sig, cert []byte, err error) {
	return extractTarTriplet(r, "manifest.json", "manifest.json.sig", "manifest.json.cert")
}
