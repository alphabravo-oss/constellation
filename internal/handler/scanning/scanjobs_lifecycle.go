package scanning

import (
	"net/http"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Pause transitions a pending scan job to paused. Running jobs are not paused mid-flight;
// workers honor the paused state by skipping claim. Idempotent for already-paused rows.
func (h *ScanJobs) Pause(w http.ResponseWriter, r *http.Request) {
	h.transitionLifecycle(w, r, "paused", `
UPDATE scan_jobs SET status = 'paused', paused_at = NOW()
 WHERE id = $1 AND org_id = $2 AND status IN ('pending', 'paused')`, "scan-job.pause")
}

// Resume transitions a paused job back to pending so workers can claim it.
func (h *ScanJobs) Resume(w http.ResponseWriter, r *http.Request) {
	h.transitionLifecycle(w, r, "pending", `
UPDATE scan_jobs SET status = 'pending', resumed_at = NOW(), paused_at = NULL
 WHERE id = $1 AND org_id = $2 AND status = 'paused'`, "scan-job.resume")
}

// Retry requeues a terminal scan job for a fresh set of attempts.
func (h *ScanJobs) Retry(w http.ResponseWriter, r *http.Request) {
	h.transitionLifecycle(w, r, "pending", `
UPDATE scan_jobs
   SET status = 'pending',
       worker_id = NULL,
       error = NULL,
       attempt_count = 0,
       next_attempt_at = NULL,
       last_attempt_at = NULL,
       last_error_at = NULL,
       claimed_at = NULL,
       lease_expires_at = NULL,
       finished_at = NULL,
       resumed_at = NOW(),
       paused_at = NULL,
       canceled_at = NULL
 WHERE id = $1 AND org_id = $2 AND status IN ('failed', 'canceled')`, "scan-job.retry")
}

// Cancel marks a job canceled. Running jobs are tagged so the worker drops the result on completion.
func (h *ScanJobs) Cancel(w http.ResponseWriter, r *http.Request) {
	h.transitionLifecycle(w, r, "canceled", `
UPDATE scan_jobs SET status = 'canceled', canceled_at = NOW(), finished_at = NOW(), lease_expires_at = NULL, next_attempt_at = NULL
 WHERE id = $1 AND org_id = $2 AND status IN ('pending', 'paused', 'running')`, "scan-job.cancel")
}

func (h *ScanJobs) transitionLifecycle(w http.ResponseWriter, r *http.Request, newStatus, sql, action string) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(), sql, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusConflict, "no transition: job not in eligible state")
		return
	}
	if action == "scan-job.cancel" {
		_, _ = h.db.Pool().Exec(r.Context(), `
UPDATE scan_job_attempts
   SET status = 'canceled',
       finished_at = NOW(),
       lease_expires_at = NULL,
       next_attempt_at = NULL
 WHERE job_id = $1
   AND org_id = $2
   AND status = 'running'`, id, subj.OrgID)
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: action,
			TargetKind: "scan-job", TargetID: id.String(),
			After: map[string]string{"status": newStatus},
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": newStatus})
}
