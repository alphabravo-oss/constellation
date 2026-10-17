package compliance

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

func (c *Compliance) RetryBenchRequest(w http.ResponseWriter, r *http.Request) {
	scope, ok := c.userWriteScope(w, r)
	if !ok {
		return
	}
	var input struct {
		ReviewedRevision string `json:"reviewed_revision"`
	}
	if !strictBenchBody(w, r, &input, 4096) {
		return
	}
	id, validID := benchUUID(chi.URLParam(r, "id"))
	if !validID || !benchRevision(input.ReviewedRevision) {
		benchReplyError(w, http.StatusBadRequest, "invalid_review", "exact request id and reviewed revision are required")
		return
	}
	tx, ok := c.beginBenchWrite(w, r, scope)
	if !ok {
		return
	}
	defer rollbackBenchRequest(r.Context(), tx)
	req, err := loadBenchRequest(r.Context(), tx, scope.orgID, id, true)
	if err == nil && !benchVisibleToScope(req, scope) {
		err = pgx.ErrNoRows
	}
	if err != nil {
		benchRequestError(w, err)
		return
	}
	if req.Revision != input.ReviewedRevision || req.AttemptCount >= 3 || req.ActiveAttempt == nil || req.Status != "failed" && req.Status != "interrupted" {
		benchReplyError(w, http.StatusConflict, "retry_conflict", "review current terminal execution before retrying; at most three attempts are allowed")
		return
	}
	// An org-wide user request is permanently bound on its first claim. Lock
	// that actual cluster too when the user did not pass a cluster selector.
	if scope.clusterID == nil && req.ClusterID != nil {
		bound := scope
		cluster := uuid.MustParse(*req.ClusterID)
		bound.clusterID = &cluster
		if !bound.lockCluster(w, r, tx) {
			return
		}
	}
	_, err = tx.Exec(r.Context(), `UPDATE compliance_bench_attempts SET status='interrupted',finished_at=clock_timestamp(),outcome='lease_expired' WHERE id=$1 AND status='running' AND lease_expires_at<=clock_timestamp()`, req.ActiveAttempt.ID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE compliance_bench_run_requests SET status='queued',active_attempt_id=NULL,completed_at=NULL,revision=revision+1 WHERE id=$1`, req.ID)
	}
	if err == nil {
		err = c.benchAudit(r.Context(), tx, scope, "compliance.bench.v2.retry_requested", req.ID, map[string]any{"previous_attempt_id": req.ActiveAttempt.ID, "previous_status": req.Status, "cluster_id": req.ClusterID, "next_attempt": req.AttemptCount + 1})
	}
	if err != nil {
		benchRequestError(w, err)
		return
	}
	req, err = loadBenchRequest(r.Context(), tx, scope.orgID, id, false)
	if err != nil {
		benchRequestError(w, err)
		return
	}
	if benchCommit(w, r, tx) {
		httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"request": req})
	}
}
