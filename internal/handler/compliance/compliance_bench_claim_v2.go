package compliance

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

func (c *Compliance) ClaimBenchRequest(w http.ResponseWriter, r *http.Request) {
	scope, ok := c.agentWriteScope(w, r)
	if !ok {
		return
	}
	var input compliancepkg.BenchExecutionClaim
	if !strictBenchBody(w, r, &input, 4096) || !validBenchClaim(w, input) {
		return
	}
	tx, ok := c.beginBenchWrite(w, r, scope)
	if !ok {
		return
	}
	defer rollbackBenchRequest(r.Context(), tx)
	// Serialize retries of one claim key, including concurrent lost-response
	// retries. Independent workers still select queue rows with SKIP LOCKED.
	key := scope.orgID.String() + scope.agentID.String() + input.ClaimKey
	if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,179))`, key); err != nil {
		benchRequestError(w, err)
		return
	}
	req, err := c.claimBenchRequest(r, tx, scope, input)
	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		benchRequestError(w, err)
		return
	}
	if req.ID == "" {
		benchReplyError(w, http.StatusConflict, "stale_claim", "claim no longer identifies an active execution")
		return
	}
	if benchCommit(w, r, tx) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"request": req})
	}
}

func validBenchClaim(w http.ResponseWriter, input compliancepkg.BenchExecutionClaim) bool {
	_, claimOK := benchUUID(input.ClaimKey)
	_, runnerOK := benchUUID(input.RunnerID)
	if !claimOK || !runnerOK || len(input.Node) == 0 || len(input.Node) > 253 || strings.TrimSpace(input.Node) != input.Node || strings.ContainsAny(input.Node, "\x00\r\n") {
		benchReplyError(w, http.StatusBadRequest, "invalid_claim", "claim key, runner identity, and node are required")
		return false
	}
	return true
}

func (c *Compliance) claimBenchRequest(r *http.Request, tx pgx.Tx, scope complianceWriteScope, input compliancepkg.BenchExecutionClaim) (compliancepkg.BenchExecutionRequest, error) {
	var existing string
	err := tx.QueryRow(r.Context(), `SELECT id::text FROM compliance_bench_attempts WHERE org_id=$1 AND agent_token_id=$2 AND claim_key=$3`, scope.orgID, scope.agentID, input.ClaimKey).Scan(&existing)
	if err == nil {
		return repeatBenchClaim(r, tx, scope, input, existing)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return compliancepkg.BenchExecutionRequest{}, err
	}
	var id uuid.UUID
	err = tx.QueryRow(r.Context(), `SELECT id FROM compliance_bench_run_requests WHERE protocol_version=2 AND status='queued' AND org_id=$1 AND profile='kube-bench' AND (cluster_id IS NULL OR cluster_id=$2) AND attempt_count<3 ORDER BY requested_at,id FOR UPDATE SKIP LOCKED LIMIT 1`, scope.orgID, scope.clusterID).Scan(&id)
	if err != nil {
		return compliancepkg.BenchExecutionRequest{}, err
	}
	attempt := uuid.New()
	_, err = tx.Exec(r.Context(), `INSERT INTO compliance_bench_attempts(id,request_id,org_id,cluster_id,agent_token_id,claim_key,runner_id,node,attempt_no,status,lease_expires_at)
SELECT $1,id,org_id,$2,$3,$4,$5,$6,attempt_count+1,'running',clock_timestamp()+INTERVAL '10 minutes' FROM compliance_bench_run_requests WHERE id=$7`, attempt, scope.clusterID, scope.agentID, input.ClaimKey, input.RunnerID, input.Node, id)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE compliance_bench_run_requests SET status='running',cluster_id=COALESCE(cluster_id,$1),active_attempt_id=$2,attempt_count=attempt_count+1,revision=revision+1,claimed_at=NOW(),completed_at=NULL WHERE id=$3`, scope.clusterID, attempt, id)
	}
	if err == nil {
		err = c.benchAudit(r.Context(), tx, scope, "compliance.bench.v2.claimed", id.String(), map[string]any{"attempt_id": attempt, "cluster_id": scope.clusterID, "agent_token_id": scope.agentID, "runner_id": input.RunnerID, "node": input.Node})
	}
	if err != nil {
		return compliancepkg.BenchExecutionRequest{}, err
	}
	return loadBenchRequest(r.Context(), tx, scope.orgID, id, false)
}

func repeatBenchClaim(r *http.Request, tx pgx.Tx, scope complianceWriteScope, input compliancepkg.BenchExecutionClaim, id string) (compliancepkg.BenchExecutionRequest, error) {
	attempt, _, err := loadBenchAttempt(r.Context(), tx, scope.orgID, id)
	if err != nil {
		return compliancepkg.BenchExecutionRequest{}, err
	}
	if attempt.ClusterID != scope.clusterID.String() || attempt.RunnerID != input.RunnerID || attempt.Node != input.Node || attempt.Status != "running" {
		return compliancepkg.BenchExecutionRequest{}, nil
	}
	req, err := loadBenchRequest(r.Context(), tx, scope.orgID, uuid.MustParse(attempt.RequestID), true)
	if err == nil && (req.Status != "running" || req.ActiveAttempt == nil || req.ActiveAttempt.ID != id || req.ActiveAttempt.Status != "running") {
		return compliancepkg.BenchExecutionRequest{}, nil
	}
	return req, err
}

func (c *Compliance) HeartbeatBenchRequest(w http.ResponseWriter, r *http.Request) {
	scope, ok := c.agentWriteScope(w, r)
	if !ok {
		return
	}
	var input struct {
		AttemptID string `json:"attempt_id"`
	}
	if !strictBenchBody(w, r, &input, 4096) {
		return
	}
	tx, ok := c.beginBenchWrite(w, r, scope)
	if !ok {
		return
	}
	defer rollbackBenchRequest(r.Context(), tx)
	req, valid := loadOwnedBenchAttempt(w, r, tx, scope, input.AttemptID)
	if !valid || !benchRequireRunning(w, req) {
		return
	}
	tag, err := tx.Exec(r.Context(), `UPDATE compliance_bench_attempts SET lease_expires_at=LEAST(clock_timestamp()+INTERVAL '10 minutes',started_at+INTERVAL '15 minutes') WHERE id=$1 AND started_at+INTERVAL '15 minutes'>clock_timestamp() AND lease_expires_at>clock_timestamp()`, input.AttemptID)
	if err != nil {
		benchRequestError(w, err)
		return
	}
	if tag.RowsAffected() != 1 {
		benchReplyError(w, http.StatusConflict, "lease_expired", "execution lease expired")
		return
	}
	req, err = loadBenchRequest(r.Context(), tx, scope.orgID, uuid.MustParse(req.ID), false)
	if err != nil {
		benchRequestError(w, err)
		return
	}
	if benchCommit(w, r, tx) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"request": req})
	}
}

func loadOwnedBenchAttempt(w http.ResponseWriter, r *http.Request, tx pgx.Tx, scope complianceWriteScope, attemptID string) (compliancepkg.BenchExecutionRequest, bool) {
	id, validID := benchUUID(chi.URLParam(r, "id"))
	_, validAttempt := benchUUID(attemptID)
	if !validID || !validAttempt {
		benchReplyError(w, http.StatusBadRequest, "invalid_id", "invalid request or attempt id")
		return compliancepkg.BenchExecutionRequest{}, false
	}
	req, err := loadBenchRequest(r.Context(), tx, scope.orgID, id, true)
	if err != nil {
		benchRequestError(w, err)
		return req, false
	}
	if req.ClusterID == nil || *req.ClusterID != scope.clusterID.String() || req.ActiveAttempt == nil || req.ActiveAttempt.ID != attemptID {
		benchReplyError(w, http.StatusConflict, "stale_attempt", "request no longer belongs to this execution")
		return req, false
	}
	_, token, err := loadBenchAttempt(r.Context(), tx, scope.orgID, attemptID)
	if err != nil {
		benchRequestError(w, err)
		return req, false
	}
	if token != *scope.agentID {
		benchReplyError(w, http.StatusForbidden, "scope_mismatch", "execution credential does not match")
		return req, false
	}
	return req, true
}

func benchRequireRunning(w http.ResponseWriter, req compliancepkg.BenchExecutionRequest) bool {
	if req.Status != "running" || req.ActiveAttempt.Status != "running" {
		benchReplyError(w, http.StatusConflict, "lease_expired", "execution is terminal or its lease expired")
		return false
	}
	return true
}
