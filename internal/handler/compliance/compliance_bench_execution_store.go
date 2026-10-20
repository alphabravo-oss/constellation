package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/pkg/audit"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

const benchRequestSelect = `SELECT r.id::text,r.request_key::text,r.requested_cluster_id::text,r.cluster_id::text,r.profile,r.benchmark,
r.status,
r.revision::text,r.attempt_count,r.requested_at,r.completed_at,r.active_attempt_id::text
FROM compliance_bench_run_requests r
WHERE r.protocol_version=2 AND r.org_id=$1 AND r.id=$2`

type benchQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func rollbackBenchRequest(ctx context.Context, tx pgx.Tx) { _ = tx.Rollback(ctx) }

func loadBenchRequest(ctx context.Context, q benchQuerier, org, id uuid.UUID, lock bool) (compliancepkg.BenchExecutionRequest, error) {
	query := benchRequestSelect
	if lock {
		query += " FOR UPDATE OF r"
	}
	var out compliancepkg.BenchExecutionRequest
	var attempt *string
	err := q.QueryRow(ctx, query, org, id).Scan(&out.ID, &out.RequestKey, &out.RequestedClusterID, &out.ClusterID, &out.Profile, &out.Benchmark, &out.Status, &out.Revision, &out.AttemptCount, &out.RequestedAt, &out.CompletedAt, &attempt)
	if err != nil || attempt == nil {
		return out, err
	}
	a, _, err := loadBenchAttempt(ctx, q, org, *attempt)
	out.ActiveAttempt = &a
	if out.Status == "running" && a.Status == "interrupted" {
		out.Status = "interrupted"
	}
	return out, err
}

func loadBenchAttempt(ctx context.Context, q benchQuerier, org uuid.UUID, id string) (compliancepkg.BenchExecutionAttempt, uuid.UUID, error) {
	var a compliancepkg.BenchExecutionAttempt
	var token uuid.UUID
	err := q.QueryRow(ctx, `SELECT id::text,request_id::text,cluster_id::text,runner_id::text,claim_key::text,node,attempt_no,
CASE WHEN status='running' AND lease_expires_at<=clock_timestamp() THEN 'interrupted' ELSE status END,
started_at,lease_expires_at,finished_at,outcome,report_sha256,rows_ingested,passed,failed,manual,not_applicable,agent_token_id
FROM compliance_bench_attempts WHERE org_id=$1 AND id=$2`, org, id).Scan(&a.ID, &a.RequestID, &a.ClusterID, &a.RunnerID, &a.ClaimKey, &a.Node, &a.Number, &a.Status, &a.StartedAt, &a.LeaseExpiresAt, &a.FinishedAt, &a.Outcome, &a.ReportSHA256, &a.RowsIngested, &a.Controls.Pass, &a.Controls.Fail, &a.Controls.Manual, &a.Controls.NotApplicable, &token)
	a.Controls.Total = a.Controls.Pass + a.Controls.Fail + a.Controls.Manual + a.Controls.NotApplicable
	return a, token, err
}

func strictBenchBody(w http.ResponseWriter, r *http.Request, target any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	err := d.Decode(target)
	var extra any
	if err != nil || !errors.Is(d.Decode(&extra), io.EOF) {
		benchReplyError(w, http.StatusBadRequest, "invalid_body", "invalid benchmark request")
		return false
	}
	return true
}

func benchReplyError(w http.ResponseWriter, status int, code, message string) {
	apiutil.WriteStatusCode(context.Background(), w, status, code, message)
}

func benchUUID(raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	return id, err == nil && id != uuid.Nil && id.String() == raw
}

func benchRevision(raw string) bool {
	n, err := strconv.ParseInt(raw, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == raw
}

func (c *Compliance) beginBenchWrite(w http.ResponseWriter, r *http.Request, scope complianceWriteScope) (pgx.Tx, bool) {
	tx, err := c.db.Pool().Begin(r.Context())
	if err != nil {
		benchReplyError(w, http.StatusInternalServerError, "unavailable", "benchmark service unavailable")
		return nil, false
	}
	if !scope.lockCluster(w, r, tx) {
		_ = tx.Rollback(r.Context())
		return nil, false
	}
	return tx, true
}

func (c *Compliance) benchAudit(ctx context.Context, tx pgx.Tx, scope complianceWriteScope, action, id string, detail any) error {
	logger := c.audit
	if logger == nil {
		logger = audit.New(c.db.Pool())
	}
	_, _, err := logger.LogInTx(ctx, tx, audit.Event{OrgID: &scope.orgID, ActorID: scope.actorID, Action: action, TargetKind: "compliance_bench_request", TargetID: id, After: detail})
	return err
}

func benchVisibleToScope(request compliancepkg.BenchExecutionRequest, scope complianceWriteScope) bool {
	return scope.clusterID == nil || request.ClusterID == nil || *request.ClusterID == scope.clusterID.String()
}

func benchRequestError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		benchReplyError(w, http.StatusNotFound, "not_found", "benchmark request not found")
		return
	}
	benchReplyError(w, http.StatusInternalServerError, "unavailable", "benchmark service unavailable")
}

func benchCommit(w http.ResponseWriter, r *http.Request, tx pgx.Tx) bool {
	if err := tx.Commit(r.Context()); err != nil {
		benchRequestError(w, err)
		return false
	}
	return true
}
