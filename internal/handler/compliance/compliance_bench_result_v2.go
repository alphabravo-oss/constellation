package compliance

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

type preparedBenchResult struct {
	input  compliancepkg.BenchExecutionResult
	counts compliancepkg.BenchExecutionCounts
	checks []compliancepkg.Check
}

func (c *Compliance) ResultBenchRequest(w http.ResponseWriter, r *http.Request) {
	scope, ok := c.agentWriteScope(w, r)
	if !ok {
		return
	}
	var input compliancepkg.BenchExecutionResult
	if !strictBenchBody(w, r, &input, compliancepkg.BenchExecutionMaxReport+(64<<10)) {
		return
	}
	tx, ok := c.beginBenchWrite(w, r, scope)
	if !ok {
		return
	}
	defer rollbackBenchRequest(r.Context(), tx)
	req, valid := loadOwnedBenchAttempt(w, r, tx, scope, input.AttemptID)
	if !valid {
		return
	}
	result, valid := prepareBenchResult(w, input, req.Benchmark)
	if !valid {
		return
	}
	if req.Status == "succeeded" || req.Status == "failed" {
		repeatBenchResult(w, req, result)
		return
	}
	if !benchRequireRunning(w, req) {
		return
	}
	failures, err := c.completeBenchResult(r, tx, scope, req, result)
	if err != nil {
		benchRequestError(w, err)
		return
	}
	req, err = loadBenchRequest(r.Context(), tx, scope.orgID, uuid.MustParse(req.ID), false)
	if err != nil {
		benchRequestError(w, err)
		return
	}
	if !benchCommit(w, r, tx) {
		return
	}
	c.alerts.fire(r.Context(), scope.orgID, *scope.clusterID, failures)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"request": req})
}

func prepareBenchResult(w http.ResponseWriter, input compliancepkg.BenchExecutionResult, benchmark string) (preparedBenchResult, bool) {
	out := preparedBenchResult{input: input}
	if input.Outcome != "report_ingested" {
		validFailure := input.Outcome == "exec_failed" || input.Outcome == "timeout" || input.Outcome == "invalid_report" || input.Outcome == "interrupted"
		if !validFailure || len(input.Report) > 0 || input.ReportSHA256 != "" {
			benchReplyError(w, http.StatusBadRequest, "invalid_result", "invalid execution outcome")
			return out, false
		}
		return out, true
	}
	raw, digest, err := compliancepkg.CanonicalBenchReport(input.Report)
	if err != nil || digest != input.ReportSHA256 {
		benchReplyError(w, http.StatusBadRequest, "invalid_report", "invalid benchmark report or digest")
		return out, false
	}
	out.counts, err = compliancepkg.ValidateBenchExecutionReport(raw)
	if err == nil {
		out.checks, err = compliancepkg.IngestKubeBenchProfile(raw, benchmark)
	}
	if err != nil {
		benchReplyError(w, http.StatusBadRequest, "invalid_report", "benchmark report has no valid evaluated controls")
		return out, false
	}
	return out, true
}

func repeatBenchResult(w http.ResponseWriter, req compliancepkg.BenchExecutionRequest, result preparedBenchResult) {
	if req.ActiveAttempt.Outcome != result.input.Outcome || req.ActiveAttempt.ReportSHA256 != result.input.ReportSHA256 {
		benchReplyError(w, http.StatusConflict, "result_conflict", "execution already has a different terminal result")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"request": req})
}

func (c *Compliance) completeBenchResult(r *http.Request, tx pgx.Tx, scope complianceWriteScope, req compliancepkg.BenchExecutionRequest, result preparedBenchResult) ([]complianceFailure, error) {
	status := "failed"
	var failures []complianceFailure
	var err error
	if result.input.Outcome == "report_ingested" {
		status = "succeeded"
		failures, err = persistBenchChecks(r.Context(), tx, scope, req.ActiveAttempt.Node, result.checks)
		if err != nil {
			return nil, err
		}
	}
	_, err = tx.Exec(r.Context(), `UPDATE compliance_bench_attempts SET status=$2,finished_at=NOW(),outcome=$3,report_sha256=$4,rows_ingested=$5,passed=$6,failed=$7,manual=$8,not_applicable=$9 WHERE id=$1`, req.ActiveAttempt.ID, status, result.input.Outcome, result.input.ReportSHA256, len(result.checks), result.counts.Pass, result.counts.Fail, result.counts.Manual, result.counts.NotApplicable)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE compliance_bench_run_requests SET status=$2,revision=revision+1,completed_at=NOW() WHERE id=$1`, req.ID, status)
	}
	if err == nil {
		err = c.benchAudit(r.Context(), tx, scope, "compliance.bench.v2.completed", req.ID, map[string]any{"attempt_id": req.ActiveAttempt.ID, "cluster_id": scope.clusterID, "agent_token_id": scope.agentID, "status": status, "outcome": result.input.Outcome, "controls": result.counts, "rows_ingested": len(result.checks)})
	}
	return failures, err
}
