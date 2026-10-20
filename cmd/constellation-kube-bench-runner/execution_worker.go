package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

type executionWorker struct {
	cfg     config
	client  *http.Client
	spool   *executionSpool
	execute func(context.Context, config) ([]byte, string)
}

func runExecutionWorker(ctx context.Context, client *http.Client, cfg config, logger *slog.Logger) error {
	spool, err := openExecutionSpool(cfg.spoolDir)
	if err != nil {
		return err
	}
	defer spool.close()
	worker := executionWorker{cfg: cfg, client: client, spool: spool, execute: executeDurableBenchmark}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := worker.step(ctx); err != nil {
			logger.Warn("benchmark execution pending or unavailable", "err", err.Error())
		}
		timer := time.NewTimer(cfg.watchInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (worker *executionWorker) step(ctx context.Context) error {
	entry, err := worker.spool.load(executionScope(worker.cfg))
	if err != nil {
		return err
	}
	if entry == nil {
		entry = &executionSpoolEntry{Version: 1, Scope: executionScope(worker.cfg), Phase: "claiming", Claim: compliancepkg.BenchExecutionClaim{ClaimKey: uuid.NewString(), RunnerID: worker.cfg.runnerID, Node: worker.cfg.node}}
		if err := worker.spool.save(entry); err != nil {
			return err
		}
	}
	if !validExecutionUUID(entry.Claim.ClaimKey) || !validExecutionUUID(entry.Claim.RunnerID) || entry.Claim.Node == "" {
		return errors.New("invalid benchmark spool claim identity")
	}
	switch entry.Phase {
	case "claiming":
		if err := worker.claimAndExecute(ctx, entry); err != nil || entry.Phase == "claiming" {
			return err
		}
	default:
		if !validExecutionClaim(worker.cfg, entry.Claim, &entry.Request, false) {
			return errors.New("invalid benchmark spool execution identity")
		}
	}
	if entry.Phase == "executing" {
		// The process may have started before the previous worker disappeared.
		// Never execute that attempt again, even when no output was persisted.
		entry.Phase = "result"
		entry.Result = compliancepkg.BenchExecutionResult{AttemptID: entry.Request.ActiveAttempt.ID, Outcome: "interrupted"}
		if err := worker.spool.save(entry); err != nil {
			return err
		}
	}
	return worker.submit(ctx, entry)
}

func (worker *executionWorker) claimAndExecute(ctx context.Context, entry *executionSpoolEntry) error {
	req, err := executionPost(ctx, worker.client, worker.cfg, "requests/claim", entry.Claim)
	if err != nil {
		return worker.handleRejected(entry, err)
	}
	if req == nil {
		return worker.spool.forget()
	}
	if !validExecutionClaim(worker.cfg, entry.Claim, req, true) {
		return errors.New("unconfirmed benchmark claim; no execution started")
	}
	entry.Request, entry.Phase = *req, "executing"
	if err := worker.spool.save(entry); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	entry.Result = compliancepkg.BenchExecutionResult{AttemptID: req.ActiveAttempt.ID, Outcome: "interrupted"}
	if entry.Claim.RunnerID == worker.cfg.runnerID && entry.Claim.Node == worker.cfg.node {
		worker.executeClaim(ctx, entry)
	}
	entry.Phase = "result"
	return worker.spool.save(entry)
}

func (worker *executionWorker) executeClaim(ctx context.Context, entry *executionSpoolEntry) {
	req := entry.Request
	cfg, err := claimedBenchmarkConfig(worker.cfg, claimedBenchRun{ID: req.ID, ClusterID: *req.ClusterID, Profile: req.Profile, Benchmark: req.Benchmark, Status: "claimed"})
	if err != nil {
		entry.Result.Outcome = "invalid_report"
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.heartbeatExecution(runCtx, cancel, entry)
	}()
	raw, outcome := worker.execute(runCtx, cfg)
	cancel()
	<-done
	entry.Result.Outcome = outcome
	if outcome != "report_ingested" {
		return
	}
	canonical, digest, err := compliancepkg.CanonicalBenchReport(raw)
	if err != nil {
		entry.Result.Outcome = "invalid_report"
		return
	}
	if _, err := compliancepkg.ValidateBenchExecutionReport(canonical); err != nil {
		entry.Result.Outcome = "invalid_report"
		return
	}
	entry.Result.Report, entry.Result.ReportSHA256 = canonical, digest
}

func (worker *executionWorker) heartbeatExecution(ctx context.Context, cancel context.CancelFunc, entry *executionSpoolEntry) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, err := executionPost(ctx, worker.client, worker.cfg, "requests/"+entry.Request.ID+"/heartbeat", map[string]string{"attempt_id": entry.Request.ActiveAttempt.ID})
			var apiErr *executionAPIError
			if err == nil && !validExecutionClaim(worker.cfg, entry.Claim, req, true) || errors.As(err, &apiErr) && apiErr.status < 500 {
				cancel()
				return
			}
		}
	}
}

func (worker *executionWorker) submit(ctx context.Context, entry *executionSpoolEntry) error {
	if entry.Result.AttemptID != entry.Request.ActiveAttempt.ID {
		return errors.New("invalid benchmark spool result identity")
	}
	receipt, err := executionPost(ctx, worker.client, worker.cfg, "requests/"+entry.Request.ID+"/result", entry.Result)
	if err != nil {
		return worker.handleRejected(entry, err)
	}
	if !executionResultConfirmed(entry, receipt) {
		return errors.New("benchmark result remains unconfirmed; durable result retained")
	}
	return worker.spool.forget()
}

func (worker *executionWorker) handleRejected(_ *executionSpoolEntry, err error) error {
	var apiErr *executionAPIError
	if errors.As(err, &apiErr) && apiErr.status == http.StatusConflict && (apiErr.code == "stale_claim" || apiErr.code == "stale_attempt" || apiErr.code == "lease_expired") {
		if spoolErr := worker.spool.reject(); spoolErr != nil {
			return spoolErr
		}
		return errors.New("execution lease or attempt replaced; last rejected record retained for review")
	}
	return err
}

type boundedBenchOutput struct{ bytes.Buffer }

func (out *boundedBenchOutput) Write(raw []byte) (int, error) {
	if len(raw) > compliancepkg.BenchExecutionMaxReport-out.Len() {
		return 0, errors.New("benchmark output exceeds report limit")
	}
	return out.Buffer.Write(raw)
}

func executeDurableBenchmark(ctx context.Context, cfg config) ([]byte, string) {
	raw, err := runBenchmark(ctx, cfg.binary, cfg.args)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, "timeout"
	}
	if ctx.Err() != nil {
		return nil, "interrupted"
	}
	if err != nil {
		return nil, "exec_failed"
	}
	return raw, "report_ingested"
}
