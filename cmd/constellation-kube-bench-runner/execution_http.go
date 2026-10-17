package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

type executionAPIError struct {
	status int
	code   string
}

func (e *executionAPIError) Error() string { return "benchmark execution service rejected request" }

func executionPost(ctx context.Context, client *http.Client, cfg config, path string, body any) (*compliancepkg.BenchExecutionRequest, error) {
	raw, err := encodeExecutionJSON(body)
	if err != nil {
		return nil, errors.New("invalid benchmark execution payload")
	}
	postCtx, cancel := context.WithTimeout(ctx, postTimeout)
	defer cancel()
	endpoint, err := url.Parse(strings.TrimRight(cfg.apiURL, "/") + "/api/v1/agent/compliance/bench/" + path)
	if err != nil {
		return nil, errors.New("invalid benchmark execution endpoint")
	}
	if cfg.clusterID != "" {
		query := endpoint.Query()
		query.Set("cluster_id", cfg.clusterID)
		endpoint.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(postCtx, http.MethodPost, endpoint.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("invalid benchmark execution endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := benchmarkClient(client).Do(req)
	if err != nil {
		return nil, errors.New("benchmark execution service unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		var errorBody struct {
			Code string `json:"code"`
		}
		_ = decodeBenchmarkReceipt(resp.Body, &errorBody)
		return nil, &executionAPIError{status: resp.StatusCode, code: errorBody.Code}
	}
	var result struct {
		Request *compliancepkg.BenchExecutionRequest `json:"request"`
	}
	if err := decodeBenchmarkReceipt(resp.Body, &result); err != nil || result.Request == nil {
		return nil, errors.New("benchmark execution has no confirmed receipt")
	}
	return result.Request, nil
}

// Reports carry a digest of compact source bytes. Default JSON HTML escaping
// would rewrite '<', '>', and '&' inside RawMessage and break that identity.
func encodeExecutionJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func validExecutionUUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func executionRevision(raw string) (int64, bool) {
	n, err := strconv.ParseInt(raw, 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == raw
}

func validExecutionClaim(cfg config, claim compliancepkg.BenchExecutionClaim, req *compliancepkg.BenchExecutionRequest, requireLease bool) bool {
	if req == nil || req.ActiveAttempt == nil || req.ClusterID == nil {
		return false
	}
	a := req.ActiveAttempt
	_, revisionOK := executionRevision(req.Revision)
	base := validExecutionUUID(req.ID) && validExecutionUUID(req.RequestKey) && validExecutionUUID(a.ID) && validExecutionUUID(*req.ClusterID)
	scope := cfg.clusterID == "" || cfg.clusterID == *req.ClusterID
	identity := a.RequestID == req.ID && a.ClusterID == *req.ClusterID && a.ClaimKey == claim.ClaimKey && a.RunnerID == claim.RunnerID && a.Node == claim.Node
	shape := req.Profile == "kube-bench" && compliancepkg.ValidBenchmarkID(req.Benchmark) && req.Status == "running" && a.Status == "running" && req.AttemptCount == a.Number && a.Number >= 1 && a.Number <= 3 && !a.StartedAt.IsZero() && a.LeaseExpiresAt.After(a.StartedAt)
	return base && scope && identity && shape && revisionOK && (!requireLease || a.LeaseExpiresAt.After(time.Now()))
}

func executionResultConfirmed(entry *executionSpoolEntry, receipt *compliancepkg.BenchExecutionRequest) bool {
	if receipt == nil || receipt.ActiveAttempt == nil || receipt.ClusterID == nil {
		return false
	}
	before, after := entry.Request, receipt
	a, b := before.ActiveAttempt, after.ActiveAttempt
	oldRevision, oldOK := executionRevision(before.Revision)
	newRevision, newOK := executionRevision(after.Revision)
	identity := after.ID == before.ID && after.RequestKey == before.RequestKey && *after.ClusterID == *before.ClusterID && after.Profile == before.Profile && after.Benchmark == before.Benchmark && sameOptionalCluster(after.RequestedClusterID, before.RequestedClusterID)
	attempt := b.ID == a.ID && b.RequestID == a.RequestID && b.ClusterID == a.ClusterID && b.RunnerID == a.RunnerID && b.ClaimKey == a.ClaimKey && b.Node == a.Node && b.Number == a.Number && b.StartedAt.Equal(a.StartedAt) && after.AttemptCount == before.AttemptCount
	terminal := confirmedExecutionOutcome(entry.Result, after)
	return identity && attempt && terminal && oldOK && newOK && newRevision > oldRevision
}

func confirmedExecutionOutcome(result compliancepkg.BenchExecutionResult, request *compliancepkg.BenchExecutionRequest) bool {
	b := request.ActiveAttempt
	status := "failed"
	if result.Outcome == "report_ingested" {
		status = "succeeded"
	}
	terminal := request.Status == status && b.Status == status && b.Outcome == result.Outcome && b.ReportSHA256 == result.ReportSHA256 && request.CompletedAt != nil && b.FinishedAt != nil
	if status == "succeeded" {
		counts, err := compliancepkg.ValidateBenchExecutionReport(result.Report)
		terminal = terminal && err == nil && b.RowsIngested >= counts.Total && b.Controls == counts
	} else {
		terminal = terminal && b.RowsIngested == 0 && b.Controls.Total == 0
	}
	return terminal
}

func sameOptionalCluster(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
