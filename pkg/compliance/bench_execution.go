package compliance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const BenchExecutionMaxReport = 16 << 20

type BenchExecutionCounts struct {
	Total         int `json:"total"`
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Manual        int `json:"manual"`
	NotApplicable int `json:"not_applicable"`
}

type BenchExecutionAttempt struct {
	ID             string               `json:"id"`
	RequestID      string               `json:"request_id"`
	ClusterID      string               `json:"cluster_id"`
	RunnerID       string               `json:"runner_id"`
	ClaimKey       string               `json:"claim_key"`
	Node           string               `json:"node"`
	Number         int                  `json:"number"`
	Status         string               `json:"status"`
	StartedAt      time.Time            `json:"started_at"`
	LeaseExpiresAt time.Time            `json:"lease_expires_at"`
	FinishedAt     *time.Time           `json:"finished_at"`
	Outcome        string               `json:"outcome"`
	ReportSHA256   string               `json:"report_sha256"`
	RowsIngested   int                  `json:"rows_ingested"`
	Controls       BenchExecutionCounts `json:"controls"`
}

type BenchExecutionRequest struct {
	ID                 string                 `json:"id"`
	RequestKey         string                 `json:"request_key"`
	RequestedClusterID *string                `json:"requested_cluster_id"`
	ClusterID          *string                `json:"cluster_id"`
	Profile            string                 `json:"profile"`
	Benchmark          string                 `json:"benchmark"`
	Status             string                 `json:"status"`
	Revision           string                 `json:"revision"`
	AttemptCount       int                    `json:"attempt_count"`
	RequestedAt        time.Time              `json:"requested_at"`
	CompletedAt        *time.Time             `json:"completed_at"`
	ActiveAttempt      *BenchExecutionAttempt `json:"active_attempt"`
}

type BenchExecutionClaim struct {
	ClaimKey string `json:"claim_key"`
	RunnerID string `json:"runner_id"`
	Node     string `json:"node"`
}

type BenchExecutionResult struct {
	AttemptID    string          `json:"attempt_id"`
	Outcome      string          `json:"outcome"`
	ReportSHA256 string          `json:"report_sha256,omitempty"`
	Report       json.RawMessage `json:"report,omitempty"`
}

// Canonical bytes make the digest stable when a report is embedded in JSON.
func CanonicalBenchReport(raw []byte) ([]byte, string, error) {
	if len(raw) == 0 || len(raw) > BenchExecutionMaxReport {
		return nil, "", errors.New("invalid benchmark report size")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, "", errors.New("invalid benchmark report")
	}
	digest := sha256.Sum256(compact.Bytes())
	return compact.Bytes(), hex.EncodeToString(digest[:]), nil
}

// Validate execution coverage before success. A valid report can contain FAIL
// controls: execution success is distinct from a clean security assessment.
func ValidateBenchExecutionReport(raw []byte) (BenchExecutionCounts, error) {
	var doc kbReport
	if err := json.Unmarshal(raw, &doc); err != nil {
		return BenchExecutionCounts{}, errors.New("invalid benchmark report")
	}
	var results []kbResult
	for _, control := range doc.Controls {
		for _, section := range control.Tests {
			results = append(results, section.Results...)
			for _, nested := range section.Tests {
				results = append(results, nested.Results...)
			}
		}
	}
	counts := BenchExecutionCounts{Total: len(results)}
	if len(results) == 0 {
		return counts, errors.New("benchmark report has no evaluated controls")
	}
	for _, result := range results {
		if strings.TrimSpace(result.TestNumber) == "" || strings.TrimSpace(result.TestDesc) == "" {
			return counts, errors.New("benchmark report has incomplete control identity")
		}
		switch strings.ToLower(result.Status) {
		case "pass":
			counts.Pass++
		case "fail":
			counts.Fail++
		case "warn":
			counts.Manual++
		case "info":
			counts.NotApplicable++
		default:
			return counts, errors.New("benchmark report has unknown control status")
		}
	}
	return counts, nil
}
