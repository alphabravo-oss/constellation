package scanning

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

type ServerlessInventoryHandler struct {
	db *db.DB
}

func NewServerlessInventory(d *db.DB) *ServerlessInventoryHandler {
	return &ServerlessInventoryHandler{db: d}
}

type serverlessFunctionDTO struct {
	ID                 uuid.UUID       `json:"id"`
	FunctionRef        string          `json:"function_ref"`
	FunctionName       string          `json:"function_name,omitempty"`
	Provider           string          `json:"provider,omitempty"`
	AccountID          string          `json:"account_id,omitempty"`
	Region             string          `json:"region,omitempty"`
	Runtime            string          `json:"runtime,omitempty"`
	Version            string          `json:"version,omitempty"`
	Architecture       string          `json:"architecture,omitempty"`
	Role               string          `json:"role,omitempty"`
	Handler            string          `json:"handler,omitempty"`
	PackageType        string          `json:"package_type,omitempty"`
	Layers             []string        `json:"layers,omitempty"`
	SourceType         string          `json:"source_type"`
	SourceRef          string          `json:"source_ref,omitempty"`
	InventoryHash      string          `json:"inventory_hash,omitempty"`
	PackageCount       int             `json:"package_count"`
	PermissionStatus   string          `json:"permission_status,omitempty"`
	PermissionLevel    string          `json:"permission_level,omitempty"`
	PermissionAnalysis json.RawMessage `json:"permission_analysis,omitempty"`
	LatestEvidenceID   *uuid.UUID      `json:"latest_evidence_id,omitempty"`
	LatestObservedAt   *time.Time      `json:"latest_observed_at,omitempty"`
	LatestJobID        *uuid.UUID      `json:"latest_job_id,omitempty"`
	LatestJobStatus    string          `json:"latest_job_status,omitempty"`
	OpenFindings       int             `json:"open_findings"`
	CriticalFindings   int             `json:"critical_findings"`
	HighFindings       int             `json:"high_findings"`
	LastSeenAt         time.Time       `json:"last_seen_at"`
	Metadata           json.RawMessage `json:"metadata,omitempty"`
}

type serverlessFunctionMetadata struct {
	FunctionName       string          `json:"function_name"`
	Provider           string          `json:"provider"`
	AccountID          string          `json:"account_id"`
	Region             string          `json:"region"`
	Runtime            string          `json:"runtime"`
	Version            string          `json:"version"`
	Architecture       string          `json:"architecture"`
	PackageCount       int             `json:"package_count"`
	Role               string          `json:"role"`
	Handler            string          `json:"handler"`
	PackageType        string          `json:"package_type"`
	Layers             []string        `json:"layers"`
	PermissionAnalysis json.RawMessage `json:"permission_analysis"`
}

type serverlessEvidenceDTO struct {
	ID            uuid.UUID         `json:"id"`
	InventoryHash string            `json:"inventory_hash"`
	PackageCount  int               `json:"package_count"`
	ObservedAt    time.Time         `json:"observed_at"`
	Runtime       string            `json:"runtime,omitempty"`
	Provider      string            `json:"provider,omitempty"`
	AccountID     string            `json:"account_id,omitempty"`
	Region        string            `json:"region,omitempty"`
	Version       string            `json:"version,omitempty"`
	Architecture  string            `json:"architecture,omitempty"`
	Packages      []scanner.Package `json:"packages,omitempty"`
}

type serverlessJobDTO struct {
	ID           uuid.UUID  `json:"id"`
	Status       string     `json:"status"`
	Error        string     `json:"error,omitempty"`
	PackageCount int        `json:"package_count"`
	FindingCount int        `json:"finding_count"`
	RequestedAt  time.Time  `json:"requested_at"`
	ClaimedAt    *time.Time `json:"claimed_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
}

type serverlessFindingDTO struct {
	ID         uuid.UUID       `json:"id"`
	Kind       string          `json:"kind"`
	ExternalID string          `json:"external_id,omitempty"`
	Title      string          `json:"title"`
	Severity   string          `json:"severity"`
	RiskScore  int             `json:"risk_score"`
	Lifecycle  string          `json:"lifecycle"`
	Detail     json.RawMessage `json:"detail,omitempty"`
	FirstSeen  time.Time       `json:"first_seen_at"`
	LastSeen   time.Time       `json:"last_seen_at"`
}

func (h *ServerlessInventoryHandler) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	provider := strings.TrimSpace(r.URL.Query().Get("provider"))
	accountID := strings.TrimSpace(r.URL.Query().Get("account_id"))
	region := strings.TrimSpace(r.URL.Query().Get("region"))

	rows, err := h.db.Pool().Query(r.Context(), `
WITH finding_rollup AS (
    SELECT scan_target_id,
           COUNT(*) FILTER (WHERE lifecycle = 'open')::int AS open_findings,
           COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'critical')::int AS critical_findings,
           COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'high')::int AS high_findings
      FROM findings
     WHERE org_id = $1
       AND target_type = 'serverless'
     GROUP BY scan_target_id
)
SELECT st.id, st.ref, st.source_type, COALESCE(st.source_ref, ''),
       COALESCE(st.inventory_hash, ''), st.metadata, st.last_seen_at,
       ev.id, COALESCE(ev.package_count, 0), ev.observed_at,
       sj.id, COALESCE(sj.status, ''),
       COALESCE(fr.open_findings, 0), COALESCE(fr.critical_findings, 0), COALESCE(fr.high_findings, 0)
  FROM scan_targets st
  LEFT JOIN LATERAL (
      SELECT id, package_count, observed_at
        FROM scan_evidence
       WHERE org_id = st.org_id
         AND scan_target_id = st.id
         AND evidence_type = 'package-inventory'
       ORDER BY observed_at DESC
       LIMIT 1
  ) ev ON true
  LEFT JOIN LATERAL (
      SELECT id, status
        FROM scan_jobs
       WHERE org_id = st.org_id
         AND target_id = st.id
       ORDER BY requested_at DESC
       LIMIT 1
  ) sj ON true
  LEFT JOIN finding_rollup fr ON fr.scan_target_id = st.id
 WHERE st.org_id = $1
   AND st.type = 'serverless'
   AND ($2 = '' OR st.ref ILIKE '%' || $2 || '%' OR st.metadata->>'function_name' ILIKE '%' || $2 || '%')
   AND ($3 = '' OR st.metadata->>'provider' = $3)
   AND ($4 = '' OR st.metadata->>'account_id' = $4)
   AND ($5 = '' OR st.metadata->>'region' = $5)
 ORDER BY st.last_seen_at DESC
 LIMIT $6 OFFSET $7`, subj.OrgID, q, provider, accountID, region, limit, offset)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	out := make([]serverlessFunctionDTO, 0)
	for rows.Next() {
		fn, err := scanServerlessFunctionRow(rows)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		out = append(out, fn)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"serverless_functions": out,
		"limit":                limit,
		"offset":               offset,
	})
}

func (h *ServerlessInventoryHandler) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid serverless function id")
		return
	}
	fn, err := h.getFunction(r, subj.OrgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "serverless function not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	evidence, err := h.latestEvidence(r, subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "evidence: "+err.Error())
		return
	}
	jobs, err := h.recentJobs(r, subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "jobs: "+err.Error())
		return
	}
	findings, err := h.findings(r, subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "findings: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"serverless_function": fn,
		"latest_evidence":     evidence,
		"jobs":                jobs,
		"findings":            findings,
	})
}

type serverlessFunctionScanner interface {
	Scan(dest ...any) error
}

func scanServerlessFunctionRow(row serverlessFunctionScanner) (serverlessFunctionDTO, error) {
	var fn serverlessFunctionDTO
	var metadataRaw []byte
	var evidenceID *uuid.UUID
	var evidencePackageCount *int
	var evidenceObservedAt *time.Time
	var jobID *uuid.UUID
	if err := row.Scan(&fn.ID, &fn.FunctionRef, &fn.SourceType, &fn.SourceRef,
		&fn.InventoryHash, &metadataRaw, &fn.LastSeenAt,
		&evidenceID, &evidencePackageCount, &evidenceObservedAt,
		&jobID, &fn.LatestJobStatus,
		&fn.OpenFindings, &fn.CriticalFindings, &fn.HighFindings); err != nil {
		return fn, err
	}
	fn.Metadata = handler.NormalizedJSONRaw(metadataRaw)
	applyServerlessMetadata(&fn, fn.Metadata)
	fn.LatestEvidenceID = evidenceID
	fn.LatestObservedAt = evidenceObservedAt
	fn.LatestJobID = jobID
	if evidencePackageCount != nil {
		fn.PackageCount = *evidencePackageCount
	}
	return fn, nil
}

func applyServerlessMetadata(fn *serverlessFunctionDTO, metadataRaw json.RawMessage) {
	if fn == nil || len(metadataRaw) == 0 {
		return
	}
	var metadata serverlessFunctionMetadata
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		return
	}
	fn.FunctionName = metadata.FunctionName
	fn.Provider = metadata.Provider
	fn.AccountID = metadata.AccountID
	fn.Region = metadata.Region
	fn.Runtime = metadata.Runtime
	fn.Version = metadata.Version
	fn.Architecture = metadata.Architecture
	fn.Role = metadata.Role
	fn.Handler = metadata.Handler
	fn.PackageType = metadata.PackageType
	fn.Layers = metadata.Layers
	if fn.PackageCount == 0 {
		fn.PackageCount = metadata.PackageCount
	}
	if len(metadata.PermissionAnalysis) > 0 && string(metadata.PermissionAnalysis) != "null" {
		fn.PermissionAnalysis = metadata.PermissionAnalysis
		var pa struct {
			Status string `json:"status"`
			Level  string `json:"level"`
		}
		if err := json.Unmarshal(metadata.PermissionAnalysis, &pa); err == nil {
			fn.PermissionStatus = strings.TrimSpace(pa.Status)
			fn.PermissionLevel = strings.TrimSpace(pa.Level)
		}
	}
}

func (h *ServerlessInventoryHandler) getFunction(r *http.Request, orgID uuid.UUID, id uuid.UUID) (serverlessFunctionDTO, error) {
	row := h.db.Pool().QueryRow(r.Context(), `
WITH finding_rollup AS (
    SELECT scan_target_id,
           COUNT(*) FILTER (WHERE lifecycle = 'open')::int AS open_findings,
           COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'critical')::int AS critical_findings,
           COUNT(*) FILTER (WHERE lifecycle = 'open' AND severity = 'high')::int AS high_findings
      FROM findings
     WHERE org_id = $1
       AND scan_target_id = $2
     GROUP BY scan_target_id
)
SELECT st.id, st.ref, st.source_type, COALESCE(st.source_ref, ''),
       COALESCE(st.inventory_hash, ''), st.metadata, st.last_seen_at,
       ev.id, COALESCE(ev.package_count, 0), ev.observed_at,
       sj.id, COALESCE(sj.status, ''),
       COALESCE(fr.open_findings, 0), COALESCE(fr.critical_findings, 0), COALESCE(fr.high_findings, 0)
  FROM scan_targets st
  LEFT JOIN LATERAL (
      SELECT id, package_count, observed_at
        FROM scan_evidence
       WHERE org_id = st.org_id
         AND scan_target_id = st.id
         AND evidence_type = 'package-inventory'
       ORDER BY observed_at DESC
       LIMIT 1
  ) ev ON true
  LEFT JOIN LATERAL (
      SELECT id, status
        FROM scan_jobs
       WHERE org_id = st.org_id
         AND target_id = st.id
       ORDER BY requested_at DESC
       LIMIT 1
  ) sj ON true
  LEFT JOIN finding_rollup fr ON fr.scan_target_id = st.id
 WHERE st.org_id = $1
   AND st.id = $2
   AND st.type = 'serverless'`, orgID, id)
	return scanServerlessFunctionRow(row)
}

func (h *ServerlessInventoryHandler) latestEvidence(r *http.Request, orgID uuid.UUID, targetID uuid.UUID) (*serverlessEvidenceDTO, error) {
	var id uuid.UUID
	var inventoryHash string
	var packageCount int
	var payloadRaw []byte
	var observedAt time.Time
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id, inventory_hash, package_count, payload, observed_at
  FROM scan_evidence
 WHERE org_id = $1
   AND scan_target_id = $2
   AND evidence_type = 'package-inventory'
 ORDER BY observed_at DESC
 LIMIT 1`, orgID, targetID).Scan(&id, &inventoryHash, &packageCount, &payloadRaw, &observedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var payload handler.ScanEvidencePackagePayload
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return nil, err
	}
	return &serverlessEvidenceDTO{
		ID:            id,
		InventoryHash: inventoryHash,
		PackageCount:  packageCount,
		ObservedAt:    observedAt,
		Runtime:       payload.Runtime,
		Provider:      payload.Provider,
		AccountID:     payload.AccountID,
		Region:        payload.Region,
		Version:       payload.Version,
		Architecture:  payload.Architecture,
		Packages:      payload.Packages,
	}, nil
}

func (h *ServerlessInventoryHandler) recentJobs(r *http.Request, orgID uuid.UUID, targetID uuid.UUID) ([]serverlessJobDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, status, COALESCE(error, ''), COALESCE(package_count, 0), COALESCE(finding_count, 0),
       requested_at, claimed_at, finished_at
  FROM scan_jobs
 WHERE org_id = $1
   AND target_id = $2
 ORDER BY requested_at DESC
 LIMIT 25`, orgID, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []serverlessJobDTO{}
	for rows.Next() {
		var item serverlessJobDTO
		if err := rows.Scan(&item.ID, &item.Status, &item.Error, &item.PackageCount, &item.FindingCount,
			&item.RequestedAt, &item.ClaimedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *ServerlessInventoryHandler) findings(r *http.Request, orgID uuid.UUID, targetID uuid.UUID) ([]serverlessFindingDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, kind, COALESCE(external_id, ''), title, severity, risk_score,
       lifecycle, detail_json, first_seen_at, last_seen_at
  FROM findings
 WHERE org_id = $1
   AND scan_target_id = $2
 ORDER BY lifecycle = 'open' DESC, risk_score DESC, last_seen_at DESC
 LIMIT 100`, orgID, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []serverlessFindingDTO{}
	for rows.Next() {
		var item serverlessFindingDTO
		var detail []byte
		if err := rows.Scan(&item.ID, &item.Kind, &item.ExternalID, &item.Title, &item.Severity,
			&item.RiskScore, &item.Lifecycle, &detail, &item.FirstSeen, &item.LastSeen); err != nil {
			return nil, err
		}
		item.Detail = handler.NormalizedJSONRaw(detail)
		out = append(out, item)
	}
	return out, rows.Err()
}
