package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

type ConnectorCoverage struct {
	db *db.DB
}

func NewConnectorCoverage(database ...*db.DB) *ConnectorCoverage {
	var d *db.DB
	if len(database) > 0 {
		d = database[0]
	}
	return &ConnectorCoverage{db: d}
}

type connectorCoverageSummaryDTO struct {
	GeneratedAt             string `json:"generated_at"`
	RegistryConnectorsTotal int    `json:"registry_connectors_total"`
	RegistryConnectorsReady int    `json:"registry_connectors_ready"`
	CloudConnectorsTotal    int    `json:"cloud_connectors_total"`
	CloudConnectorsReady    int    `json:"cloud_connectors_ready"`
	ImagesObserved          int    `json:"images_observed"`
	ImagesScanned           int    `json:"images_scanned"`
	ImagesUnscanned         int    `json:"images_unscanned"`
	CloudResourcesObserved  int    `json:"cloud_resources_observed"`
	CloudResourcesAssessed  int    `json:"cloud_resources_assessed"`
	QueuedScans             int    `json:"queued_scans"`
	CredentialRotationsDue  int    `json:"credential_rotations_due"`
}

type registryConnectorDTO struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Provider        string   `json:"provider"`
	Status          string   `json:"status"`
	Endpoint        string   `json:"endpoint"`
	AuthMode        string   `json:"auth_mode"`
	Repositories    int      `json:"repositories"`
	ImagesObserved  int      `json:"images_observed"`
	ImagesScanned   int      `json:"images_scanned"`
	LastScanAt      string   `json:"last_scan_at"`
	NextScanAt      string   `json:"next_scan_at"`
	CredentialAge   string   `json:"credential_age"`
	RotationDueAt   string   `json:"rotation_due_at"`
	SupportedChecks []string `json:"supported_checks"`
	Notes           string   `json:"notes"`
}

type cloudConnectorDTO struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Provider          string   `json:"provider"`
	Status            string   `json:"status"`
	Account           string   `json:"account"`
	Regions           []string `json:"regions"`
	AuthMode          string   `json:"auth_mode"`
	ResourcesObserved int      `json:"resources_observed"`
	ResourcesAssessed int      `json:"resources_assessed"`
	FindingsOpen      int      `json:"findings_open"`
	LastAssessmentAt  string   `json:"last_assessment_at"`
	NextAssessmentAt  string   `json:"next_assessment_at"`
	CredentialAge     string   `json:"credential_age"`
	RotationDueAt     string   `json:"rotation_due_at"`
	Controls          []string `json:"controls"`
	Notes             string   `json:"notes"`
}

type scanCoverageDTO struct {
	Scope          string `json:"scope"`
	Observed       int    `json:"observed"`
	Scanned        int    `json:"scanned"`
	Unscanned      int    `json:"unscanned"`
	CriticalGaps   int    `json:"critical_gaps"`
	LastCoveredAt  string `json:"last_covered_at"`
	RecommendedFix string `json:"recommended_fix"`
}

type scannerPoolDTO struct {
	ID                string                       `json:"id"`
	Name              string                       `json:"name"`
	Status            string                       `json:"status"`
	DesiredWorkers    int                          `json:"desired_workers"`
	ReadyWorkers      int                          `json:"ready_workers"`
	ActiveJobs        int                          `json:"active_jobs"`
	IdleCapacity      int                          `json:"idle_capacity"`
	QueueDepth        int                          `json:"queue_depth"`
	StaleLeases       int                          `json:"stale_leases"`
	P95Duration       string                       `json:"p95_duration"`
	Capacity          string                       `json:"capacity"`
	QueueByTargetType []handler.ScanQueueMetricDTO `json:"queue_by_target_type"`
	Scanners          []scannerWorkerDTO           `json:"scanners"`
}

type scannerWorkerDTO struct {
	InstanceID             string         `json:"instance_id,omitempty"`
	Hostname               string         `json:"hostname"`
	ClusterID              string         `json:"cluster_id,omitempty"`
	ClusterName            string         `json:"cluster_name,omitempty"`
	Status                 string         `json:"status"`
	LastSeenAt             string         `json:"last_seen_at"`
	MaxConcurrent          int            `json:"max_concurrent"`
	ActiveJobs             int            `json:"active_jobs"`
	IdleCapacity           int            `json:"idle_capacity"`
	TargetCapacity         map[string]int `json:"target_capacity,omitempty"`
	ActiveJobsByTargetType map[string]int `json:"active_jobs_by_target_type,omitempty"`
	CacheHealth            map[string]any `json:"cache_health,omitempty"`
	VulnDBStatus           string         `json:"vulndb_status,omitempty"`
	VulnDBBundleVersion    string         `json:"vulndb_bundle_version,omitempty"`
	VulnDBError            string         `json:"vulndb_error,omitempty"`
}

type connectorScanJobDTO struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	TargetType  string `json:"target_type"`
	TargetRef   string `json:"target_ref"`
	ImageRef    string `json:"image_ref,omitempty"`
	Status      string `json:"status"`
	RequestedAt string `json:"requested_at"`
	FinishedAt  string `json:"finished_at,omitempty"`
	Findings    int    `json:"findings"`
	Error       string `json:"error,omitempty"`
}

type connectorGuardrailDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type connectorCoverageOverviewDTO struct {
	Summary            connectorCoverageSummaryDTO `json:"summary"`
	RegistryConnectors []registryConnectorDTO      `json:"registry_connectors"`
	CloudConnectors    []cloudConnectorDTO         `json:"cloud_connectors"`
	Configs            []connectorConfigDTO        `json:"configs"`
	ScanCoverage       []scanCoverageDTO           `json:"scan_coverage"`
	ScannerPools       []scannerPoolDTO            `json:"scanner_pools"`
	RecentJobs         []connectorScanJobDTO       `json:"recent_jobs"`
	Guardrails         []connectorGuardrailDTO     `json:"guardrails"`
}

type connectorCheckPreviewDTO struct {
	ConnectorID       string                  `json:"connector_id"`
	ConnectorType     string                  `json:"connector_type"`
	Status            string                  `json:"status"`
	Message           string                  `json:"message"`
	PersistsSecrets   bool                    `json:"persists_secrets"`
	StartsScan        bool                    `json:"starts_scan"`
	RotatesCredential bool                    `json:"rotates_credential"`
	Guardrails        []connectorGuardrailDTO `json:"guardrails"`
}

type connectorConfigTestDTO struct {
	Config            connectorConfigDTO      `json:"config"`
	Status            string                  `json:"status"`
	Message           string                  `json:"message"`
	PersistsSecrets   bool                    `json:"persists_secrets"`
	StartsScan        bool                    `json:"starts_scan"`
	RotatesCredential bool                    `json:"rotates_credential"`
	Guardrails        []connectorGuardrailDTO `json:"guardrails"`
}

type connectorConfigDTO struct {
	ID                    string `json:"id,omitempty"`
	ConnectorID           string `json:"connector_id"`
	ConnectorType         string `json:"connector_type"`
	Provider              string `json:"provider"`
	DisplayName           string `json:"display_name"`
	Endpoint              string `json:"endpoint"`
	AuthMode              string `json:"auth_mode"`
	Owner                 string `json:"owner"`
	ScanCadence           string `json:"scan_cadence"`
	RotationDueAt         string `json:"rotation_due_at,omitempty"`
	CredentialRef         string `json:"credential_ref,omitempty"`
	CredentialPresent     bool   `json:"credential_present"`
	CredentialFingerprint string `json:"credential_fingerprint,omitempty"`
	LastTestStatus        string `json:"last_test_status"`
	LastTestAt            string `json:"last_test_at,omitempty"`
	UpdatedAt             string `json:"updated_at,omitempty"`
}

type saveConnectorConfigBody struct {
	ConnectorID   string `json:"connector_id"`
	ConnectorType string `json:"connector_type"`
	Provider      string `json:"provider"`
	DisplayName   string `json:"display_name"`
	Endpoint      string `json:"endpoint"`
	AuthMode      string `json:"auth_mode"`
	Owner         string `json:"owner"`
	ScanCadence   string `json:"scan_cadence"`
	RotationDueAt string `json:"rotation_due_at"`
	CredentialRef string `json:"credential_ref"`
	Secret        string `json:"secret"`
}

func (h *ConnectorCoverage) Overview(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		httpx.WriteJSON(w, http.StatusOK, emptyConnectorCoverageOverview())
		return
	}
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	overview, err := h.dbOverview(r, subj.OrgID.String())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, overview)
}

func (h *ConnectorCoverage) Test(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	kind := strings.TrimSpace(r.URL.Query().Get("type"))
	if id == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "connector id required"})
		return
	}
	if kind == "" {
		kind = "registry"
	}
	if kind != "registry" && kind != "cloud" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be registry or cloud"})
		return
	}
	if h.db != nil {
		subj, ok := authctx.SubjectFrom(r.Context())
		if !ok {
			httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}
		exists, err := h.connectorExists(r, subj.OrgID.String(), id, kind)
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if !exists {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": kind + " connector not found"})
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, connectorCheckPreviewDTO{
		ConnectorID:       id,
		ConnectorType:     kind,
		Status:            "preview",
		Message:           "Connectivity check is read-only; no credential is persisted, no scan is started, and no cloud/resource state is changed.",
		PersistsSecrets:   false,
		StartsScan:        false,
		RotatesCredential: false,
		Guardrails:        connectorGuardrails,
	})
}

func (h *ConnectorCoverage) SaveConfig(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "connector config storage unavailable"})
		return
	}
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	var body saveConnectorConfigBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	body.ConnectorID = strings.TrimSpace(body.ConnectorID)
	body.ConnectorType = strings.TrimSpace(body.ConnectorType)
	body.Provider = strings.TrimSpace(body.Provider)
	body.DisplayName = strings.TrimSpace(body.DisplayName)
	body.Endpoint = strings.TrimSpace(body.Endpoint)
	body.AuthMode = strings.TrimSpace(body.AuthMode)
	body.Owner = strings.TrimSpace(body.Owner)
	body.ScanCadence = strings.TrimSpace(body.ScanCadence)
	if body.ScanCadence == "" {
		body.ScanCadence = "daily"
	}
	if body.ConnectorID == "" || body.DisplayName == "" || body.Endpoint == "" || body.AuthMode == "" || body.Owner == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "connector_id, display_name, endpoint, auth_mode, and owner are required"})
		return
	}
	if body.ConnectorType != "registry" && body.ConnectorType != "cloud" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "connector_type must be registry or cloud"})
		return
	}
	if strings.TrimSpace(body.Secret) != "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "raw secrets are not accepted; provide credential_ref from an external secret store"})
		return
	}
	var rotationDueAt *time.Time
	if body.RotationDueAt != "" {
		parsed, err := time.Parse(time.RFC3339, body.RotationDueAt)
		if err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "rotation_due_at must be RFC3339"})
			return
		}
		rotationDueAt = &parsed
	}
	fingerprint := ""
	credentialRef := strings.TrimSpace(body.CredentialRef)
	credentialPresent := credentialRef != ""
	if credentialPresent {
		sum := sha256.Sum256([]byte(credentialRef))
		fingerprint = hex.EncodeToString(sum[:])
	}
	var out connectorConfigDTO
	var rotation *time.Time
	var lastTestAt *time.Time
	var updatedAt time.Time
	if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO connector_configs (
    org_id, connector_id, connector_type, provider, display_name, endpoint, auth_mode,
    owner, scan_cadence, rotation_due_at, credential_ref, credential_fingerprint, credential_present,
    created_by, updated_by, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,''),NULLIF($12,''),$13,$14,$14,NOW())
ON CONFLICT (org_id, connector_type, connector_id) DO UPDATE SET
    provider = EXCLUDED.provider,
    display_name = EXCLUDED.display_name,
    endpoint = EXCLUDED.endpoint,
    auth_mode = EXCLUDED.auth_mode,
    owner = EXCLUDED.owner,
    scan_cadence = EXCLUDED.scan_cadence,
    rotation_due_at = EXCLUDED.rotation_due_at,
    credential_ref = COALESCE(EXCLUDED.credential_ref, connector_configs.credential_ref),
    credential_fingerprint = COALESCE(EXCLUDED.credential_fingerprint, connector_configs.credential_fingerprint),
    credential_present = connector_configs.credential_present OR EXCLUDED.credential_present,
    updated_by = EXCLUDED.updated_by,
    updated_at = NOW()
RETURNING id::text, connector_id, connector_type, provider, display_name, endpoint, auth_mode,
          owner, scan_cadence, rotation_due_at, credential_present,
          COALESCE(credential_ref, ''), COALESCE(credential_fingerprint, ''), last_test_status, last_test_at, updated_at`,
		subj.OrgID, body.ConnectorID, body.ConnectorType, body.Provider, body.DisplayName, body.Endpoint,
		body.AuthMode, body.Owner, body.ScanCadence, rotationDueAt, credentialRef, fingerprint, credentialPresent, subj.UserID).
		Scan(&out.ID, &out.ConnectorID, &out.ConnectorType, &out.Provider, &out.DisplayName, &out.Endpoint,
			&out.AuthMode, &out.Owner, &out.ScanCadence, &rotation, &out.CredentialPresent,
			&out.CredentialRef, &out.CredentialFingerprint, &out.LastTestStatus, &lastTestAt, &updatedAt); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if rotation != nil {
		out.RotationDueAt = rotation.UTC().Format(time.RFC3339)
	}
	if lastTestAt != nil {
		out.LastTestAt = lastTestAt.UTC().Format(time.RFC3339)
	}
	out.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"config": out})
}

func (h *ConnectorCoverage) TestSavedConfig(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "connector config storage unavailable"})
		return
	}
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	configID := strings.TrimSpace(chi.URLParam(r, "id"))
	if configID == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "config id is required"})
		return
	}
	if r.Body != nil && r.ContentLength != 0 {
		var body saveConnectorConfigBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if strings.TrimSpace(body.Secret) != "" {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "raw secrets are not accepted; saved connector tests use credential_ref metadata"})
			return
		}
	}

	var existing connectorConfigDTO
	if err := scanConnectorConfig(h.db.Pool().QueryRow(r.Context(), `
SELECT id::text, connector_id, connector_type, provider, display_name, endpoint, auth_mode,
       owner, scan_cadence, rotation_due_at, credential_present,
       COALESCE(credential_ref, ''), COALESCE(credential_fingerprint, ''), last_test_status, last_test_at, updated_at
  FROM connector_configs
 WHERE id = $1 AND org_id = $2`, configID, subj.OrgID), &existing); err != nil {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "connector config not found"})
		return
	}

	status := "healthy"
	message := "Credential reference is present; saved connector check completed without persisting secrets or starting scans."
	if !existing.CredentialPresent || strings.TrimSpace(existing.CredentialRef) == "" {
		status = "unhealthy"
		message = "Credential reference is missing; add an external secret reference before this connector can run authenticated checks."
	}

	var out connectorConfigDTO
	if err := scanConnectorConfig(h.db.Pool().QueryRow(r.Context(), `
UPDATE connector_configs
   SET last_test_status = $1,
       last_test_at = NOW(),
       updated_by = $2,
       updated_at = NOW()
 WHERE id = $3 AND org_id = $4
RETURNING id::text, connector_id, connector_type, provider, display_name, endpoint, auth_mode,
          owner, scan_cadence, rotation_due_at, credential_present,
          COALESCE(credential_ref, ''), COALESCE(credential_fingerprint, ''), last_test_status, last_test_at, updated_at`,
		status, subj.UserID, configID, subj.OrgID), &out); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, connectorConfigTestDTO{
		Config:            out,
		Status:            status,
		Message:           message,
		PersistsSecrets:   false,
		StartsScan:        false,
		RotatesCredential: false,
		Guardrails:        connectorGuardrails,
	})
}

func (h *ConnectorCoverage) listConfigs(r *http.Request, orgID string) ([]connectorConfigDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, connector_id, connector_type, provider, display_name, endpoint, auth_mode,
       owner, scan_cadence, rotation_due_at, credential_present,
       COALESCE(credential_ref, ''), COALESCE(credential_fingerprint, ''), last_test_status, last_test_at, updated_at
  FROM connector_configs
 WHERE org_id = $1
 ORDER BY updated_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []connectorConfigDTO{}
	for rows.Next() {
		var item connectorConfigDTO
		if err := scanConnectorConfig(rows, &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

type connectorConfigScanner interface {
	Scan(dest ...any) error
}

func scanConnectorConfig(row connectorConfigScanner, item *connectorConfigDTO) error {
	var rotation *time.Time
	var lastTestAt *time.Time
	var updatedAt time.Time
	if err := row.Scan(
		&item.ID, &item.ConnectorID, &item.ConnectorType, &item.Provider, &item.DisplayName,
		&item.Endpoint, &item.AuthMode, &item.Owner, &item.ScanCadence, &rotation, &item.CredentialPresent,
		&item.CredentialRef, &item.CredentialFingerprint, &item.LastTestStatus, &lastTestAt, &updatedAt,
	); err != nil {
		return err
	}
	if rotation != nil {
		item.RotationDueAt = rotation.UTC().Format(time.RFC3339)
	}
	if lastTestAt != nil {
		item.LastTestAt = lastTestAt.UTC().Format(time.RFC3339)
	}
	item.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	return nil
}

func (h *ConnectorCoverage) dbOverview(r *http.Request, orgID string) (connectorCoverageOverviewDTO, error) {
	configs, err := h.listConfigs(r, orgID)
	if err != nil {
		return connectorCoverageOverviewDTO{}, fmt.Errorf("configs: %w", err)
	}

	registryConnectors, err := h.registryConnectors(r, orgID, configs)
	if err != nil {
		return connectorCoverageOverviewDTO{}, fmt.Errorf("registry connectors: %w", err)
	}

	cloudConnectors, cloudResourcesObserved, cloudResourcesAssessed, err := h.cloudConnectors(r, orgID, configs)
	if err != nil {
		return connectorCoverageOverviewDTO{}, fmt.Errorf("cloud connectors: %w", err)
	}

	scanCoverage, err := h.scanCoverage(r, orgID)
	if err != nil {
		return connectorCoverageOverviewDTO{}, fmt.Errorf("scan coverage: %w", err)
	}

	scannerPools, err := h.scannerPools(r, orgID)
	if err != nil {
		return connectorCoverageOverviewDTO{}, fmt.Errorf("scanner pools: %w", err)
	}

	recentJobs, err := h.recentJobs(r, orgID)
	if err != nil {
		return connectorCoverageOverviewDTO{}, fmt.Errorf("recent jobs: %w", err)
	}

	summary := connectorCoverageSummaryDTO{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	summary.RegistryConnectorsTotal = len(registryConnectors)
	summary.CloudConnectorsTotal = len(cloudConnectors)
	summary.CloudResourcesObserved = cloudResourcesObserved
	summary.CloudResourcesAssessed = cloudResourcesAssessed
	for _, c := range registryConnectors {
		if c.Status == "ready" {
			summary.RegistryConnectorsReady++
		}
		summary.ImagesObserved += c.ImagesObserved
		summary.ImagesScanned += c.ImagesScanned
		if rotationDueSoon(c.RotationDueAt) {
			summary.CredentialRotationsDue++
		}
	}
	if summary.ImagesObserved >= summary.ImagesScanned {
		summary.ImagesUnscanned = summary.ImagesObserved - summary.ImagesScanned
	}
	for _, c := range cloudConnectors {
		if c.Status == "ready" {
			summary.CloudConnectorsReady++
		}
		if rotationDueSoon(c.RotationDueAt) {
			summary.CredentialRotationsDue++
		}
	}
	summary.QueuedScans = sumScanQueues(scannerPools)
	return connectorCoverageOverviewDTO{
		Summary:            summary,
		RegistryConnectors: registryConnectors,
		CloudConnectors:    cloudConnectors,
		Configs:            configs,
		ScanCoverage:       scanCoverage,
		ScannerPools:       scannerPools,
		RecentJobs:         recentJobs,
		Guardrails:         connectorGuardrails,
	}, nil
}

func (h *ConnectorCoverage) registryConnectors(r *http.Request, orgID string, configs []connectorConfigDTO) ([]registryConnectorDTO, error) {
	configsByConnector := connectorConfigsByKey(configs)
	rows, err := h.db.Pool().Query(r.Context(), `
WITH image_counts AS (
    SELECT registry_id,
           COUNT(*)::int AS repositories,
           COALESCE(SUM(GREATEST(cardinality(tags), 1)), 0)::int AS images_observed
      FROM registry_images
     WHERE org_id = $1
     GROUP BY registry_id
)
SELECT r.id::text, r.name, r.kind, r.endpoint, r.auth_kind,
       (r.auth_secret IS NOT NULL) AS has_secret,
       r.scan_cadence, r.last_sync_at, COALESCE(r.last_sync_status, ''),
       COALESCE(r.last_sync_error, ''), COALESCE(ic.repositories, 0),
       COALESCE(ic.images_observed, r.images_seen, 0),
       COALESCE(sc.completed_scans, 0), sc.last_scan_at
  FROM registries r
  LEFT JOIN image_counts ic ON ic.registry_id = r.id
  LEFT JOIN LATERAL (
      SELECT COUNT(*) FILTER (WHERE sj.status = 'completed')::int AS completed_scans,
             MAX(COALESCE(sj.finished_at, sj.claimed_at, sj.requested_at)) AS last_scan_at
        FROM scan_jobs sj
        JOIN scan_targets st ON st.id = sj.target_id
       WHERE sj.org_id = $1
         AND (
              st.registry_id = r.id
              OR st.ref LIKE r.endpoint || '%'
              OR st.image_ref LIKE r.endpoint || '%'
              OR EXISTS (
                    SELECT 1 FROM registry_images ri
                     WHERE ri.registry_id = r.id
                       AND ri.org_id = $1
                       AND (st.ref LIKE ri.repository || '%' OR st.image_ref LIKE ri.repository || '%')
              )
         )
  ) sc ON TRUE
 WHERE r.org_id = $1
 ORDER BY r.updated_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []registryConnectorDTO{}
	for rows.Next() {
		var (
			id, name, provider, endpoint, authMode string
			hasSecret                              bool
			cadence, syncStatus, syncError         string
			lastSync, lastScan                     *time.Time
			repositories, observed, scanned        int
		)
		if err := rows.Scan(&id, &name, &provider, &endpoint, &authMode, &hasSecret, &cadence,
			&lastSync, &syncStatus, &syncError, &repositories, &observed, &scanned, &lastScan); err != nil {
			return nil, err
		}
		if observed > 0 && scanned > observed {
			scanned = observed
		}
		config := firstConnectorConfig(configsByConnector, id, name, endpoint)
		rotationDue := ""
		if config != nil {
			rotationDue = config.RotationDueAt
		}
		out = append(out, registryConnectorDTO{
			ID:              id,
			Name:            name,
			Provider:        provider,
			Status:          registryStatus(authMode, hasSecret, lastSync, syncStatus),
			Endpoint:        endpoint,
			AuthMode:        authMode,
			Repositories:    repositories,
			ImagesObserved:  observed,
			ImagesScanned:   scanned,
			LastScanAt:      formatOptionalTime(lastScan),
			NextScanAt:      nextCadenceTime(lastSync, cadence),
			CredentialAge:   registryCredentialAge(authMode, hasSecret),
			RotationDueAt:   rotationDue,
			SupportedChecks: registrySupportedChecks(provider),
			Notes:           registryNotes(lastSync, syncStatus, syncError),
		})
	}
	return out, rows.Err()
}

func (h *ConnectorCoverage) cloudConnectors(r *http.Request, orgID string, configs []connectorConfigDTO) ([]cloudConnectorDTO, int, int, error) {
	var resourcesObserved, resourcesAssessed, findingsOpen int
	var lastAssessment *time.Time
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT COUNT(DISTINCT a.id) FILTER (WHERE a.kind = 'cloud-resource')::int,
       COUNT(DISTINCT a.id) FILTER (WHERE a.kind = 'cloud-resource' AND f.id IS NOT NULL)::int,
       COUNT(f.id) FILTER (WHERE f.kind = 'cloud-config' AND f.lifecycle = 'open')::int,
       MAX(f.last_seen_at) FILTER (WHERE f.kind = 'cloud-config')
  FROM assets a
  LEFT JOIN findings f ON f.org_id = a.org_id AND f.asset_id = a.id AND f.kind = 'cloud-config'
 WHERE a.org_id = $1`, orgID).Scan(&resourcesObserved, &resourcesAssessed, &findingsOpen, &lastAssessment); err != nil {
		return nil, 0, 0, err
	}

	cloudConfigs := make([]connectorConfigDTO, 0, len(configs))
	for _, config := range configs {
		if config.ConnectorType == "cloud" {
			cloudConfigs = append(cloudConfigs, config)
		}
	}
	out := make([]cloudConnectorDTO, 0, len(cloudConfigs))
	for _, config := range cloudConfigs {
		itemResourcesObserved := 0
		itemResourcesAssessed := 0
		itemFindingsOpen := 0
		if len(cloudConfigs) == 1 {
			itemResourcesObserved = resourcesObserved
			itemResourcesAssessed = resourcesAssessed
			itemFindingsOpen = findingsOpen
		}
		last := lastAssessment
		if config.LastTestAt != "" {
			if parsed, err := time.Parse(time.RFC3339, config.LastTestAt); err == nil {
				last = &parsed
			}
		}
		out = append(out, cloudConnectorDTO{
			ID:                configID(config),
			Name:              config.DisplayName,
			Provider:          config.Provider,
			Status:            cloudStatus(config),
			Account:           config.Endpoint,
			Regions:           []string{},
			AuthMode:          config.AuthMode,
			ResourcesObserved: itemResourcesObserved,
			ResourcesAssessed: itemResourcesAssessed,
			FindingsOpen:      itemFindingsOpen,
			LastAssessmentAt:  formatOptionalTime(last),
			NextAssessmentAt:  nextCadenceTime(last, config.ScanCadence),
			CredentialAge:     configCredentialAge(config),
			RotationDueAt:     config.RotationDueAt,
			Controls:          cloudControls(config.Provider),
			Notes:             "Cloud posture connector metadata is sourced from saved connector configuration; resource evidence is read from cloud-resource assets and cloud-config findings.",
		})
	}
	return out, resourcesObserved, resourcesAssessed, nil
}

func (h *ConnectorCoverage) scanCoverage(r *http.Request, orgID string) ([]scanCoverageDTO, error) {
	var deployedObserved, deployedScanned, deployedCriticalGaps int
	var deployedLast *time.Time
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT COUNT(*)::int,
       COUNT(*) FILTER (WHERE COALESCE(scan.result_count, 0) > 0)::int,
       COUNT(*) FILTER (
           WHERE lower(a.criticality) IN ('high', 'critical')
             AND COALESCE(scan.result_count, 0) = 0
       )::int,
       MAX(COALESCE(scan.last_scanned_at, a.last_seen_at))
  FROM assets a
  LEFT JOIN LATERAL (
      SELECT COUNT(*)::int AS result_count,
             MAX(r.last_scanned_at) AS last_scanned_at
        FROM image_scan_results r
       WHERE r.org_id = a.org_id
         AND (
              r.asset_id = a.id
           OR (a.digest IS NOT NULL AND r.image_digest = a.digest)
           OR r.image_ref = a.name
           OR r.image_ref_normalized = a.name
         )
  ) scan ON true
 WHERE a.org_id = $1 AND a.kind = 'image'`, orgID).Scan(&deployedObserved, &deployedScanned, &deployedCriticalGaps, &deployedLast); err != nil {
		return nil, err
	}

	var ciObserved, ciScanned, ciCriticalGaps int
	var ciLast *time.Time
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT COUNT(*)::int,
       COUNT(*) FILTER (WHERE status = 'completed')::int,
       COUNT(*) FILTER (WHERE status = 'failed')::int,
       MAX(COALESCE(finished_at, claimed_at, requested_at))
  FROM scan_jobs
 WHERE org_id = $1`, orgID).Scan(&ciObserved, &ciScanned, &ciCriticalGaps, &ciLast); err != nil {
		return nil, err
	}

	var cloudObserved, cloudAssessed, cloudCriticalGaps int
	var cloudLast *time.Time
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT COUNT(DISTINCT a.id) FILTER (WHERE a.kind = 'cloud-resource')::int,
       COUNT(DISTINCT a.id) FILTER (WHERE a.kind = 'cloud-resource' AND f.id IS NOT NULL)::int,
       COUNT(f.id) FILTER (WHERE f.kind = 'cloud-config' AND f.lifecycle = 'open' AND f.severity IN ('high', 'critical'))::int,
       MAX(f.last_seen_at) FILTER (WHERE f.kind = 'cloud-config')
  FROM assets a
  LEFT JOIN findings f ON f.org_id = a.org_id AND f.asset_id = a.id AND f.kind = 'cloud-config'
 WHERE a.org_id = $1`, orgID).Scan(&cloudObserved, &cloudAssessed, &cloudCriticalGaps, &cloudLast); err != nil {
		return nil, err
	}

	var hostObserved, hostScanned, hostGaps int
	var hostLast *time.Time
	if err := h.db.Pool().QueryRow(r.Context(), `
WITH hosts AS (
    SELECT hp.id, hp.org_id, hp.cluster_id, hp.node, hp.observed_at,
           st.id AS target_id
      FROM host_packages hp
      LEFT JOIN scan_targets st
        ON st.org_id = hp.org_id
       AND st.type = 'host'
       AND st.ref = hp.node
       AND (
            st.cluster_id = hp.cluster_id
            OR (st.cluster_id IS NULL AND hp.cluster_id IS NULL)
       )
     WHERE hp.org_id = $1
)
SELECT COUNT(*)::int,
       COUNT(*) FILTER (
           WHERE EXISTS (
               SELECT 1 FROM scan_jobs sj
                WHERE sj.org_id = hosts.org_id
                  AND sj.target_id = hosts.target_id
                  AND sj.status = 'completed'
           )
       )::int,
       COUNT(*) FILTER (
           WHERE NOT EXISTS (
               SELECT 1 FROM scan_jobs sj
                WHERE sj.org_id = hosts.org_id
                  AND sj.target_id = hosts.target_id
                  AND sj.status = 'completed'
           )
       )::int,
       MAX(COALESCE(se.observed_at, hosts.observed_at))
  FROM hosts
  LEFT JOIN scan_evidence se
    ON se.org_id = hosts.org_id
   AND se.scan_target_id = hosts.target_id
   AND se.evidence_type = 'package-inventory'`, orgID).Scan(&hostObserved, &hostScanned, &hostGaps, &hostLast); err != nil {
		return nil, err
	}

	return []scanCoverageDTO{
		scanCoverageItem("Deployed images", deployedObserved, deployedScanned, deployedCriticalGaps, deployedLast, "Queue scans for image assets that lack completed scan evidence."),
		scanCoverageItem("CI submitted images", ciObserved, ciScanned, ciCriticalGaps, ciLast, "Retry failed scan jobs and require digest-pinned image refs from CI gates."),
		scanCoverageItem("Host package evidence", hostObserved, hostScanned, hostGaps, hostLast, "Keep runtime-agent package evidence fresh and complete host scan jobs for each node."),
		scanCoverageItem("Cloud resources", cloudObserved, cloudAssessed, cloudCriticalGaps, cloudLast, "Enable cloud connector credentials and run CSPM assessment for unassessed cloud assets."),
	}, nil
}

func (h *ConnectorCoverage) scannerPools(r *http.Request, orgID string) ([]scannerPoolDTO, error) {
	scanners, err := h.scannerWorkers(r, orgID)
	if err != nil {
		return nil, err
	}
	desired := len(scanners)
	ready := 0
	activeJobs := 0
	idleCapacity := 0
	var lastSeen *time.Time
	for _, scanner := range scanners {
		if scanner.Status == "ready" {
			ready++
		}
		activeJobs += scanner.ActiveJobs
		idleCapacity += scanner.IdleCapacity
		if scanner.LastSeenAt != "" {
			if seen, err := time.Parse(time.RFC3339, scanner.LastSeenAt); err == nil {
				if lastSeen == nil || seen.After(*lastSeen) {
					t := seen
					lastSeen = &t
				}
			}
		}
	}
	var queueDepth, staleLeases, p95Seconds int
	if err := h.db.Pool().QueryRow(r.Context(), `
	SELECT COUNT(*) FILTER (WHERE status = 'pending')::int,
	       COUNT(*) FILTER (
	           WHERE status = 'running'
	             AND (
	               (lease_expires_at IS NOT NULL AND lease_expires_at < NOW())
	               OR (lease_expires_at IS NULL AND claimed_at IS NOT NULL AND claimed_at < NOW() - $2::interval)
	             )
	       )::int
	  FROM scan_jobs
	 WHERE org_id = $1`, orgID, handler.ScannerJobLeaseInterval).Scan(&queueDepth, &staleLeases); err != nil {
		return nil, err
	}
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT COALESCE(ROUND((percentile_cont(0.95) WITHIN GROUP (
           ORDER BY EXTRACT(EPOCH FROM finished_at - COALESCE(claimed_at, requested_at))
       ))::numeric), 0)::int
  FROM scan_jobs
 WHERE org_id = $1
   AND status = 'completed'
   AND finished_at IS NOT NULL`, orgID).Scan(&p95Seconds); err != nil {
		return nil, err
	}
	queueByTargetType, err := handler.ScanQueueMetrics(r.Context(), h.db.Pool(), orgID)
	if err != nil {
		return nil, err
	}

	return []scannerPoolDTO{{
		ID:                "scanner-workers",
		Name:              "Scanner workers",
		Status:            scannerPoolStatus(desired, ready, queueDepth, staleLeases, lastSeen),
		DesiredWorkers:    desired,
		ReadyWorkers:      ready,
		ActiveJobs:        activeJobs,
		IdleCapacity:      idleCapacity,
		QueueDepth:        queueDepth,
		StaleLeases:       staleLeases,
		P95Duration:       durationLabel(p95Seconds),
		Capacity:          capacityLabel(ready, p95Seconds),
		QueueByTargetType: queueByTargetType,
		Scanners:          scanners,
	}}, nil
}

func (h *ConnectorCoverage) scannerWorkers(r *http.Request, orgID string) ([]scannerWorkerDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT ch.hostname, COALESCE(ch.cluster_id::text, ''), COALESCE(c.name, ''), ch.last_seen_at, ch.metadata
  FROM component_heartbeats ch
  LEFT JOIN clusters c ON c.id = ch.cluster_id
 WHERE ch.org_id = $1
   AND ch.component = 'scanner'
 ORDER BY ch.last_seen_at DESC, ch.hostname`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	out := []scannerWorkerDTO{}
	for rows.Next() {
		var (
			hostname    string
			clusterID   string
			clusterName string
			lastSeen    time.Time
			raw         []byte
		)
		if err := rows.Scan(&hostname, &clusterID, &clusterName, &lastSeen, &raw); err != nil {
			return nil, err
		}
		item := scannerWorkerDTO{
			Hostname:               hostname,
			ClusterID:              clusterID,
			ClusterName:            clusterName,
			Status:                 "stale",
			LastSeenAt:             lastSeen.UTC().Format(time.RFC3339),
			TargetCapacity:         map[string]int{},
			ActiveJobsByTargetType: map[string]int{},
		}
		if now.Sub(lastSeen) <= 2*time.Minute {
			item.Status = "ready"
		}
		var metadata map[string]any
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &metadata)
		}
		item.InstanceID = handler.MetadataString(metadata, "instance_id")
		item.MaxConcurrent = handler.MetadataInt(metadata, "max_concurrent")
		item.ActiveJobs = handler.MetadataInt(metadata, "active_jobs")
		item.IdleCapacity = handler.MetadataInt(metadata, "idle_capacity")
		item.TargetCapacity = metadataIntMap(handler.MetadataMap(metadata, "target_capacity"))
		item.ActiveJobsByTargetType = metadataIntMap(handler.MetadataMap(metadata, "active_jobs_by_target_type"))
		item.CacheHealth = handler.MetadataMap(metadata, "cache_health")
		if vuln := handler.MetadataMap(metadata, "vulndb"); len(vuln) > 0 {
			item.VulnDBStatus = handler.MetadataString(vuln, "status")
			item.VulnDBBundleVersion = handler.MetadataString(vuln, "bundle_version")
			item.VulnDBError = handler.MetadataString(vuln, "error")
			if item.Status == "ready" && handler.MetadataBool(vuln, "enabled") && !handler.MetadataBool(vuln, "ready") {
				item.Status = "degraded"
			}
		}
		if item.Status == "ready" && handler.ScannerHeartbeatDegradedReason(metadata) != "" {
			item.Status = "degraded"
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *ConnectorCoverage) recentJobs(r *http.Request, orgID string) ([]connectorScanJobDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT sj.id::text, st.type, st.ref, COALESCE(st.image_ref, ''),
       st.source_type, sj.status, sj.requested_at, sj.finished_at,
       COALESCE(sj.finding_count, 0), COALESCE(sj.error, '')
  FROM scan_jobs sj
  JOIN scan_targets st ON st.id = sj.target_id
 WHERE sj.org_id = $1
 ORDER BY sj.requested_at DESC
 LIMIT 5`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []connectorScanJobDTO{}
	for rows.Next() {
		var item connectorScanJobDTO
		var requestedAt time.Time
		var finishedAt *time.Time
		var sourceType string
		if err := rows.Scan(&item.ID, &item.TargetType, &item.TargetRef, &item.ImageRef, &sourceType,
			&item.Status, &requestedAt, &finishedAt, &item.Findings, &item.Error); err != nil {
			return nil, err
		}
		if sourceType != "" {
			item.Source = sourceType
		} else {
			item.Source = imageRefSource(item.ImageRef)
		}
		item.RequestedAt = requestedAt.UTC().Format(time.RFC3339)
		item.FinishedAt = formatOptionalTime(finishedAt)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *ConnectorCoverage) connectorExists(r *http.Request, orgID, id, kind string) (bool, error) {
	if kind == "registry" {
		var exists bool
		err := h.db.Pool().QueryRow(r.Context(), `
SELECT EXISTS (
    SELECT 1 FROM registries
     WHERE org_id = $1
       AND (id::text = $2 OR name = $2 OR endpoint = $2)
    UNION ALL
    SELECT 1 FROM connector_configs
     WHERE org_id = $1
       AND connector_type = 'registry'
       AND (id::text = $2 OR connector_id = $2 OR display_name = $2 OR endpoint = $2)
)`, orgID, id).Scan(&exists)
		return exists, err
	}
	var exists bool
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT EXISTS (
    SELECT 1 FROM connector_configs
     WHERE org_id = $1
       AND connector_type = 'cloud'
       AND (id::text = $2 OR connector_id = $2 OR display_name = $2 OR endpoint = $2)
)`, orgID, id).Scan(&exists)
	return exists, err
}

func emptyConnectorCoverageOverview() connectorCoverageOverviewDTO {
	return connectorCoverageOverviewDTO{
		Summary:    connectorCoverageSummaryDTO{GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		Guardrails: connectorGuardrails,
	}
}

func connectorConfigsByKey(configs []connectorConfigDTO) map[string]connectorConfigDTO {
	out := map[string]connectorConfigDTO{}
	for _, config := range configs {
		for _, key := range []string{config.ID, config.ConnectorID, config.DisplayName, config.Endpoint} {
			key = strings.TrimSpace(key)
			if key != "" {
				out[key] = config
			}
		}
	}
	return out
}

func firstConnectorConfig(configs map[string]connectorConfigDTO, keys ...string) *connectorConfigDTO {
	for _, key := range keys {
		if config, ok := configs[key]; ok {
			return &config
		}
	}
	return nil
}

func configID(config connectorConfigDTO) string {
	if config.ID != "" {
		return config.ID
	}
	return config.ConnectorID
}

func registryStatus(authKind string, hasSecret bool, lastSync *time.Time, syncStatus string) string {
	if authKind != "none" && !hasSecret {
		return "needs-setup"
	}
	switch syncStatus {
	case "ok":
		return "ready"
	case "failed", "partial":
		return "degraded"
	}
	if lastSync == nil {
		return "pending"
	}
	return "ready"
}

func cloudStatus(config connectorConfigDTO) string {
	if !config.CredentialPresent {
		return "needs-setup"
	}
	switch config.LastTestStatus {
	case "healthy":
		return "ready"
	case "unhealthy":
		return "degraded"
	default:
		return "pending"
	}
}

func registryCredentialAge(authKind string, hasSecret bool) string {
	if authKind == "none" {
		return "n/a"
	}
	if !hasSecret {
		return "missing"
	}
	return "configured"
}

func configCredentialAge(config connectorConfigDTO) string {
	if !config.CredentialPresent {
		return "missing"
	}
	return "configured"
}

func registryNotes(lastSync *time.Time, syncStatus, syncError string) string {
	if syncError != "" {
		return "Last registry walker sync reported: " + syncError
	}
	if lastSync == nil {
		return "Awaiting first registry walker sync."
	}
	if syncStatus == "partial" {
		return "Registry walker completed with partial inventory coverage."
	}
	return "Sourced from registry walker inventory and scan job history."
}

func registrySupportedChecks(provider string) []string {
	switch provider {
	case "docker-hub", "acr":
		return []string{"sbom", "cve", "license"}
	case "ecr", "quay":
		return []string{"sbom", "cve", "signature"}
	default:
		return []string{"sbom", "cve", "secret", "license", "signature"}
	}
}

func cloudControls(provider string) []string {
	switch provider {
	case "aws":
		return []string{"IAM overprivilege", "S3 public access", "EKS control-plane"}
	case "gcp":
		return []string{"project IAM", "GCS public access", "service account keys"}
	case "azure":
		return []string{"RBAC overprivilege", "storage public access"}
	default:
		return []string{"IAM posture", "storage exposure", "control-plane hardening"}
	}
}

func scanCoverageItem(scope string, observed, scanned, criticalGaps int, last *time.Time, recommendedFix string) scanCoverageDTO {
	unscanned := observed - scanned
	if unscanned < 0 {
		unscanned = 0
	}
	return scanCoverageDTO{
		Scope:          scope,
		Observed:       observed,
		Scanned:        scanned,
		Unscanned:      unscanned,
		CriticalGaps:   criticalGaps,
		LastCoveredAt:  formatOptionalTime(last),
		RecommendedFix: recommendedFix,
	}
}

func scannerPoolStatus(desired, ready, queueDepth, staleLeases int, lastSeen *time.Time) string {
	if staleLeases > 0 {
		return "degraded"
	}
	if desired == 0 {
		if queueDepth > 0 {
			return "degraded"
		}
		return "idle"
	}
	if ready == desired {
		return "healthy"
	}
	if ready > 0 {
		return "degraded"
	}
	if lastSeen != nil {
		return "degraded"
	}
	return "missing"
}

func metadataIntMap(source map[string]any) map[string]int {
	if len(source) == 0 {
		return nil
	}
	out := make(map[string]int, len(source))
	for key, raw := range source {
		switch value := raw.(type) {
		case float64:
			out[key] = int(value)
		case int:
			out[key] = value
		case int64:
			out[key] = int(value)
		case json.Number:
			n, _ := value.Int64()
			out[key] = int(n)
		}
	}
	return out
}

func durationLabel(seconds int) string {
	if seconds <= 0 {
		return "n/a"
	}
	d := time.Duration(seconds) * time.Second
	if d >= time.Hour {
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	if d >= time.Minute {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", seconds)
}

func capacityLabel(ready, p95Seconds int) string {
	if ready <= 0 || p95Seconds <= 0 {
		return "awaiting scans"
	}
	perHour := ready * 3600 / p95Seconds
	if perHour < 1 {
		perHour = 1
	}
	return fmt.Sprintf("%d images/hour", perHour)
}

func nextCadenceTime(last *time.Time, cadence string) string {
	d, ok := cadenceDuration(cadence)
	if !ok {
		return ""
	}
	base := time.Now().UTC()
	if last != nil {
		base = last.UTC()
	}
	return base.Add(d).Format(time.RFC3339)
}

func cadenceDuration(cadence string) (time.Duration, bool) {
	switch cadence {
	case "hourly":
		return time.Hour, true
	case "6h":
		return 6 * time.Hour, true
	case "daily":
		return 24 * time.Hour, true
	case "weekly":
		return 7 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func rotationDueSoon(value string) bool {
	if value == "" || value == "n/a" {
		return false
	}
	due, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return false
	}
	return due.Before(time.Now().UTC().Add(30 * 24 * time.Hour))
}

func imageRefSource(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "manual"
	}
	if i := strings.Index(ref, "/"); i > 0 {
		return ref[:i]
	}
	return "manual"
}

func sumScanQueues(pools []scannerPoolDTO) int {
	total := 0
	for _, pool := range pools {
		total += pool.QueueDepth
	}
	return total
}

var connectorGuardrails = []connectorGuardrailDTO{
	{ID: "secret-redaction", Name: "Credential redaction", Status: "enforced", Description: "Connector API returns logical auth mode and age only; raw tokens and keys are never returned."},
	{ID: "dry-run-checks", Name: "Dry-run connectivity checks", Status: "enforced", Description: "Test actions do not persist secrets, start scans, rotate credentials, or mutate cloud state."},
	{ID: "delegated-scanning", Name: "Delegated private scanning", Status: "active", Description: "Private registry scans can run from secured-cluster workers rather than hosted control-plane egress."},
	{ID: "coverage-gates", Name: "Release coverage gates", Status: "active", Description: "Unscanned critical images are surfaced before admission and CI enforcement decisions."},
}
