// File profile handlers. These expose the workload file-monitor lifecycle that
// sits beside process baselines: learn observed paths, monitor drift, and
// enforce after review once the agent can consume the approved profile.
//
//	GET  /api/v1/runtime/file-profiles?cluster_id=&namespace=
//	GET  /api/v1/runtime/file-profiles/{workload_id}
//	GET  /api/v1/runtime/file-profiles/{workload_id}/export
//	POST /api/v1/runtime/file-profiles/{workload_id}/mode
//	POST /api/v1/runtime/file-profiles/{workload_id}:import
//	POST /api/v1/runtime/file-profiles/{workload_id}/exceptions
//	GET  /api/v1/runtime/file-profile-rules:bundle?cluster_id=    runtime-agent rule bundle
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type fileProfileMode string

const (
	fileProfileModeLearn   fileProfileMode = "learn"
	fileProfileModeMonitor fileProfileMode = "monitor"
	fileProfileModeEnforce fileProfileMode = "enforce"
)

const fileProfileBundleSchemaVersion = "constellation-file-profile-v1"

// FileProfiles is the HTTP handler for workload file-monitor profiles.
type FileProfiles struct {
	db       *db.DB
	auditLog *audit.Logger
}

func NewFileProfiles(d *db.DB, a *audit.Logger) *FileProfiles {
	return &FileProfiles{db: d, auditLog: a}
}

type fileProfileState struct {
	WorkloadID         string
	ClusterID          string
	Namespace          string
	Name               string
	Mode               fileProfileMode
	LearnStartedAt     time.Time
	MonitorStartedAt   time.Time
	EnforceStartedAt   time.Time
	Files              []fileObservation
	Alerts24h          int
	Blocks24h          int
	SensitivePathCount int
	LastNewPathAt      time.Time
	Transitions        []fileProfileTransition
	Rules              []fileProfileRule
	Exceptions         []fileProfileException
	WatchedFiles       []fileProfileWatch
}

type fileObservation struct {
	Path          string
	Operation     string
	Comm          string
	Flags         uint32
	Mode          uint32
	ObservedCount int
	Sensitive     bool
	FirstSeen     time.Time
	LastSeen      time.Time
}

type fileProfileTransition struct {
	At     time.Time
	Actor  string
	From   fileProfileMode
	To     fileProfileMode
	Reason string
}

type fileProfileRule struct {
	ID           uuid.UUID
	Filter       string
	Path         string
	Regex        string
	Recursive    bool
	Behavior     string
	Applications []string
	Enabled      bool
	Description  string
	CreatedBy    string
	UpdatedBy    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type fileProfileException struct {
	ID           uuid.UUID
	RuleID       uuid.UUID
	Filter       string
	Path         string
	Regex        string
	Recursive    bool
	Applications []string
	Enabled      bool
	Description  string
	ExpiresAt    time.Time
	CreatedBy    string
	UpdatedBy    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type fileProfileWatch struct {
	Node              string
	RuleID            uuid.UUID
	Filter            string
	Path              string
	Regex             string
	Recursive         bool
	Behavior          string
	Applications      []string
	ProfileMode       fileProfileMode
	DesiredProtect    bool
	Protect           bool
	EnforcementState  string
	Files             json.RawMessage
	FilesCount        int
	SensitiveCount    int
	BundleFingerprint string
	ObservedAt        time.Time
	UpdatedAt         time.Time
}

type parsedFileProfileFilter struct {
	Filter string
	Path   string
	Regex  string
}

type fileProfileSummaryDTO struct {
	WorkloadID         string   `json:"workload_id"`
	ClusterID          string   `json:"cluster_id,omitempty"`
	Namespace          string   `json:"namespace"`
	Name               string   `json:"name"`
	Mode               string   `json:"mode"`
	LearnedPathsCount  int      `json:"learned_paths_count"`
	SensitivePathCount int      `json:"sensitive_path_count"`
	MonitoredAlerts24h int      `json:"monitored_alerts_24h"`
	EnforcedBlocks24h  int      `json:"enforced_blocks_24h"`
	LearnStartedAt     string   `json:"learn_started_at,omitempty"`
	MonitorStartedAt   string   `json:"monitor_started_at,omitempty"`
	EnforceStartedAt   string   `json:"enforce_started_at,omitempty"`
	LastNewPathAt      string   `json:"last_new_path_at,omitempty"`
	TopPaths           []string `json:"top_paths,omitempty"`
	RuleCount          int      `json:"rule_count"`
	WatchedFileCount   int      `json:"watched_file_count"`
}

type fileProfileFileDTO struct {
	Path          string `json:"path"`
	Operation     string `json:"operation"`
	Comm          string `json:"comm,omitempty"`
	Flags         uint32 `json:"flags"`
	Mode          uint32 `json:"mode"`
	ObservedCount int    `json:"observed_count"`
	Sensitive     bool   `json:"sensitive"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
}

type fileProfileTransitionDTO struct {
	At     string `json:"at"`
	Actor  string `json:"actor"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

type fileProfileRuleDTO struct {
	ID           string   `json:"id"`
	Filter       string   `json:"filter"`
	Path         string   `json:"path"`
	Regex        string   `json:"regex"`
	Recursive    bool     `json:"recursive"`
	Behavior     string   `json:"behavior"`
	Applications []string `json:"applications"`
	Enabled      bool     `json:"enabled"`
	Description  string   `json:"description,omitempty"`
	CreatedBy    string   `json:"created_by,omitempty"`
	UpdatedBy    string   `json:"updated_by,omitempty"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

type fileProfileExceptionDTO struct {
	ID           string   `json:"id"`
	RuleID       string   `json:"rule_id,omitempty"`
	Filter       string   `json:"filter"`
	Path         string   `json:"path"`
	Regex        string   `json:"regex"`
	Recursive    bool     `json:"recursive"`
	Applications []string `json:"applications"`
	Enabled      bool     `json:"enabled"`
	Description  string   `json:"description,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	CreatedBy    string   `json:"created_by,omitempty"`
	UpdatedBy    string   `json:"updated_by,omitempty"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

type fileProfileRuleBundleDTO struct {
	ClusterID   string                     `json:"cluster_id"`
	GeneratedAt string                     `json:"generated_at"`
	Rules       []fileProfileRuleBundleRow `json:"rules"`
}

type fileProfileRuleBundleRow struct {
	ID             string                              `json:"id"`
	WorkloadID     string                              `json:"workload_id"`
	PodWorkloadIDs []string                            `json:"pod_workload_ids,omitempty"`
	Namespace      string                              `json:"namespace,omitempty"`
	Name           string                              `json:"name,omitempty"`
	Mode           string                              `json:"mode"`
	Filter         string                              `json:"filter"`
	Path           string                              `json:"path"`
	Regex          string                              `json:"regex"`
	Recursive      bool                                `json:"recursive"`
	Behavior       string                              `json:"behavior"`
	Applications   []string                            `json:"applications"`
	Exceptions     []fileProfileRuleExceptionBundleRow `json:"exceptions,omitempty"`
	Description    string                              `json:"description,omitempty"`
	UpdatedAt      string                              `json:"updated_at"`
}

type fileProfileRuleExceptionBundleRow struct {
	ID           string   `json:"id"`
	RuleID       string   `json:"rule_id,omitempty"`
	Filter       string   `json:"filter"`
	Path         string   `json:"path"`
	Regex        string   `json:"regex"`
	Recursive    bool     `json:"recursive"`
	Applications []string `json:"applications"`
	Description  string   `json:"description,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	UpdatedAt    string   `json:"updated_at"`
}

type fileProfileWatchDTO struct {
	Node              string   `json:"node"`
	RuleID            string   `json:"rule_id"`
	Filter            string   `json:"filter"`
	Path              string   `json:"path"`
	Regex             string   `json:"regex"`
	Recursive         bool     `json:"recursive"`
	Behavior          string   `json:"behavior"`
	Applications      []string `json:"applications"`
	ProfileMode       string   `json:"profile_mode"`
	DesiredProtect    bool     `json:"desired_protect"`
	Protect           bool     `json:"protect"`
	EnforcementState  string   `json:"enforcement_state"`
	Files             any      `json:"files"`
	FilesCount        int      `json:"files_count"`
	SensitiveCount    int      `json:"sensitive_count"`
	BundleFingerprint string   `json:"bundle_fingerprint,omitempty"`
	ObservedAt        string   `json:"observed_at"`
	UpdatedAt         string   `json:"updated_at"`
}

type fileProfileDetailDTO struct {
	fileProfileSummaryDTO
	Files        []fileProfileFileDTO       `json:"files"`
	Transitions  []fileProfileTransitionDTO `json:"transitions"`
	Rules        []fileProfileRuleDTO       `json:"rules"`
	Exceptions   []fileProfileExceptionDTO  `json:"exceptions"`
	WatchedFiles []fileProfileWatchDTO      `json:"watched_files"`
}

type fileProfilePortableRuleDTO struct {
	ID           string   `json:"id,omitempty"`
	Filter       string   `json:"filter"`
	Path         string   `json:"path,omitempty"`
	Regex        string   `json:"regex,omitempty"`
	Recursive    bool     `json:"recursive"`
	Behavior     string   `json:"behavior"`
	Applications []string `json:"applications"`
	Enabled      *bool    `json:"enabled,omitempty"`
	Description  string   `json:"description,omitempty"`
	SourceID     string   `json:"source_id,omitempty"`
	SourceGroup  string   `json:"source_group,omitempty"`
	CfgType      string   `json:"cfg_type,omitempty"`
}

type fileProfilePortableExceptionDTO struct {
	ID           string   `json:"id,omitempty"`
	RuleID       string   `json:"rule_id,omitempty"`
	Filter       string   `json:"filter"`
	Path         string   `json:"path,omitempty"`
	Regex        string   `json:"regex,omitempty"`
	Recursive    bool     `json:"recursive"`
	Applications []string `json:"applications"`
	Enabled      *bool    `json:"enabled,omitempty"`
	Description  string   `json:"description,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
}

type fileProfileExportBundle struct {
	SchemaVersion string                            `json:"schema_version"`
	Kind          string                            `json:"kind"`
	WorkloadID    string                            `json:"workload_id"`
	ClusterID     string                            `json:"cluster_id,omitempty"`
	Namespace     string                            `json:"namespace,omitempty"`
	Name          string                            `json:"name,omitempty"`
	Mode          string                            `json:"mode"`
	ExportedAt    string                            `json:"exported_at"`
	Rules         []fileProfilePortableRuleDTO      `json:"rules"`
	Exceptions    []fileProfilePortableExceptionDTO `json:"exceptions,omitempty"`
}

type fileProfileImportRequest struct {
	Bundle  *fileProfileExportBundle `json:"bundle,omitempty"`
	Mode    string                   `json:"mode,omitempty"`
	DryRun  bool                     `json:"dry_run,omitempty"`
	Replace bool                     `json:"replace,omitempty"`
	Reason  string                   `json:"reason"`
}

type fileProfileImportResponse struct {
	DryRun           bool                              `json:"dry_run"`
	Replace          bool                              `json:"replace"`
	Imported         int                               `json:"imported"`
	Deleted          int64                             `json:"deleted"`
	Mode             string                            `json:"mode"`
	ClusterID        string                            `json:"cluster_id"`
	TargetWorkloadID string                            `json:"target_workload_id"`
	Rules            []fileProfilePortableRuleDTO      `json:"rules"`
	Exceptions       []fileProfilePortableExceptionDTO `json:"exceptions,omitempty"`
	Warnings         []string                          `json:"warnings,omitempty"`
}

type fileProfileWatchReportBody struct {
	ClusterID         string                       `json:"cluster_id"`
	Node              string                       `json:"node"`
	ObservedAt        time.Time                    `json:"observed_at"`
	BundleFingerprint string                       `json:"bundle_fingerprint"`
	Rules             []fileProfileWatchReportRule `json:"rules"`
}

type fileProfileWatchReportRule struct {
	ID             string                 `json:"id"`
	Protect        bool                   `json:"protect"`
	Enforcement    string                 `json:"enforcement_state"`
	Files          []fileProfileWatchFile `json:"files"`
	FilesCount     int                    `json:"files_count"`
	SensitiveCount int                    `json:"sensitive_count"`
}

type fileProfileWatchFile struct {
	Path          string `json:"path"`
	IsDir         bool   `json:"is_dir"`
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	PodName       string `json:"pod_name,omitempty"`
	PodNamespace  string `json:"pod_namespace,omitempty"`
	SizeBytes     int64  `json:"size_bytes,omitempty"`
}

func (h *FileProfiles) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
	workloads, err := h.observedWorkloads(r.Context(), subj.OrgID, clusterArg, namespace)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	now := time.Now().UTC()
	profiles := make([]fileProfileSummaryDTO, 0, len(workloads))
	for _, wl := range workloads {
		state, err := h.ensureState(r.Context(), subj.OrgID, wl, now)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		profiles = append(profiles, fileProfileSummary(state))
	}
	sort.SliceStable(profiles, func(i, j int) bool {
		if profiles[i].Mode != profiles[j].Mode {
			return modeRank(profiles[i].Mode) < modeRank(profiles[j].Mode)
		}
		if profiles[i].Namespace != profiles[j].Namespace {
			return profiles[i].Namespace < profiles[j].Namespace
		}
		return profiles[i].Name < profiles[j].Name
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"profiles": profiles,
		"summary": map[string]any{
			"total":   len(profiles),
			"learn":   countFileProfiles(profiles, string(fileProfileModeLearn)),
			"monitor": countFileProfiles(profiles, string(fileProfileModeMonitor)),
			"enforce": countFileProfiles(profiles, string(fileProfileModeEnforce)),
		},
	})
}

func (h *FileProfiles) AgentRulesBundle(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	clusterIDRaw := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterIDRaw == "" {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	clusterID, err := uuid.Parse(clusterIDRaw)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid cluster_id")
		return
	}
	var exists bool
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT EXISTS (SELECT 1 FROM clusters WHERE org_id = $1 AND id = $2)`,
		tok.OrgID, clusterID).Scan(&exists); err != nil {
		jsonError(w, http.StatusInternalServerError, "cluster lookup: "+err.Error())
		return
	}
	if !exists {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT r.id,
       r.workload_id,
       COALESCE((
           SELECT array_agg(DISTINCT l.pod_workload_id ORDER BY l.pod_workload_id)
             FROM pod_workload_links l
            WHERE l.org_id = r.org_id
              AND l.cluster_id = r.cluster_id
              AND l.owner_workload_id = r.workload_id
              AND l.pod_workload_id <> ''
       ), '{}'),
       COALESCE(s.namespace, ''),
       COALESCE(s.name, ''),
       COALESCE(s.mode, 'learn'),
       r.filter,
       r.path,
       r.regex,
       r.recursive,
       r.behavior,
       r.applications,
       r.description,
       r.updated_at
  FROM file_profile_rules r
  LEFT JOIN file_profile_states s
    ON s.org_id = r.org_id
   AND s.cluster_id = r.cluster_id
   AND s.workload_id = r.workload_id
 WHERE r.org_id = $1
   AND r.cluster_id = $2
   AND r.enabled
 ORDER BY r.workload_id,
          CASE r.behavior WHEN 'block_access' THEN 0 ELSE 1 END,
          r.recursive DESC,
          r.updated_at DESC,
          r.filter ASC`, tok.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "file profile rules: "+err.Error())
		return
	}
	defer rows.Close()

	bundle := fileProfileRuleBundleDTO{
		ClusterID:   clusterID.String(),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Rules:       []fileProfileRuleBundleRow{},
	}
	for rows.Next() {
		var row fileProfileRuleBundleRow
		var id uuid.UUID
		var updatedAt time.Time
		if err := rows.Scan(&id, &row.WorkloadID, &row.PodWorkloadIDs, &row.Namespace, &row.Name, &row.Mode, &row.Filter,
			&row.Path, &row.Regex, &row.Recursive, &row.Behavior, &row.Applications,
			&row.Description, &updatedAt); err != nil {
			jsonError(w, http.StatusInternalServerError, "file profile rules: "+err.Error())
			return
		}
		row.ID = id.String()
		row.PodWorkloadIDs = nonNilStrings(row.PodWorkloadIDs)
		row.Applications = nonNilStrings(row.Applications)
		row.UpdatedAt = rfc3339Or(updatedAt)
		bundle.Rules = append(bundle.Rules, row)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, "file profile rules: "+err.Error())
		return
	}
	if err := h.attachRuleBundleExceptions(r.Context(), tok.OrgID, clusterID, &bundle); err != nil {
		jsonError(w, http.StatusInternalServerError, "file profile exceptions: "+err.Error())
		return
	}
	// P2-3: merge master-authored (federated) file-profile rules read-only. On a
	// joint these were replicated from its master into fed_runtime_profiles and
	// apply fleet-wide; on a master/standalone the table is empty so this is a no-op.
	fedPayloads, err := fetchFedRuntimeProfilePayloads(r.Context(), h.db.Pool(), tok.OrgID, handler.FedKindFileProfile)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "fed file profiles: "+err.Error())
		return
	}
	bundle.Rules = appendFedFileProfileRows(bundle.Rules, fedPayloads)
	httpx.WriteJSON(w, http.StatusOK, bundle)
}

// fedFileProfileBundleRow builds the agent-bundle row a master ships when it
// federates a file-profile rule. Mode is left empty (the joint's fleet-wide
// template carries no per-cluster lifecycle state); enabled rules are authored,
// disabled ones are tombstoned by the caller so the fed bundle mirrors the
// enabled-only cluster bundle.
func fedFileProfileBundleRow(wl observedWorkload, rule fileProfileRule) fileProfileRuleBundleRow {
	return fileProfileRuleBundleRow{
		ID:           rule.ID.String(),
		WorkloadID:   wl.WorkloadID,
		Namespace:    wl.Namespace,
		Name:         wl.Name,
		Filter:       rule.Filter,
		Path:         rule.Path,
		Regex:        rule.Regex,
		Recursive:    rule.Recursive,
		Behavior:     rule.Behavior,
		Applications: nonNilStrings(rule.Applications),
		Description:  rule.Description,
		UpdatedAt:    rfc3339Or(rule.UpdatedAt),
	}
}

func (h *FileProfiles) attachRuleBundleExceptions(ctx context.Context, orgID, clusterID uuid.UUID, bundle *fileProfileRuleBundleDTO) error {
	if bundle == nil || len(bundle.Rules) == 0 {
		return nil
	}
	ruleIDs := make([]string, 0, len(bundle.Rules))
	workloadIDs := map[string]bool{}
	for _, rule := range bundle.Rules {
		ruleIDs = append(ruleIDs, rule.ID)
		workloadIDs[rule.WorkloadID] = true
	}
	workloads := make([]string, 0, len(workloadIDs))
	for workloadID := range workloadIDs {
		workloads = append(workloads, workloadID)
	}
	sort.Strings(workloads)

	rows, err := h.db.Pool().Query(ctx, `
SELECT id,
       workload_id,
       COALESCE(rule_id::text, ''),
       filter,
       path,
       regex,
       recursive,
       applications,
       description,
       expires_at,
       updated_at
  FROM file_profile_exceptions
 WHERE org_id = $1
   AND cluster_id = $2
   AND enabled
   AND workload_id = ANY($3::text[])
   AND (expires_at IS NULL OR expires_at > NOW())
   AND (rule_id IS NULL OR rule_id::text = ANY($4::text[]))
 ORDER BY updated_at DESC, filter ASC`, orgID, clusterID, workloads, ruleIDs)
	if err != nil {
		return err
	}
	defer rows.Close()

	byRule := map[string][]fileProfileRuleExceptionBundleRow{}
	byWorkload := map[string][]fileProfileRuleExceptionBundleRow{}
	for rows.Next() {
		var id uuid.UUID
		var workloadID, ruleID string
		var row fileProfileRuleExceptionBundleRow
		var expiresAt *time.Time
		var updatedAt time.Time
		if err := rows.Scan(&id, &workloadID, &ruleID, &row.Filter, &row.Path, &row.Regex,
			&row.Recursive, &row.Applications, &row.Description, &expiresAt, &updatedAt); err != nil {
			return err
		}
		row.ID = id.String()
		row.RuleID = ruleID
		row.Applications = nonNilStrings(row.Applications)
		if expiresAt != nil {
			row.ExpiresAt = rfc3339Or(*expiresAt)
		}
		row.UpdatedAt = rfc3339Or(updatedAt)
		if ruleID != "" {
			byRule[ruleID] = append(byRule[ruleID], row)
		} else {
			byWorkload[workloadID] = append(byWorkload[workloadID], row)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range bundle.Rules {
		rule := &bundle.Rules[i]
		exceptions := append([]fileProfileRuleExceptionBundleRow{}, byWorkload[rule.WorkloadID]...)
		exceptions = append(exceptions, byRule[rule.ID]...)
		sort.SliceStable(exceptions, func(i, j int) bool {
			if exceptions[i].RuleID != exceptions[j].RuleID {
				return exceptions[i].RuleID != ""
			}
			return exceptions[i].Filter < exceptions[j].Filter
		})
		rule.Exceptions = exceptions
	}
	return nil
}

func (h *FileProfiles) ReportWatchInventory(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)

	var body fileProfileWatchReportBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(body.ClusterID))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid cluster_id")
		return
	}
	node := strings.TrimSpace(body.Node)
	if node == "" {
		jsonError(w, http.StatusBadRequest, "node is required")
		return
	}
	if body.ObservedAt.IsZero() {
		body.ObservedAt = time.Now().UTC()
	}
	bundleFingerprint := strings.TrimSpace(body.BundleFingerprint)
	if len(body.Rules) > 10000 {
		jsonError(w, http.StatusRequestEntityTooLarge, "too many file profile watch rules")
		return
	}
	var exists bool
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT EXISTS (SELECT 1 FROM clusters WHERE org_id = $1 AND id = $2)`,
		tok.OrgID, clusterID).Scan(&exists); err != nil {
		jsonError(w, http.StatusInternalServerError, "cluster lookup: "+err.Error())
		return
	}
	if !exists {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return
	}

	rulesByID := map[string]fileProfileWatchReportRule{}
	for i := range body.Rules {
		rule := body.Rules[i]
		id := strings.TrimSpace(rule.ID)
		if id == "" {
			continue
		}
		if _, err := uuid.Parse(id); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid rule id")
			return
		}
		if len(rule.Files) > 1000 {
			jsonError(w, http.StatusRequestEntityTooLarge, "too many watched files for rule")
			return
		}
		normalizedFiles := make([]fileProfileWatchFile, 0, len(rule.Files))
		for _, file := range rule.Files {
			file.Path = strings.TrimSpace(file.Path)
			if file.Path == "" || !strings.HasPrefix(file.Path, "/") {
				continue
			}
			file.ContainerID = strings.TrimSpace(file.ContainerID)
			file.ContainerName = strings.TrimSpace(file.ContainerName)
			file.PodName = strings.TrimSpace(file.PodName)
			file.PodNamespace = strings.TrimSpace(file.PodNamespace)
			normalizedFiles = append(normalizedFiles, file)
		}
		rule.Files = normalizedFiles
		rule.FilesCount = len(normalizedFiles)
		rule.SensitiveCount = sensitiveFileProfileWatchCount(normalizedFiles)
		rule.Enforcement = normalizeFileProfileWatchEnforcement(rule.Enforcement)
		rulesByID[id] = rule
	}
	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if len(ruleIDs) == 0 {
		if _, err := tx.Exec(r.Context(), `
DELETE FROM file_profile_watch_inventory
 WHERE org_id = $1
   AND cluster_id = $2
   AND node = $3`, tok.OrgID, clusterID, node); err != nil {
			jsonError(w, http.StatusInternalServerError, "delete stale watches: "+err.Error())
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "accepted": 0})
		return
	}

	if _, err := tx.Exec(r.Context(), `
DELETE FROM file_profile_watch_inventory
 WHERE org_id = $1
   AND cluster_id = $2
   AND node = $3
   AND NOT (rule_id::text = ANY($4::text[]))`, tok.OrgID, clusterID, node, ruleIDs); err != nil {
		jsonError(w, http.StatusInternalServerError, "delete stale watches: "+err.Error())
		return
	}
	var accepted int64
	acceptedRuleIDs := make([]string, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		rule := rulesByID[ruleID]
		filesRaw, err := json.Marshal(rule.Files)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "marshal watched files: "+err.Error())
			return
		}
		tag, err := tx.Exec(r.Context(), `
INSERT INTO file_profile_watch_inventory (
    org_id, cluster_id, node, workload_id, rule_id, filter, path, regex,
    recursive, behavior, applications, profile_mode, desired_protect, protect,
    enforcement_state, files, files_count, sensitive_count, bundle_fingerprint,
    observed_at, updated_at
)
SELECT r.org_id,
       r.cluster_id,
       $3,
       r.workload_id,
       r.id,
       r.filter,
       r.path,
       r.regex,
       r.recursive,
       r.behavior,
       r.applications,
       COALESCE(s.mode, 'learn'),
       (COALESCE(s.mode, 'learn') = 'enforce' AND r.behavior = 'block_access'),
       ($10 AND $11 = 'enforced' AND COALESCE(s.mode, 'learn') = 'enforce' AND r.behavior = 'block_access'),
       CASE
         WHEN COALESCE(s.mode, 'learn') = 'enforce' AND r.behavior = 'block_access' AND $11 <> ''
           THEN $11
         WHEN COALESCE(s.mode, 'learn') = 'enforce' AND r.behavior = 'block_access'
           THEN 'unsupported'
         ELSE 'synced'
       END,
       $6::jsonb,
       $7,
       $8,
       $4,
       $5,
       NOW()
  FROM file_profile_rules r
  LEFT JOIN file_profile_states s
    ON s.org_id = r.org_id
   AND s.cluster_id = r.cluster_id
   AND s.workload_id = r.workload_id
 WHERE r.org_id = $1
   AND r.cluster_id = $2
   AND r.enabled
   AND r.id::text = $9
ON CONFLICT (org_id, cluster_id, node, rule_id) DO UPDATE
   SET workload_id = EXCLUDED.workload_id,
       filter = EXCLUDED.filter,
       path = EXCLUDED.path,
       regex = EXCLUDED.regex,
       recursive = EXCLUDED.recursive,
       behavior = EXCLUDED.behavior,
       applications = EXCLUDED.applications,
       profile_mode = EXCLUDED.profile_mode,
       desired_protect = EXCLUDED.desired_protect,
       protect = EXCLUDED.protect,
       enforcement_state = EXCLUDED.enforcement_state,
       files = EXCLUDED.files,
       files_count = EXCLUDED.files_count,
       sensitive_count = EXCLUDED.sensitive_count,
       bundle_fingerprint = EXCLUDED.bundle_fingerprint,
       observed_at = EXCLUDED.observed_at,
       updated_at = NOW()`,
			tok.OrgID, clusterID, node, bundleFingerprint, body.ObservedAt,
			filesRaw, rule.FilesCount, rule.SensitiveCount, ruleID, rule.Protect, rule.Enforcement)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "upsert watches: "+err.Error())
			return
		}
		if tag.RowsAffected() > 0 {
			accepted += tag.RowsAffected()
			acceptedRuleIDs = append(acceptedRuleIDs, ruleID)
		}
	}
	if len(acceptedRuleIDs) == 0 {
		if _, err := tx.Exec(r.Context(), `
DELETE FROM file_profile_watch_inventory
 WHERE org_id = $1
   AND cluster_id = $2
   AND node = $3`, tok.OrgID, clusterID, node); err != nil {
			jsonError(w, http.StatusInternalServerError, "delete invalid watches: "+err.Error())
			return
		}
	} else if len(acceptedRuleIDs) != len(ruleIDs) {
		if _, err := tx.Exec(r.Context(), `
DELETE FROM file_profile_watch_inventory
 WHERE org_id = $1
   AND cluster_id = $2
   AND node = $3
   AND NOT (rule_id::text = ANY($4::text[]))`, tok.OrgID, clusterID, node, acceptedRuleIDs); err != nil {
			jsonError(w, http.StatusInternalServerError, "delete invalid watches: "+err.Error())
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "accepted": accepted})
}

func (h *FileProfiles) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	workloadID := workloadIDParam(r)
	if workloadID == "" {
		jsonError(w, http.StatusBadRequest, "workload_id required")
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	wl, ok, err := h.findWorkload(r.Context(), subj.OrgID, clusterArg, workloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		jsonError(w, http.StatusNotFound, "workload not found")
		return
	}
	state, err := h.ensureState(r.Context(), subj.OrgID, wl, time.Now().UTC())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, fileProfileDetailDTO{
		fileProfileSummaryDTO: fileProfileSummary(state),
		Files:                 fileProfileFilesDTO(state.Files),
		Transitions:           fileProfileTransitionsDTO(state.Transitions),
		Rules:                 fileProfileRulesDTO(state.Rules),
		Exceptions:            fileProfileExceptionsDTO(state.Exceptions),
		WatchedFiles:          fileProfileWatchesDTO(state.WatchedFiles),
	})
}

func (h *FileProfiles) Export(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	workloadID := workloadIDParam(r)
	if workloadID == "" {
		jsonError(w, http.StatusBadRequest, "workload_id required")
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	wl, found, err := h.findWorkload(r.Context(), subj.OrgID, clusterArg, workloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "workload not found")
		return
	}
	state, err := h.ensureState(r.Context(), subj.OrgID, wl, time.Now().UTC())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, fileProfileExportBundle{
		SchemaVersion: fileProfileBundleSchemaVersion,
		Kind:          "FileProfile",
		WorkloadID:    state.WorkloadID,
		ClusterID:     state.ClusterID,
		Namespace:     state.Namespace,
		Name:          state.Name,
		Mode:          string(state.Mode),
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Rules:         fileProfilePortableRulesDTO(state.Rules),
		Exceptions:    fileProfilePortableExceptionsDTO(state.Exceptions),
	})
}

func (h *FileProfiles) Import(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	workloadID := workloadIDParam(r)
	if workloadID == "" {
		jsonError(w, http.StatusBadRequest, "workload_id required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	req, err := decodeFileProfileImportRequest(r.Body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = strings.TrimSpace(r.URL.Query().Get("reason"))
	}
	if reason == "" {
		jsonError(w, http.StatusBadRequest, "reason required")
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	wl, found, err := h.findWorkload(r.Context(), subj.OrgID, clusterArg, workloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "workload not found")
		return
	}
	now := time.Now().UTC()
	state, err := h.ensureState(r.Context(), subj.OrgID, wl, now)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	targetMode, rules, exceptions, warnings, err := normalizeFileProfileImportRequest(req)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Bundle != nil {
		if req.Bundle.WorkloadID != "" && req.Bundle.WorkloadID != wl.WorkloadID {
			warnings = append(warnings, fmt.Sprintf("bundle workload %q retargeted to %q", req.Bundle.WorkloadID, wl.WorkloadID))
		}
		if req.Bundle.ClusterID != "" && req.Bundle.ClusterID != wl.ClusterID {
			warnings = append(warnings, fmt.Sprintf("bundle cluster %q retargeted to %q", req.Bundle.ClusterID, wl.ClusterID))
		}
	}
	if req.DryRun {
		httpx.WriteJSON(w, http.StatusOK, fileProfileImportResponse{
			DryRun:           true,
			Replace:          req.Replace,
			Imported:         len(rules),
			Mode:             string(targetMode),
			ClusterID:        wl.ClusterID,
			TargetWorkloadID: wl.WorkloadID,
			Rules:            fileProfilePortableRulesDTO(rules),
			Exceptions:       fileProfilePortableExceptionsDTO(exceptions),
			Warnings:         warnings,
		})
		return
	}

	clusterID, _ := uuid.Parse(wl.ClusterID)
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if state.Mode != targetMode {
		if _, err := tx.Exec(r.Context(), `
UPDATE file_profile_states
   SET mode = $1,
       learn_started_at = CASE WHEN $1 = 'learn' THEN $2 ELSE learn_started_at END,
       monitor_started_at = CASE WHEN $1 = 'monitor' AND monitor_started_at IS NULL THEN $2 ELSE monitor_started_at END,
       enforce_started_at = CASE WHEN $1 = 'enforce' THEN $2 ELSE enforce_started_at END,
       updated_by = $3,
       updated_at = $2
 WHERE org_id = $4
   AND cluster_id = $5
   AND workload_id = $6`,
			string(targetMode), now, subj.UserID, subj.OrgID, clusterID, wl.WorkloadID); err != nil {
			jsonError(w, http.StatusInternalServerError, "set mode: "+err.Error())
			return
		}
		if _, err := tx.Exec(r.Context(), `
INSERT INTO file_profile_transitions (
    org_id, cluster_id, workload_id, from_mode, to_mode, reason, actor_id, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			subj.OrgID, clusterID, wl.WorkloadID, string(state.Mode), string(targetMode), reason, subj.UserID, now); err != nil {
			jsonError(w, http.StatusInternalServerError, "record mode transition: "+err.Error())
			return
		}
	}

	filters := make([]string, 0, len(rules))
	ruleIDRemap := map[uuid.UUID]uuid.UUID{}
	for _, rule := range rules {
		filters = append(filters, rule.Filter)
		var storedRuleID uuid.UUID
		if err := tx.QueryRow(r.Context(), `
INSERT INTO file_profile_rules (
    org_id, cluster_id, workload_id, filter, path, regex, recursive, behavior,
    applications, enabled, description, created_by, updated_by, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, $13, $13)
ON CONFLICT (org_id, cluster_id, workload_id, filter) DO UPDATE
   SET path = EXCLUDED.path,
       regex = EXCLUDED.regex,
       recursive = EXCLUDED.recursive,
       behavior = EXCLUDED.behavior,
       applications = EXCLUDED.applications,
       enabled = EXCLUDED.enabled,
       description = EXCLUDED.description,
       updated_by = EXCLUDED.updated_by,
       updated_at = EXCLUDED.updated_at
RETURNING id`,
			subj.OrgID, clusterID, wl.WorkloadID, rule.Filter, rule.Path, rule.Regex, rule.Recursive,
			rule.Behavior, rule.Applications, rule.Enabled, rule.Description, subj.UserID, now).Scan(&storedRuleID); err != nil {
			jsonError(w, http.StatusInternalServerError, "upsert file profile rule: "+err.Error())
			return
		}
		if rule.ID != uuid.Nil && storedRuleID != uuid.Nil {
			ruleIDRemap[rule.ID] = storedRuleID
		}
	}
	validRuleIDs, err := h.fileProfileRuleIDSet(r.Context(), subj.OrgID, clusterID, wl.WorkloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "file profile rule ids: "+err.Error())
		return
	}
	if req.Replace {
		if _, err := tx.Exec(r.Context(), `
DELETE FROM file_profile_exceptions
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3`, subj.OrgID, clusterID, wl.WorkloadID); err != nil {
			jsonError(w, http.StatusInternalServerError, "replace file profile exceptions: "+err.Error())
			return
		}
	}
	for _, exception := range exceptions {
		ruleIDArg := any(nil)
		if exception.RuleID != uuid.Nil {
			if remapped, ok := ruleIDRemap[exception.RuleID]; ok {
				ruleIDArg = remapped
			} else if !req.Replace && validRuleIDs[exception.RuleID] {
				ruleIDArg = exception.RuleID
			} else {
				exception.RuleID = uuid.Nil
			}
		}
		expiresAtArg := any(nil)
		if !exception.ExpiresAt.IsZero() {
			expiresAtArg = exception.ExpiresAt
		}
		if _, err := tx.Exec(r.Context(), `
DELETE FROM file_profile_exceptions
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
   AND filter = $4
   AND recursive = $5
   AND applications = $6
   AND rule_id IS NOT DISTINCT FROM $7::uuid`, subj.OrgID, clusterID, wl.WorkloadID, exception.Filter,
			exception.Recursive, exception.Applications, ruleIDArg); err != nil {
			jsonError(w, http.StatusInternalServerError, "dedupe file profile exception: "+err.Error())
			return
		}
		if _, err := tx.Exec(r.Context(), `
INSERT INTO file_profile_exceptions (
    org_id, cluster_id, workload_id, rule_id, filter, path, regex, recursive,
    applications, enabled, description, expires_at, created_by, updated_by, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13, $14, $14)`,
			subj.OrgID, clusterID, wl.WorkloadID, ruleIDArg, exception.Filter, exception.Path, exception.Regex,
			exception.Recursive, exception.Applications, exception.Enabled, exception.Description,
			expiresAtArg, subj.UserID, now); err != nil {
			jsonError(w, http.StatusInternalServerError, "insert file profile exception: "+err.Error())
			return
		}
	}

	var deleted int64
	if req.Replace {
		var tag interface {
			RowsAffected() int64
		}
		if len(filters) == 0 {
			tag, err = tx.Exec(r.Context(), `
DELETE FROM file_profile_rules
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3`, subj.OrgID, clusterID, wl.WorkloadID)
		} else {
			tag, err = tx.Exec(r.Context(), `
DELETE FROM file_profile_rules
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
   AND NOT (filter = ANY($4::text[]))`, subj.OrgID, clusterID, wl.WorkloadID, filters)
		}
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "replace file profile rules: "+err.Error())
			return
		}
		deleted = tag.RowsAffected()
	}

	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	updatedRules, err := h.rulesFor(r.Context(), subj.OrgID, clusterID, wl.WorkloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "file profile rules: "+err.Error())
		return
	}
	updatedExceptions, err := h.exceptionsFor(r.Context(), subj.OrgID, clusterID, wl.WorkloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "file profile exceptions: "+err.Error())
		return
	}
	h.auditImport(r, subj, wl.WorkloadID, state.Mode, targetMode, len(rules), deleted, req.Replace, reason)
	httpx.WriteJSON(w, http.StatusOK, fileProfileImportResponse{
		DryRun:           false,
		Replace:          req.Replace,
		Imported:         len(rules),
		Deleted:          deleted,
		Mode:             string(targetMode),
		ClusterID:        wl.ClusterID,
		TargetWorkloadID: wl.WorkloadID,
		Rules:            fileProfilePortableRulesDTO(updatedRules),
		Exceptions:       fileProfilePortableExceptionsDTO(updatedExceptions),
		Warnings:         warnings,
	})
}

type fileProfileModeBody struct {
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
}

func (h *FileProfiles) SetMode(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	workloadID := workloadIDParam(r)
	if workloadID == "" {
		jsonError(w, http.StatusBadRequest, "workload_id required")
		return
	}
	var body fileProfileModeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	target, err := normalizeFileProfileMode(body.Mode)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		jsonError(w, http.StatusBadRequest, "reason required")
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	wl, ok, err := h.findWorkload(r.Context(), subj.OrgID, clusterArg, workloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		jsonError(w, http.StatusNotFound, "workload not found")
		return
	}
	now := time.Now().UTC()
	state, err := h.ensureState(r.Context(), subj.OrgID, wl, now)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	from := state.Mode
	if !validFileProfileTransition(from, target) {
		jsonError(w, http.StatusConflict, fmt.Sprintf("transition %s → %s not allowed", from, target))
		return
	}
	if err := h.persistModeTransition(r.Context(), subj, wl, from, target, reason, now); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	applyFileProfileTransition(state, subj.UserID.String(), from, target, reason, now)
	h.audit(r, subj, target, from, wl.WorkloadID, reason)
	httpx.WriteJSON(w, http.StatusOK, fileProfileSummary(state))
}

type fileProfileRuleBody struct {
	Filter       string   `json:"filter"`
	Recursive    *bool    `json:"recursive"`
	Behavior     string   `json:"behavior"`
	Applications []string `json:"applications"`
	Enabled      *bool    `json:"enabled"`
	Description  string   `json:"description"`
	Reason       string   `json:"reason"`
}

type fileProfileExceptionBody struct {
	RuleID       string   `json:"rule_id"`
	Filter       string   `json:"filter"`
	Recursive    *bool    `json:"recursive"`
	Applications []string `json:"applications"`
	Enabled      *bool    `json:"enabled"`
	Description  string   `json:"description"`
	ExpiresAt    string   `json:"expires_at"`
	Reason       string   `json:"reason"`
}

func (h *FileProfiles) CreateRule(w http.ResponseWriter, r *http.Request) {
	subj, wl, body, ok := h.ruleRequest(w, r)
	if !ok {
		return
	}
	rule, err := normalizeFileProfileRuleBody(body, nil)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	clusterID, _ := uuid.Parse(wl.ClusterID)
	now := time.Now().UTC()
	var created fileProfileRule
	err = h.db.Pool().QueryRow(r.Context(), `
INSERT INTO file_profile_rules (
    org_id, cluster_id, workload_id, filter, path, regex, recursive, behavior,
    applications, enabled, description, created_by, updated_by, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, $13, $13)
ON CONFLICT (org_id, cluster_id, workload_id, filter) DO UPDATE
   SET path = EXCLUDED.path,
       regex = EXCLUDED.regex,
       recursive = EXCLUDED.recursive,
       behavior = EXCLUDED.behavior,
       applications = EXCLUDED.applications,
       enabled = EXCLUDED.enabled,
       description = EXCLUDED.description,
       updated_by = EXCLUDED.updated_by,
       updated_at = EXCLUDED.updated_at
RETURNING id, filter, path, regex, recursive, behavior, applications, enabled,
          description, COALESCE(created_by::text, ''), COALESCE(updated_by::text, ''),
          created_at, updated_at`,
		subj.OrgID, clusterID, wl.WorkloadID, rule.Filter, rule.Path, rule.Regex, rule.Recursive,
		rule.Behavior, rule.Applications, rule.Enabled, rule.Description, subj.UserID, now).
		Scan(&created.ID, &created.Filter, &created.Path, &created.Regex, &created.Recursive, &created.Behavior,
			&created.Applications, &created.Enabled, &created.Description, &created.CreatedBy,
			&created.UpdatedBy, &created.CreatedAt, &created.UpdatedAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditRule(r, subj, "file_profile.rule.upsert", wl.WorkloadID, nil, created, body.Reason)
	recordFedFileProfileRule(r.Context(), h.db.Pool(), subj.OrgID, created.ID.String(),
		fedFileProfileBundleRow(wl, created), !created.Enabled)
	httpx.WriteJSON(w, http.StatusCreated, fileProfileRuleToDTO(created))
}

func (h *FileProfiles) UpdateRule(w http.ResponseWriter, r *http.Request) {
	subj, wl, body, ok := h.ruleRequest(w, r)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "rule_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid rule_id")
		return
	}
	clusterID, _ := uuid.Parse(wl.ClusterID)
	before, ok, err := h.findRule(r.Context(), subj.OrgID, clusterID, wl.WorkloadID, ruleID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		jsonError(w, http.StatusNotFound, "rule not found")
		return
	}
	next, err := normalizeFileProfileRuleBody(body, &before)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	var updated fileProfileRule
	err = h.db.Pool().QueryRow(r.Context(), `
UPDATE file_profile_rules
   SET filter = $1,
       path = $2,
       regex = $3,
       recursive = $4,
       behavior = $5,
       applications = $6,
       enabled = $7,
       description = $8,
       updated_by = $9,
       updated_at = $10
 WHERE org_id = $11
   AND cluster_id = $12
   AND workload_id = $13
   AND id = $14
RETURNING id, filter, path, regex, recursive, behavior, applications, enabled,
          description, COALESCE(created_by::text, ''), COALESCE(updated_by::text, ''),
          created_at, updated_at`,
		next.Filter, next.Path, next.Regex, next.Recursive, next.Behavior, next.Applications,
		next.Enabled, next.Description, subj.UserID, now, subj.OrgID, clusterID, wl.WorkloadID, ruleID).
		Scan(&updated.ID, &updated.Filter, &updated.Path, &updated.Regex, &updated.Recursive, &updated.Behavior,
			&updated.Applications, &updated.Enabled, &updated.Description, &updated.CreatedBy,
			&updated.UpdatedBy, &updated.CreatedAt, &updated.UpdatedAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditRule(r, subj, "file_profile.rule.update", wl.WorkloadID, &before, updated, body.Reason)
	recordFedFileProfileRule(r.Context(), h.db.Pool(), subj.OrgID, updated.ID.String(),
		fedFileProfileBundleRow(wl, updated), !updated.Enabled)
	httpx.WriteJSON(w, http.StatusOK, fileProfileRuleToDTO(updated))
}

func (h *FileProfiles) DeleteRule(w http.ResponseWriter, r *http.Request) {
	subj, wl, body, ok := h.ruleRequest(w, r)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "rule_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid rule_id")
		return
	}
	clusterID, _ := uuid.Parse(wl.ClusterID)
	before, ok, err := h.findRule(r.Context(), subj.OrgID, clusterID, wl.WorkloadID, ruleID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		jsonError(w, http.StatusNotFound, "rule not found")
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(), `
DELETE FROM file_profile_rules
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
   AND id = $4`, subj.OrgID, clusterID, wl.WorkloadID, ruleID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "rule not found")
		return
	}
	h.auditRule(r, subj, "file_profile.rule.delete", wl.WorkloadID, &before, fileProfileRule{}, body.Reason)
	recordFedFileProfileRule(r.Context(), h.db.Pool(), subj.OrgID, ruleID.String(),
		fileProfileRuleBundleRow{}, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": ruleID.String()})
}

func (h *FileProfiles) CreateException(w http.ResponseWriter, r *http.Request) {
	subj, wl, body, ok := h.exceptionRequest(w, r)
	if !ok {
		return
	}
	exception, err := h.normalizeFileProfileExceptionBody(r.Context(), subj.OrgID, wl, body, nil)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	clusterID, _ := uuid.Parse(wl.ClusterID)
	now := time.Now().UTC()
	var created fileProfileException
	var ruleIDRaw string
	var expiresAt *time.Time
	err = h.db.Pool().QueryRow(r.Context(), `
INSERT INTO file_profile_exceptions (
    org_id, cluster_id, workload_id, rule_id, filter, path, regex, recursive,
    applications, enabled, description, expires_at, created_by, updated_by, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13, $14, $14)
RETURNING id, COALESCE(rule_id::text, ''), filter, path, regex, recursive,
          applications, enabled, description, expires_at,
          COALESCE(created_by::text, ''), COALESCE(updated_by::text, ''),
          created_at, updated_at`,
		subj.OrgID, clusterID, wl.WorkloadID, nullableFileProfileUUID(exception.RuleID), exception.Filter,
		exception.Path, exception.Regex, exception.Recursive, exception.Applications,
		exception.Enabled, exception.Description, nullableTime(exception.ExpiresAt), subj.UserID, now).
		Scan(&created.ID, &ruleIDRaw, &created.Filter, &created.Path, &created.Regex,
			&created.Recursive, &created.Applications, &created.Enabled, &created.Description,
			&expiresAt, &created.CreatedBy, &created.UpdatedBy, &created.CreatedAt, &created.UpdatedAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	created.RuleID = parseFileProfileOptionalUUID(ruleIDRaw)
	if expiresAt != nil {
		created.ExpiresAt = *expiresAt
	}
	h.auditException(r, subj, "file_profile.exception.create", wl.WorkloadID, nil, created, body.Reason)
	httpx.WriteJSON(w, http.StatusCreated, fileProfileExceptionToDTO(created))
}

func (h *FileProfiles) UpdateException(w http.ResponseWriter, r *http.Request) {
	subj, wl, body, ok := h.exceptionRequest(w, r)
	if !ok {
		return
	}
	exceptionID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "exception_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid exception_id")
		return
	}
	clusterID, _ := uuid.Parse(wl.ClusterID)
	before, found, err := h.findException(r.Context(), subj.OrgID, clusterID, wl.WorkloadID, exceptionID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "exception not found")
		return
	}
	next, err := h.normalizeFileProfileExceptionBody(r.Context(), subj.OrgID, wl, body, &before)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	var updated fileProfileException
	var ruleIDRaw string
	var expiresAt *time.Time
	err = h.db.Pool().QueryRow(r.Context(), `
UPDATE file_profile_exceptions
   SET rule_id = $1,
       filter = $2,
       path = $3,
       regex = $4,
       recursive = $5,
       applications = $6,
       enabled = $7,
       description = $8,
       expires_at = $9,
       updated_by = $10,
       updated_at = $11
 WHERE org_id = $12
   AND cluster_id = $13
   AND workload_id = $14
   AND id = $15
RETURNING id, COALESCE(rule_id::text, ''), filter, path, regex, recursive,
          applications, enabled, description, expires_at,
          COALESCE(created_by::text, ''), COALESCE(updated_by::text, ''),
          created_at, updated_at`,
		nullableFileProfileUUID(next.RuleID), next.Filter, next.Path, next.Regex, next.Recursive,
		next.Applications, next.Enabled, next.Description, nullableTime(next.ExpiresAt),
		subj.UserID, now, subj.OrgID, clusterID, wl.WorkloadID, exceptionID).
		Scan(&updated.ID, &ruleIDRaw, &updated.Filter, &updated.Path, &updated.Regex,
			&updated.Recursive, &updated.Applications, &updated.Enabled, &updated.Description,
			&expiresAt, &updated.CreatedBy, &updated.UpdatedBy, &updated.CreatedAt, &updated.UpdatedAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated.RuleID = parseFileProfileOptionalUUID(ruleIDRaw)
	if expiresAt != nil {
		updated.ExpiresAt = *expiresAt
	}
	h.auditException(r, subj, "file_profile.exception.update", wl.WorkloadID, &before, updated, body.Reason)
	httpx.WriteJSON(w, http.StatusOK, fileProfileExceptionToDTO(updated))
}

func (h *FileProfiles) DeleteException(w http.ResponseWriter, r *http.Request) {
	subj, wl, body, ok := h.exceptionRequest(w, r)
	if !ok {
		return
	}
	exceptionID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "exception_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid exception_id")
		return
	}
	clusterID, _ := uuid.Parse(wl.ClusterID)
	before, found, err := h.findException(r.Context(), subj.OrgID, clusterID, wl.WorkloadID, exceptionID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "exception not found")
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(), `
DELETE FROM file_profile_exceptions
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
   AND id = $4`, subj.OrgID, clusterID, wl.WorkloadID, exceptionID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "exception not found")
		return
	}
	h.auditException(r, subj, "file_profile.exception.delete", wl.WorkloadID, &before, fileProfileException{}, body.Reason)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": exceptionID.String()})
}

func (h *FileProfiles) observedWorkloads(ctx context.Context, orgID uuid.UUID, clusterArg any, namespace string) ([]observedWorkload, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT COALESCE(cluster_id::text, ''), namespace, name, COALESCE(labels,'{}'::jsonb)
  FROM deployments
 WHERE org_id = $1
   AND cluster_id IS NOT NULL
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND ($3::text = '' OR namespace = $3)
 ORDER BY namespace, name`, orgID, clusterArg, namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []observedWorkload{}
	for rows.Next() {
		var clusterID, ns, name string
		var labelsRaw []byte
		if err := rows.Scan(&clusterID, &ns, &name, &labelsRaw); err != nil {
			return nil, err
		}
		var labels map[string]string
		if len(labelsRaw) > 0 {
			_ = json.Unmarshal(labelsRaw, &labels)
		}
		out = append(out, observedWorkload{
			WorkloadID: deploymentWorkloadID(ns, name),
			ClusterID:  clusterID,
			Namespace:  ns,
			Name:       name,
			Labels:     labels,
		})
	}
	return out, rows.Err()
}

func (h *FileProfiles) findWorkload(ctx context.Context, orgID uuid.UUID, clusterArg any, workloadID string) (observedWorkload, bool, error) {
	all, err := h.observedWorkloads(ctx, orgID, clusterArg, "")
	if err != nil {
		return observedWorkload{}, false, err
	}
	for _, wl := range all {
		if wl.WorkloadID == workloadID {
			return wl, true, nil
		}
	}
	return observedWorkload{}, false, nil
}

func (h *FileProfiles) ensureState(ctx context.Context, orgID uuid.UUID, wl observedWorkload, now time.Time) (*fileProfileState, error) {
	clusterID, err := uuid.Parse(wl.ClusterID)
	if err != nil {
		return nil, fmt.Errorf("invalid workload cluster id")
	}
	var state fileProfileState
	var monitorStartedAt, enforceStartedAt *time.Time
	err = h.db.Pool().QueryRow(ctx, `
INSERT INTO file_profile_states (
    org_id, cluster_id, workload_id, namespace, name, mode, learn_started_at
) VALUES ($1, $2, $3, $4, $5, 'learn', $6)
ON CONFLICT (org_id, cluster_id, workload_id) DO UPDATE
   SET namespace = EXCLUDED.namespace,
       name = EXCLUDED.name
RETURNING workload_id, cluster_id::text, namespace, name, mode,
          learn_started_at, monitor_started_at, enforce_started_at`,
		orgID, clusterID, wl.WorkloadID, wl.Namespace, wl.Name, now).
		Scan(&state.WorkloadID, &state.ClusterID, &state.Namespace, &state.Name, &state.Mode,
			&state.LearnStartedAt, &monitorStartedAt, &enforceStartedAt)
	if err != nil {
		return nil, err
	}
	if monitorStartedAt != nil {
		state.MonitorStartedAt = *monitorStartedAt
	}
	if enforceStartedAt != nil {
		state.EnforceStartedAt = *enforceStartedAt
	}
	files, sensitive, alerts, blocks, lastNew, err := h.fileObservations(ctx, orgID, clusterID, wl.WorkloadID)
	if err != nil {
		return nil, err
	}
	state.Files = files
	state.SensitivePathCount = sensitive
	state.Alerts24h = alerts
	state.Blocks24h = blocks
	state.LastNewPathAt = lastNew
	transitions, err := h.fileProfileTransitions(ctx, orgID, clusterID, wl.WorkloadID)
	if err != nil {
		return nil, err
	}
	state.Transitions = transitions
	rules, err := h.rulesFor(ctx, orgID, clusterID, wl.WorkloadID)
	if err != nil {
		return nil, err
	}
	state.Rules = rules
	exceptions, err := h.exceptionsFor(ctx, orgID, clusterID, wl.WorkloadID)
	if err != nil {
		return nil, err
	}
	state.Exceptions = exceptions
	watches, err := h.watchesFor(ctx, orgID, clusterID, wl.WorkloadID)
	if err != nil {
		return nil, err
	}
	state.WatchedFiles = watches
	return &state, nil
}

func (h *FileProfiles) fileObservations(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string) ([]fileObservation, int, int, int, time.Time, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT severity,
       verdict,
       payload,
       at
  FROM events
 WHERE org_id = $1
   AND cluster_id = $2
   AND kind = 'file_open'
   AND (
        workload_id = $3
     OR workload_id IN (
        SELECT pod_workload_id
          FROM pod_workload_links
         WHERE org_id = $1
           AND cluster_id = $2
           AND owner_workload_id = $3
     )
   )
 ORDER BY at DESC
 LIMIT 1000`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, 0, 0, 0, time.Time{}, err
	}
	defer rows.Close()

	type filePayload struct {
		PID   uint32 `json:"pid"`
		Comm  string `json:"comm"`
		Path  string `json:"path"`
		Flags uint32 `json:"flags"`
		Mode  uint32 `json:"mode"`
	}
	files := map[string]*fileObservation{}
	var alerts24h, blocks24h int
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	for rows.Next() {
		var severity, verdict string
		var payloadRaw []byte
		var at time.Time
		if err := rows.Scan(&severity, &verdict, &payloadRaw, &at); err != nil {
			return nil, 0, 0, 0, time.Time{}, err
		}
		if at.After(cutoff) && (severity == "high" || severity == "critical" || verdict == "alert") {
			alerts24h++
		}
		if at.After(cutoff) && (verdict == "block" || verdict == "deny") {
			blocks24h++
		}
		var payload filePayload
		_ = json.Unmarshal(payloadRaw, &payload)
		path := strings.TrimSpace(payload.Path)
		if path == "" {
			continue
		}
		comm := strings.TrimSpace(payload.Comm)
		key := path + "\x00" + comm
		item, ok := files[key]
		if !ok {
			item = &fileObservation{
				Path:      path,
				Operation: "open",
				Comm:      comm,
				Flags:     payload.Flags,
				Mode:      payload.Mode,
				Sensitive: isSensitivePath(path),
				FirstSeen: at,
				LastSeen:  at,
			}
			files[key] = item
		}
		item.ObservedCount++
		if at.Before(item.FirstSeen) {
			item.FirstSeen = at
		}
		if at.After(item.LastSeen) {
			item.LastSeen = at
			item.Flags = payload.Flags
			item.Mode = payload.Mode
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, 0, time.Time{}, err
	}
	out := make([]fileObservation, 0, len(files))
	var sensitiveCount int
	var lastNewPathAt time.Time
	for _, file := range files {
		out = append(out, *file)
		if file.Sensitive {
			sensitiveCount++
		}
		if lastNewPathAt.IsZero() || file.FirstSeen.After(lastNewPathAt) {
			lastNewPathAt = file.FirstSeen.UTC()
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ObservedCount != out[j].ObservedCount {
			return out[i].ObservedCount > out[j].ObservedCount
		}
		if out[i].Sensitive != out[j].Sensitive {
			return out[i].Sensitive
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Comm < out[j].Comm
	})
	return out, sensitiveCount, alerts24h, blocks24h, lastNewPathAt, nil
}

func (h *FileProfiles) fileProfileTransitions(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string) ([]fileProfileTransition, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT created_at,
       COALESCE(actor_id::text, ''),
       from_mode,
       to_mode,
       reason
  FROM file_profile_transitions
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
 ORDER BY created_at ASC`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fileProfileTransition{}
	for rows.Next() {
		var item fileProfileTransition
		if err := rows.Scan(&item.At, &item.Actor, &item.From, &item.To, &item.Reason); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *FileProfiles) rulesFor(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string) ([]fileProfileRule, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id,
       filter,
       path,
       regex,
       recursive,
       behavior,
       applications,
       enabled,
       description,
       COALESCE(created_by::text, ''),
       COALESCE(updated_by::text, ''),
       created_at,
       updated_at
  FROM file_profile_rules
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
 ORDER BY enabled DESC, updated_at DESC, filter ASC`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fileProfileRule{}
	for rows.Next() {
		var rule fileProfileRule
		if err := rows.Scan(&rule.ID, &rule.Filter, &rule.Path, &rule.Regex, &rule.Recursive, &rule.Behavior,
			&rule.Applications, &rule.Enabled, &rule.Description, &rule.CreatedBy, &rule.UpdatedBy,
			&rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

func (h *FileProfiles) fileProfileRuleIDSet(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string) (map[uuid.UUID]bool, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id
  FROM file_profile_rules
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (h *FileProfiles) findRule(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string, ruleID uuid.UUID) (fileProfileRule, bool, error) {
	var rule fileProfileRule
	err := h.db.Pool().QueryRow(ctx, `
SELECT id,
       filter,
       path,
       regex,
       recursive,
       behavior,
       applications,
       enabled,
       description,
       COALESCE(created_by::text, ''),
       COALESCE(updated_by::text, ''),
       created_at,
       updated_at
  FROM file_profile_rules
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
   AND id = $4`, orgID, clusterID, workloadID, ruleID).
		Scan(&rule.ID, &rule.Filter, &rule.Path, &rule.Regex, &rule.Recursive, &rule.Behavior,
			&rule.Applications, &rule.Enabled, &rule.Description, &rule.CreatedBy, &rule.UpdatedBy,
			&rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return fileProfileRule{}, false, nil
		}
		return fileProfileRule{}, false, err
	}
	return rule, true, nil
}

func (h *FileProfiles) exceptionsFor(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string) ([]fileProfileException, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id,
       COALESCE(rule_id::text, ''),
       filter,
       path,
       regex,
       recursive,
       applications,
       enabled,
       description,
       expires_at,
       COALESCE(created_by::text, ''),
       COALESCE(updated_by::text, ''),
       created_at,
       updated_at
  FROM file_profile_exceptions
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
 ORDER BY enabled DESC, updated_at DESC, filter ASC`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fileProfileException{}
	for rows.Next() {
		var item fileProfileException
		var ruleID string
		var expiresAt *time.Time
		if err := rows.Scan(&item.ID, &ruleID, &item.Filter, &item.Path, &item.Regex, &item.Recursive,
			&item.Applications, &item.Enabled, &item.Description, &expiresAt,
			&item.CreatedBy, &item.UpdatedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if ruleID != "" {
			if parsed, err := uuid.Parse(ruleID); err == nil {
				item.RuleID = parsed
			}
		}
		if expiresAt != nil {
			item.ExpiresAt = *expiresAt
		}
		item.Applications = nonNilStrings(item.Applications)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *FileProfiles) findException(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string, exceptionID uuid.UUID) (fileProfileException, bool, error) {
	var item fileProfileException
	var ruleID string
	var expiresAt *time.Time
	err := h.db.Pool().QueryRow(ctx, `
SELECT id,
       COALESCE(rule_id::text, ''),
       filter,
       path,
       regex,
       recursive,
       applications,
       enabled,
       description,
       expires_at,
       COALESCE(created_by::text, ''),
       COALESCE(updated_by::text, ''),
       created_at,
       updated_at
  FROM file_profile_exceptions
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
   AND id = $4`, orgID, clusterID, workloadID, exceptionID).
		Scan(&item.ID, &ruleID, &item.Filter, &item.Path, &item.Regex, &item.Recursive,
			&item.Applications, &item.Enabled, &item.Description, &expiresAt,
			&item.CreatedBy, &item.UpdatedBy, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return fileProfileException{}, false, nil
		}
		return fileProfileException{}, false, err
	}
	if ruleID != "" {
		if parsed, err := uuid.Parse(ruleID); err == nil {
			item.RuleID = parsed
		}
	}
	if expiresAt != nil {
		item.ExpiresAt = *expiresAt
	}
	item.Applications = nonNilStrings(item.Applications)
	return item, true, nil
}

func (h *FileProfiles) watchesFor(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string) ([]fileProfileWatch, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT node,
       rule_id,
       filter,
       path,
       regex,
       recursive,
       behavior,
       applications,
       profile_mode,
       desired_protect,
       protect,
       enforcement_state,
       files,
       files_count,
       sensitive_count,
       bundle_fingerprint,
       observed_at,
       updated_at
  FROM file_profile_watch_inventory
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
 ORDER BY observed_at DESC, node ASC, filter ASC`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fileProfileWatch{}
	for rows.Next() {
		var watch fileProfileWatch
		if err := rows.Scan(&watch.Node, &watch.RuleID, &watch.Filter, &watch.Path, &watch.Regex,
			&watch.Recursive, &watch.Behavior, &watch.Applications, &watch.ProfileMode,
			&watch.DesiredProtect, &watch.Protect, &watch.EnforcementState,
			&watch.Files, &watch.FilesCount, &watch.SensitiveCount,
			&watch.BundleFingerprint, &watch.ObservedAt, &watch.UpdatedAt); err != nil {
			return nil, err
		}
		watch.Applications = nonNilStrings(watch.Applications)
		out = append(out, watch)
	}
	return out, rows.Err()
}

func (h *FileProfiles) persistModeTransition(ctx context.Context, subj authctx.Subject, wl observedWorkload, from, to fileProfileMode, reason string, now time.Time) error {
	clusterID, err := uuid.Parse(wl.ClusterID)
	if err != nil {
		return err
	}
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
UPDATE file_profile_states
   SET mode = $1,
       learn_started_at = CASE WHEN $1 = 'learn' THEN $2 ELSE learn_started_at END,
       monitor_started_at = CASE WHEN $1 = 'monitor' AND monitor_started_at IS NULL THEN $2 ELSE monitor_started_at END,
       enforce_started_at = CASE WHEN $1 = 'enforce' THEN $2 ELSE enforce_started_at END,
       updated_by = $3,
       updated_at = $2
 WHERE org_id = $4
   AND cluster_id = $5
   AND workload_id = $6`,
		string(to), now, subj.UserID, subj.OrgID, clusterID, wl.WorkloadID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO file_profile_transitions (
    org_id, cluster_id, workload_id, from_mode, to_mode, reason, actor_id, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		subj.OrgID, clusterID, wl.WorkloadID, string(from), string(to), reason, subj.UserID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func fileProfileSummary(s *fileProfileState) fileProfileSummaryDTO {
	top := make([]string, 0, 5)
	seen := map[string]bool{}
	for _, file := range s.Files {
		if len(top) >= 5 {
			break
		}
		if seen[file.Path] {
			continue
		}
		seen[file.Path] = true
		top = append(top, file.Path)
	}
	return fileProfileSummaryDTO{
		WorkloadID:         s.WorkloadID,
		ClusterID:          s.ClusterID,
		Namespace:          s.Namespace,
		Name:               s.Name,
		Mode:               string(s.Mode),
		LearnedPathsCount:  len(s.Files),
		SensitivePathCount: s.SensitivePathCount,
		MonitoredAlerts24h: s.Alerts24h,
		EnforcedBlocks24h:  s.Blocks24h,
		LearnStartedAt:     rfc3339Or(s.LearnStartedAt),
		MonitorStartedAt:   rfc3339Or(s.MonitorStartedAt),
		EnforceStartedAt:   rfc3339Or(s.EnforceStartedAt),
		LastNewPathAt:      rfc3339Or(s.LastNewPathAt),
		TopPaths:           top,
		RuleCount:          len(s.Rules),
		WatchedFileCount:   len(s.WatchedFiles),
	}
}

func fileProfileFilesDTO(in []fileObservation) []fileProfileFileDTO {
	out := make([]fileProfileFileDTO, 0, len(in))
	for _, file := range in {
		out = append(out, fileProfileFileDTO{
			Path:          file.Path,
			Operation:     file.Operation,
			Comm:          file.Comm,
			Flags:         file.Flags,
			Mode:          file.Mode,
			ObservedCount: file.ObservedCount,
			Sensitive:     file.Sensitive,
			FirstSeen:     rfc3339Or(file.FirstSeen),
			LastSeen:      rfc3339Or(file.LastSeen),
		})
	}
	return out
}

func fileProfileTransitionsDTO(in []fileProfileTransition) []fileProfileTransitionDTO {
	out := make([]fileProfileTransitionDTO, 0, len(in))
	for _, transition := range in {
		out = append(out, fileProfileTransitionDTO{
			At:     rfc3339Or(transition.At),
			Actor:  transition.Actor,
			From:   string(transition.From),
			To:     string(transition.To),
			Reason: transition.Reason,
		})
	}
	return out
}

func fileProfileRulesDTO(in []fileProfileRule) []fileProfileRuleDTO {
	out := make([]fileProfileRuleDTO, 0, len(in))
	for _, rule := range in {
		out = append(out, fileProfileRuleToDTO(rule))
	}
	return out
}

func fileProfileExceptionsDTO(in []fileProfileException) []fileProfileExceptionDTO {
	out := make([]fileProfileExceptionDTO, 0, len(in))
	for _, exception := range in {
		out = append(out, fileProfileExceptionToDTO(exception))
	}
	return out
}

func fileProfileRuleToDTO(rule fileProfileRule) fileProfileRuleDTO {
	return fileProfileRuleDTO{
		ID:           rule.ID.String(),
		Filter:       rule.Filter,
		Path:         rule.Path,
		Regex:        rule.Regex,
		Recursive:    rule.Recursive,
		Behavior:     rule.Behavior,
		Applications: nonNilStrings(rule.Applications),
		Enabled:      rule.Enabled,
		Description:  rule.Description,
		CreatedBy:    rule.CreatedBy,
		UpdatedBy:    rule.UpdatedBy,
		CreatedAt:    rfc3339Or(rule.CreatedAt),
		UpdatedAt:    rfc3339Or(rule.UpdatedAt),
	}
}

func fileProfileExceptionToDTO(exception fileProfileException) fileProfileExceptionDTO {
	ruleID := ""
	if exception.RuleID != uuid.Nil {
		ruleID = exception.RuleID.String()
	}
	return fileProfileExceptionDTO{
		ID:           exception.ID.String(),
		RuleID:       ruleID,
		Filter:       exception.Filter,
		Path:         exception.Path,
		Regex:        exception.Regex,
		Recursive:    exception.Recursive,
		Applications: nonNilStrings(exception.Applications),
		Enabled:      exception.Enabled,
		Description:  exception.Description,
		ExpiresAt:    rfc3339Or(exception.ExpiresAt),
		CreatedBy:    exception.CreatedBy,
		UpdatedBy:    exception.UpdatedBy,
		CreatedAt:    rfc3339Or(exception.CreatedAt),
		UpdatedAt:    rfc3339Or(exception.UpdatedAt),
	}
}

func fileProfilePortableRulesDTO(in []fileProfileRule) []fileProfilePortableRuleDTO {
	out := make([]fileProfilePortableRuleDTO, 0, len(in))
	for _, rule := range in {
		item := fileProfilePortableRuleDTO{
			Filter:       rule.Filter,
			Path:         rule.Path,
			Regex:        rule.Regex,
			Recursive:    rule.Recursive,
			Behavior:     rule.Behavior,
			Applications: nonNilStrings(rule.Applications),
			Enabled:      boolPtr(rule.Enabled),
			Description:  rule.Description,
		}
		if rule.ID != uuid.Nil {
			item.ID = rule.ID.String()
		}
		out = append(out, item)
	}
	return out
}

func fileProfilePortableExceptionsDTO(in []fileProfileException) []fileProfilePortableExceptionDTO {
	out := make([]fileProfilePortableExceptionDTO, 0, len(in))
	for _, exception := range in {
		ruleID := ""
		if exception.RuleID != uuid.Nil {
			ruleID = exception.RuleID.String()
		}
		item := fileProfilePortableExceptionDTO{
			RuleID:       ruleID,
			Filter:       exception.Filter,
			Path:         exception.Path,
			Regex:        exception.Regex,
			Recursive:    exception.Recursive,
			Applications: nonNilStrings(exception.Applications),
			Enabled:      boolPtr(exception.Enabled),
			Description:  exception.Description,
			ExpiresAt:    rfc3339Or(exception.ExpiresAt),
		}
		if exception.ID != uuid.Nil {
			item.ID = exception.ID.String()
		}
		out = append(out, item)
	}
	return out
}

func fileProfileWatchesDTO(in []fileProfileWatch) []fileProfileWatchDTO {
	out := make([]fileProfileWatchDTO, 0, len(in))
	for _, watch := range in {
		files := json.RawMessage("[]")
		if len(watch.Files) > 0 {
			files = watch.Files
		}
		out = append(out, fileProfileWatchDTO{
			Node:              watch.Node,
			RuleID:            watch.RuleID.String(),
			Filter:            watch.Filter,
			Path:              watch.Path,
			Regex:             watch.Regex,
			Recursive:         watch.Recursive,
			Behavior:          watch.Behavior,
			Applications:      nonNilStrings(watch.Applications),
			ProfileMode:       string(watch.ProfileMode),
			DesiredProtect:    watch.DesiredProtect,
			Protect:           watch.Protect,
			EnforcementState:  watch.EnforcementState,
			Files:             files,
			FilesCount:        watch.FilesCount,
			SensitiveCount:    watch.SensitiveCount,
			BundleFingerprint: watch.BundleFingerprint,
			ObservedAt:        rfc3339Or(watch.ObservedAt),
			UpdatedAt:         rfc3339Or(watch.UpdatedAt),
		})
	}
	return out
}

func decodeFileProfileImportRequest(body io.Reader) (fileProfileImportRequest, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return fileProfileImportRequest{}, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return fileProfileImportRequest{}, errors.New("request body required")
	}
	var req fileProfileImportRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fileProfileImportRequest{}, errors.New("invalid body")
	}
	if req.Bundle != nil {
		return req, nil
	}
	var direct fileProfileExportBundle
	if err := json.Unmarshal(raw, &direct); err != nil {
		return fileProfileImportRequest{}, errors.New("invalid body")
	}
	if direct.SchemaVersion != "" || strings.EqualFold(direct.Kind, "FileProfile") || len(direct.Rules) > 0 {
		req.Bundle = &direct
		return req, nil
	}
	return fileProfileImportRequest{}, errors.New("bundle required")
}

func normalizeFileProfileImportRequest(req fileProfileImportRequest) (fileProfileMode, []fileProfileRule, []fileProfileException, []string, error) {
	if req.Bundle == nil {
		return "", nil, nil, nil, errors.New("bundle required")
	}
	bundle := req.Bundle
	warnings := []string{}
	if schema := strings.TrimSpace(bundle.SchemaVersion); schema != "" && schema != fileProfileBundleSchemaVersion {
		return "", nil, nil, nil, fmt.Errorf("unsupported file profile schema %q", schema)
	} else if schema == "" {
		warnings = append(warnings, "bundle schema_version missing; treating as constellation-file-profile-v1")
	}
	if kind := strings.TrimSpace(bundle.Kind); kind != "" && !strings.EqualFold(kind, "FileProfile") {
		return "", nil, nil, nil, fmt.Errorf("unsupported bundle kind %q", kind)
	}
	if len(bundle.Rules) > 1000 {
		return "", nil, nil, nil, errors.New("too many file profile rules")
	}
	if len(bundle.Exceptions) > 1000 {
		return "", nil, nil, nil, errors.New("too many file profile exceptions")
	}

	modeRaw := strings.TrimSpace(req.Mode)
	if modeRaw == "" {
		modeRaw = strings.TrimSpace(bundle.Mode)
	}
	if modeRaw == "" {
		if len(bundle.Rules) == 0 {
			modeRaw = string(fileProfileModeLearn)
		} else {
			modeRaw = string(fileProfileModeMonitor)
		}
	}
	mode, err := normalizeFileProfileMode(modeRaw)
	if err != nil {
		return "", nil, nil, nil, err
	}

	seen := map[string]bool{}
	rules := make([]fileProfileRule, 0, len(bundle.Rules))
	for i, item := range bundle.Rules {
		enabled := true
		if item.Enabled != nil {
			enabled = *item.Enabled
		}
		recursive := item.Recursive
		rule, err := normalizeFileProfileRuleBody(fileProfileRuleBody{
			Filter:       item.Filter,
			Recursive:    &recursive,
			Behavior:     item.Behavior,
			Applications: item.Applications,
			Enabled:      &enabled,
			Description:  item.Description,
		}, nil)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		if strings.TrimSpace(item.ID) != "" {
			id, err := uuid.Parse(strings.TrimSpace(item.ID))
			if err != nil {
				return "", nil, nil, nil, fmt.Errorf("rule %d: invalid id", i+1)
			}
			rule.ID = id
		}
		if seen[rule.Filter] {
			return "", nil, nil, nil, fmt.Errorf("duplicate file profile filter %q", rule.Filter)
		}
		seen[rule.Filter] = true
		if item.Path != "" && item.Path != rule.Path {
			warnings = append(warnings, fmt.Sprintf("rule %q path was re-derived from filter", rule.Filter))
		}
		if item.Regex != "" && item.Regex != rule.Regex {
			warnings = append(warnings, fmt.Sprintf("rule %q regex was re-derived from filter", rule.Filter))
		}
		rules = append(rules, rule)
	}
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Filter < rules[j].Filter
	})

	exceptionSeen := map[string]bool{}
	exceptions := make([]fileProfileException, 0, len(bundle.Exceptions))
	for i, item := range bundle.Exceptions {
		enabled := true
		if item.Enabled != nil {
			enabled = *item.Enabled
		}
		recursive := item.Recursive
		exception, err := normalizeFileProfileExceptionBodyValue(fileProfileExceptionBody{
			RuleID:       item.RuleID,
			Filter:       item.Filter,
			Recursive:    &recursive,
			Applications: item.Applications,
			Enabled:      &enabled,
			Description:  item.Description,
			ExpiresAt:    item.ExpiresAt,
		}, nil)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("exception %d: %w", i+1, err)
		}
		key := exception.Filter + "\x00" + exception.RuleID.String() + "\x00" + strings.Join(exception.Applications, "\x00")
		if exceptionSeen[key] {
			return "", nil, nil, nil, fmt.Errorf("duplicate file profile exception %q", exception.Filter)
		}
		exceptionSeen[key] = true
		if item.Path != "" && item.Path != exception.Path {
			warnings = append(warnings, fmt.Sprintf("exception %q path was re-derived from filter", exception.Filter))
		}
		if item.Regex != "" && item.Regex != exception.Regex {
			warnings = append(warnings, fmt.Sprintf("exception %q regex was re-derived from filter", exception.Filter))
		}
		exceptions = append(exceptions, exception)
	}
	sort.SliceStable(exceptions, func(i, j int) bool {
		return exceptions[i].Filter < exceptions[j].Filter
	})
	return mode, rules, exceptions, warnings, nil
}

func sensitiveFileProfileWatchCount(files []fileProfileWatchFile) int {
	total := 0
	for _, file := range files {
		if isSensitivePath(file.Path) {
			total++
		}
	}
	return total
}

func normalizeFileProfileWatchEnforcement(state string) string {
	switch strings.TrimSpace(state) {
	case "synced", "unsupported", "enforced", "error":
		return strings.TrimSpace(state)
	default:
		return ""
	}
}

func applyFileProfileTransition(state *fileProfileState, actor string, from, to fileProfileMode, reason string, now time.Time) {
	state.Mode = to
	switch to {
	case fileProfileModeMonitor:
		if state.MonitorStartedAt.IsZero() {
			state.MonitorStartedAt = now
		}
	case fileProfileModeEnforce:
		state.EnforceStartedAt = now
	case fileProfileModeLearn:
		state.LearnStartedAt = now
	}
	state.Transitions = append(state.Transitions, fileProfileTransition{
		At: now, Actor: actor, From: from, To: to, Reason: reason,
	})
}

func validFileProfileTransition(from, to fileProfileMode) bool {
	if from == to {
		return false
	}
	switch from {
	case fileProfileModeLearn:
		return to == fileProfileModeMonitor
	case fileProfileModeMonitor:
		return to == fileProfileModeEnforce || to == fileProfileModeLearn
	case fileProfileModeEnforce:
		return to == fileProfileModeMonitor
	}
	return false
}

func normalizeFileProfileMode(m string) (fileProfileMode, error) {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "learn":
		return fileProfileModeLearn, nil
	case "monitor":
		return fileProfileModeMonitor, nil
	case "enforce":
		return fileProfileModeEnforce, nil
	}
	return "", errors.New("mode must be learn | monitor | enforce")
}

func normalizeFileProfileRuleBody(body fileProfileRuleBody, existing *fileProfileRule) (fileProfileRule, error) {
	rule := fileProfileRule{
		Behavior: "monitor_change",
		Enabled:  true,
	}
	if existing != nil {
		rule = *existing
	}
	filter := strings.TrimSpace(body.Filter)
	if filter == "" && existing == nil {
		return fileProfileRule{}, errors.New("filter required")
	}
	if filter != "" {
		parsed, err := parseFileProfileFilter(filter)
		if err != nil {
			return fileProfileRule{}, err
		}
		rule.Filter = parsed.Filter
		rule.Path = parsed.Path
		rule.Regex = parsed.Regex
	}
	if body.Recursive != nil {
		rule.Recursive = *body.Recursive
	}
	if strings.TrimSpace(body.Behavior) != "" {
		behavior, err := normalizeFileProfileRuleBehavior(body.Behavior)
		if err != nil {
			return fileProfileRule{}, err
		}
		rule.Behavior = behavior
	}
	if body.Applications != nil {
		rule.Applications = normalizeRuleApplications(body.Applications)
	}
	if body.Enabled != nil {
		rule.Enabled = *body.Enabled
	}
	if strings.TrimSpace(body.Description) != "" || existing == nil {
		rule.Description = strings.TrimSpace(body.Description)
	}
	return rule, nil
}

func (h *FileProfiles) normalizeFileProfileExceptionBody(ctx context.Context, orgID uuid.UUID, wl observedWorkload, body fileProfileExceptionBody, existing *fileProfileException) (fileProfileException, error) {
	exception, err := normalizeFileProfileExceptionBodyValue(body, existing)
	if err != nil {
		return fileProfileException{}, err
	}
	if exception.RuleID != uuid.Nil {
		clusterID, err := uuid.Parse(wl.ClusterID)
		if err != nil {
			return fileProfileException{}, err
		}
		if _, ok, err := h.findRule(ctx, orgID, clusterID, wl.WorkloadID, exception.RuleID); err != nil {
			return fileProfileException{}, err
		} else if !ok {
			return fileProfileException{}, errors.New("rule_id does not belong to this file profile")
		}
	}
	return exception, nil
}

func normalizeFileProfileExceptionBodyValue(body fileProfileExceptionBody, existing *fileProfileException) (fileProfileException, error) {
	exception := fileProfileException{
		Enabled: true,
	}
	if existing != nil {
		exception = *existing
	}
	ruleIDRaw := strings.TrimSpace(body.RuleID)
	if ruleIDRaw != "" {
		ruleID, err := uuid.Parse(ruleIDRaw)
		if err != nil {
			return fileProfileException{}, errors.New("invalid rule_id")
		}
		exception.RuleID = ruleID
	}
	filter := strings.TrimSpace(body.Filter)
	if filter == "" && existing == nil {
		return fileProfileException{}, errors.New("filter required")
	}
	if filter != "" {
		parsed, err := parseFileProfileFilter(filter)
		if err != nil {
			return fileProfileException{}, err
		}
		exception.Filter = parsed.Filter
		exception.Path = parsed.Path
		exception.Regex = parsed.Regex
	}
	if body.Recursive != nil {
		exception.Recursive = *body.Recursive
	}
	if body.Applications != nil {
		exception.Applications = normalizeRuleApplications(body.Applications)
	}
	if body.Enabled != nil {
		exception.Enabled = *body.Enabled
	}
	if strings.TrimSpace(body.Description) != "" || existing == nil {
		exception.Description = strings.TrimSpace(body.Description)
	}
	if strings.TrimSpace(body.ExpiresAt) != "" {
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(body.ExpiresAt))
		if err != nil {
			return fileProfileException{}, errors.New("expires_at must be RFC3339")
		}
		exception.ExpiresAt = expiresAt.UTC()
	}
	return exception, nil
}

func parseFileProfileFilter(filter string) (parsedFileProfileFilter, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return parsedFileProfileFilter{}, errors.New("filter required")
	}
	if len(filter) > 512 {
		return parsedFileProfileFilter{}, errors.New("filter is too long")
	}
	if strings.ContainsRune(filter, '\x00') {
		return parsedFileProfileFilter{}, errors.New("filter contains invalid character")
	}
	if !strings.HasPrefix(filter, "/") {
		return parsedFileProfileFilter{}, errors.New("filter must be an absolute path")
	}
	if strings.ContainsAny(filter, "[]()<>") || strings.Contains(filter, "..") || strings.Contains(filter, "/./") {
		return parsedFileProfileFilter{}, errors.New("filter supports only absolute paths and simple * wildcards")
	}
	if strings.HasSuffix(filter, "/") {
		filter += "*"
	}
	cleaned := path.Clean(filter)
	if cleaned == "." || cleaned == "/" || cleaned == "/*" {
		return parsedFileProfileFilter{}, errors.New("filter must target a path below /")
	}
	derived := strings.ReplaceAll(cleaned, ".", "\\.")
	derived = strings.ReplaceAll(derived, "*", ".*")
	idx := strings.LastIndex(derived, "/")
	if idx < 0 {
		return parsedFileProfileFilter{}, errors.New("filter must be an absolute path")
	}
	base := derived[:idx]
	regex := derived[idx+1:]
	if regex == "" {
		return parsedFileProfileFilter{}, errors.New("filter must target a file or wildcard below /")
	}
	if !strings.Contains(regex, "*") {
		base += "/" + regex
		regex = ""
	}
	if _, err := regexp.Compile(base); err != nil {
		return parsedFileProfileFilter{}, errors.New("filter path wildcard is invalid")
	}
	if _, err := regexp.Compile(regex); err != nil {
		return parsedFileProfileFilter{}, errors.New("filter wildcard is invalid")
	}
	return parsedFileProfileFilter{Filter: cleaned, Path: base, Regex: regex}, nil
}

func normalizeFileProfileRuleBehavior(behavior string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(behavior)) {
	case "monitor", "monitor_change":
		return "monitor_change", nil
	case "deny", "block", "block_access":
		return "block_access", nil
	}
	return "", errors.New("behavior must be monitor_change | block_access")
}

func normalizeRuleApplications(apps []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, app := range apps {
		app = strings.TrimSpace(app)
		if app == "" || seen[app] {
			continue
		}
		seen[app] = true
		out = append(out, app)
	}
	sort.Strings(out)
	return out
}

func boolPtr(v bool) *bool {
	return &v
}

func nullableFileProfileUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func parseFileProfileOptionalUUID(raw string) uuid.UUID {
	if strings.TrimSpace(raw) == "" {
		return uuid.Nil
	}
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return uuid.Nil
	}
	return id
}

func countFileProfiles(items []fileProfileSummaryDTO, mode string) int {
	total := 0
	for _, item := range items {
		if item.Mode == mode {
			total++
		}
	}
	return total
}

func (h *FileProfiles) ruleRequest(w http.ResponseWriter, r *http.Request) (authctx.Subject, observedWorkload, fileProfileRuleBody, bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return authctx.Subject{}, observedWorkload{}, fileProfileRuleBody{}, false
	}
	workloadID := workloadIDParam(r)
	if workloadID == "" {
		jsonError(w, http.StatusBadRequest, "workload_id required")
		return authctx.Subject{}, observedWorkload{}, fileProfileRuleBody{}, false
	}
	var body fileProfileRuleBody
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			jsonError(w, http.StatusBadRequest, "invalid body")
			return authctx.Subject{}, observedWorkload{}, fileProfileRuleBody{}, false
		}
	}
	if strings.TrimSpace(body.Reason) == "" {
		jsonError(w, http.StatusBadRequest, "reason required")
		return authctx.Subject{}, observedWorkload{}, fileProfileRuleBody{}, false
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return authctx.Subject{}, observedWorkload{}, fileProfileRuleBody{}, false
	}
	wl, found, err := h.findWorkload(r.Context(), subj.OrgID, clusterArg, workloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return authctx.Subject{}, observedWorkload{}, fileProfileRuleBody{}, false
	}
	if !found {
		jsonError(w, http.StatusNotFound, "workload not found")
		return authctx.Subject{}, observedWorkload{}, fileProfileRuleBody{}, false
	}
	if _, err := h.ensureState(r.Context(), subj.OrgID, wl, time.Now().UTC()); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return authctx.Subject{}, observedWorkload{}, fileProfileRuleBody{}, false
	}
	return subj, wl, body, true
}

func (h *FileProfiles) exceptionRequest(w http.ResponseWriter, r *http.Request) (authctx.Subject, observedWorkload, fileProfileExceptionBody, bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return authctx.Subject{}, observedWorkload{}, fileProfileExceptionBody{}, false
	}
	workloadID := workloadIDParam(r)
	if workloadID == "" {
		jsonError(w, http.StatusBadRequest, "workload_id required")
		return authctx.Subject{}, observedWorkload{}, fileProfileExceptionBody{}, false
	}
	var body fileProfileExceptionBody
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			jsonError(w, http.StatusBadRequest, "invalid body")
			return authctx.Subject{}, observedWorkload{}, fileProfileExceptionBody{}, false
		}
	}
	if strings.TrimSpace(body.Reason) == "" {
		jsonError(w, http.StatusBadRequest, "reason required")
		return authctx.Subject{}, observedWorkload{}, fileProfileExceptionBody{}, false
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return authctx.Subject{}, observedWorkload{}, fileProfileExceptionBody{}, false
	}
	wl, found, err := h.findWorkload(r.Context(), subj.OrgID, clusterArg, workloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return authctx.Subject{}, observedWorkload{}, fileProfileExceptionBody{}, false
	}
	if !found {
		jsonError(w, http.StatusNotFound, "workload not found")
		return authctx.Subject{}, observedWorkload{}, fileProfileExceptionBody{}, false
	}
	if _, err := h.ensureState(r.Context(), subj.OrgID, wl, time.Now().UTC()); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return authctx.Subject{}, observedWorkload{}, fileProfileExceptionBody{}, false
	}
	return subj, wl, body, true
}

func (h *FileProfiles) audit(r *http.Request, subj authctx.Subject, to, from fileProfileMode, workloadID, reason string) {
	if h.auditLog == nil {
		return
	}
	orgID := subj.OrgID
	userID := subj.UserID
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    actorIP,
		Action:     "file_profile.transition",
		TargetKind: "file-profile",
		TargetID:   workloadID,
		Before:     map[string]any{"mode": string(from)},
		After:      map[string]any{"mode": string(to), "reason": reason},
		RequestID:  chimw.GetReqID(r.Context()),
	})
}

func (h *FileProfiles) auditRule(r *http.Request, subj authctx.Subject, action, workloadID string, before *fileProfileRule, after fileProfileRule, reason string) {
	if h.auditLog == nil {
		return
	}
	orgID := subj.OrgID
	userID := subj.UserID
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	var beforeBody any
	if before != nil {
		dto := fileProfileRuleToDTO(*before)
		beforeBody = dto
	}
	afterBody := any(nil)
	if after.ID != uuid.Nil {
		dto := fileProfileRuleToDTO(after)
		afterBody = dto
	}
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    actorIP,
		Action:     action,
		TargetKind: "file-profile-rule",
		TargetID:   workloadID,
		Before:     beforeBody,
		After:      map[string]any{"rule": afterBody, "reason": reason},
		RequestID:  chimw.GetReqID(r.Context()),
	})
}

func (h *FileProfiles) auditException(r *http.Request, subj authctx.Subject, action, workloadID string, before *fileProfileException, after fileProfileException, reason string) {
	if h.auditLog == nil {
		return
	}
	orgID := subj.OrgID
	userID := subj.UserID
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	var beforeBody any
	if before != nil {
		dto := fileProfileExceptionToDTO(*before)
		beforeBody = dto
	}
	afterBody := any(nil)
	if after.ID != uuid.Nil {
		dto := fileProfileExceptionToDTO(after)
		afterBody = dto
	}
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    actorIP,
		Action:     action,
		TargetKind: "file-profile-exception",
		TargetID:   workloadID,
		Before:     beforeBody,
		After:      map[string]any{"exception": afterBody, "reason": reason},
		RequestID:  chimw.GetReqID(r.Context()),
	})
}

func (h *FileProfiles) auditImport(r *http.Request, subj authctx.Subject, workloadID string, from, to fileProfileMode, imported int, deleted int64, replace bool, reason string) {
	if h.auditLog == nil {
		return
	}
	orgID := subj.OrgID
	userID := subj.UserID
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    actorIP,
		Action:     "file_profile.import",
		TargetKind: "file-profile",
		TargetID:   workloadID,
		Before: map[string]any{
			"mode": string(from),
		},
		After: map[string]any{
			"mode":     string(to),
			"imported": imported,
			"deleted":  deleted,
			"replace":  replace,
			"reason":   reason,
		},
		RequestID: chimw.GetReqID(r.Context()),
	})
}
