// Runtime deployment-detail seam, retained in package handler.
//
// deployments.go and migration_preview.go render runtime data (events,
// quarantine, file-profile rules/exceptions/watches) inline as part of the
// deployment-detail and migration-preview API responses. Those handlers live in
// package handler and cannot import internal/handler/runtime (that package
// imports handler, so importing it back would create a cycle).
//
// During the ARC-1 runtime split the DTO shapes, the row types those handlers
// scan into, the small pure converters, and a few stateless helpers were copied
// here so the parent package stays self-contained. The runtime sub-package keeps
// its own (identical) copies; the two never share a symbol, so there is no
// cross-package coupling and no cycle. These are pure data shapes / pure
// functions — keeping a parallel copy is the same pattern policy/findings used
// for their small helpers.
package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// DTO output shapes (deployment-detail / migration-preview API contract)
// ---------------------------------------------------------------------------

// EventDTO is the wire shape for a runtime event in deployment detail.
type EventDTO struct {
	ID               uuid.UUID       `json:"id"`
	At               time.Time       `json:"at"`
	Kind             string          `json:"kind"`
	Source           string          `json:"source"`
	Severity         string          `json:"severity"`
	Verdict          string          `json:"verdict"`
	NodeID           string          `json:"node_id"`
	WorkloadID       string          `json:"workload_id"`
	Namespace        string          `json:"namespace,omitempty"`
	ContainerID      string          `json:"container_id,omitempty"`
	AttackTechniques []string        `json:"attack_techniques"`
	Payload          json.RawMessage `json:"payload"`
}

type quarantineDTO struct {
	ID           uuid.UUID  `json:"id"`
	OrgID        uuid.UUID  `json:"org_id"`
	ClusterID    uuid.UUID  `json:"cluster_id"`
	Scope        string     `json:"scope"`
	MatchKey     string     `json:"match_key"`
	Reason       string     `json:"reason"`
	Origin       string     `json:"origin"`
	SourceKind   string     `json:"source_kind,omitempty"`
	SourceID     *uuid.UUID `json:"source_id,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	LiftedAt     *time.Time `json:"lifted_at,omitempty"`
	LiftedBy     *uuid.UUID `json:"lifted_by,omitempty"`
	LiftedReason string     `json:"lifted_reason,omitempty"`
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

// ---------------------------------------------------------------------------
// Row types the deployment-detail SQL scans into
// ---------------------------------------------------------------------------

type fileProfileMode string

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

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

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

func fileProfileExceptionsDTO(in []fileProfileException) []fileProfileExceptionDTO {
	out := make([]fileProfileExceptionDTO, 0, len(in))
	for _, exception := range in {
		out = append(out, fileProfileExceptionToDTO(exception))
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

// deploymentFileProfileExceptions is the parent-local equivalent of the runtime
// FileProfiles.exceptionsFor query: it loads a workload's file-profile exceptions
// for inline rendering in the deployment-detail response.
func (h *Deployments) deploymentFileProfileExceptions(r *http.Request, orgID, clusterID uuid.UUID, workloadID string) ([]fileProfileException, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
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

// ---------------------------------------------------------------------------
// Stateless helpers (mirrors of the runtime copies)
// ---------------------------------------------------------------------------

func boolPtr(v bool) *bool { return &v }

func rfc3339Or(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func commBasename(comm, filename string) string {
	if comm != "" {
		return comm
	}
	if filename == "" {
		return ""
	}
	if i := strings.LastIndexByte(filename, '/'); i >= 0 {
		return filename[i+1:]
	}
	return filename
}

func isSensitivePath(p string) bool {
	if p == "" {
		return false
	}
	for _, prefix := range []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/sudoers",
		"/etc/kubernetes",
		"/root/.ssh",
		"/home",
		"/run/secrets",
		"/var/lib/kubelet/pki",
		"/var/run/secrets/kubernetes.io",
		"/var/run/secrets/eks.amazonaws.com",
	} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}
