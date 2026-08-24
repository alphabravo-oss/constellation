package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/migration/aqua"
	"github.com/alphabravocompany/constellation/internal/migration/neuvector"
	"github.com/alphabravocompany/constellation/internal/migration/prisma"
	"github.com/alphabravocompany/constellation/internal/migration/stackrox"
	"github.com/alphabravocompany/constellation/internal/runtime/dlp"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/group"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

type migrationPreviewRequest struct {
	Source    string `json:"source"`
	Export    string `json:"export"`
	ClusterID string `json:"cluster_id,omitempty"`
}

type migrationPreviewPolicyDTO struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Engine      string            `json:"engine"`
	Category    string            `json:"category"`
	Enabled     bool              `json:"enabled"`
	Mode        string            `json:"mode"`
	SpecYAML    string            `json:"spec_yaml"`
	Imported    map[string]string `json:"imported_from,omitempty"`
	DiffAction  string            `json:"diff_action"`
}

type migrationPreviewFileProfileDTO struct {
	Group           string                       `json:"group"`
	ClusterID       string                       `json:"cluster_id,omitempty"`
	TargetGroupName string                       `json:"target_group_name,omitempty"`
	TargetWorkloads []string                     `json:"target_workloads,omitempty"`
	Mode            string                       `json:"mode"`
	CfgType         string                       `json:"cfg_type,omitempty"`
	Description     string                       `json:"description,omitempty"`
	Rules           []fileProfilePortableRuleDTO `json:"rules"`
	Imported        map[string]string            `json:"imported_from,omitempty"`
	DiffAction      string                       `json:"diff_action"`
}

type migrationPreviewProcessProfileDTO struct {
	Group           string                    `json:"group"`
	ClusterID       string                    `json:"cluster_id,omitempty"`
	TargetGroupName string                    `json:"target_group_name,omitempty"`
	TargetWorkloads []string                  `json:"target_workloads,omitempty"`
	Mode            string                    `json:"mode"`
	Baseline        string                    `json:"baseline,omitempty"`
	CfgType         string                    `json:"cfg_type,omitempty"`
	Description     string                    `json:"description,omitempty"`
	Rules           []migrationProcessRuleDTO `json:"rules"`
	Imported        map[string]string         `json:"imported_from,omitempty"`
	DiffAction      string                    `json:"diff_action"`
}

type migrationProcessRuleDTO struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	User        string `json:"user,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
	Action      string `json:"action"`
	CfgType     string `json:"cfg_type,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	AllowUpdate bool   `json:"allow_update"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

type migrationPreviewGroupDTO struct {
	Name        string                   `json:"name"`
	ClusterID   string                   `json:"cluster_id,omitempty"`
	Kind        string                   `json:"kind"`
	Comment     string                   `json:"comment,omitempty"`
	CfgType     string                   `json:"cfg_type,omitempty"`
	PolicyMode  string                   `json:"policy_mode,omitempty"`
	ProfileMode string                   `json:"profile_mode,omitempty"`
	Criteria    []portableGroupCriterion `json:"criteria"`
	Imported    map[string]string        `json:"imported_from,omitempty"`
	DiffAction  string                   `json:"diff_action"`
}

type migrationPreviewDPIRuleDTO struct {
	Name              string                   `json:"name"`
	ClusterID         string                   `json:"cluster_id,omitempty"`
	Category          string                   `json:"category"`
	ApplyDir          int16                    `json:"apply_dir"`
	Severity          int16                    `json:"severity"`
	Mode              string                   `json:"mode"`
	Patterns          []migrationDPIPatternDTO `json:"patterns"`
	Description       string                   `json:"description,omitempty"`
	SourceSensor      string                   `json:"source_sensor,omitempty"`
	SourceGroups      []string                 `json:"source_groups,omitempty"`
	SourcePath        string                   `json:"source_path,omitempty"`
	SourceCfgType     string                   `json:"source_cfg_type,omitempty"`
	SourceRuleCfgType string                   `json:"source_rule_cfg_type,omitempty"`
	Federated         bool                     `json:"federated,omitempty"`
	Imported          map[string]string        `json:"imported_from,omitempty"`
	DiffAction        string                   `json:"diff_action"`
}

type migrationPreviewDPIBindingDTO struct {
	SourceGroup     string            `json:"source_group"`
	TargetGroupID   string            `json:"target_group_id"`
	TargetGroupName string            `json:"target_group_name"`
	SensorKind      string            `json:"sensor_kind"`
	SourceSensors   []string          `json:"source_sensors,omitempty"`
	Imported        map[string]string `json:"imported_from,omitempty"`
	DiffAction      string            `json:"diff_action"`
}

type migrationPreviewNetworkRuleDTO struct {
	Name       string                    `json:"name"`
	ClusterID  string                    `json:"cluster_id,omitempty"`
	FromGroup  string                    `json:"from_group"`
	ToGroup    string                    `json:"to_group"`
	Ports      []migrationNetworkPortDTO `json:"ports"`
	Mode       string                    `json:"mode"`
	Comment    string                    `json:"comment,omitempty"`
	Priority   int                       `json:"priority"`
	Imported   map[string]string         `json:"imported_from,omitempty"`
	DiffAction string                    `json:"diff_action"`
}

type migrationNetworkPortDTO struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

type migrationDPIPatternDTO struct {
	Pattern string `json:"pattern"`
	Op      string `json:"op,omitempty"`
	Context string `json:"context,omitempty"`
}

type migrationPreviewSummaryDTO struct {
	Source          string         `json:"source"`
	Total           int            `json:"total"`
	SourceTotal     int            `json:"source_total,omitempty"`
	SourceCounts    map[string]int `json:"source_counts,omitempty"`
	Unaccounted     int            `json:"unaccounted_source,omitempty"`
	Create          int            `json:"create"`
	Update          int            `json:"update"`
	Enforce         int            `json:"enforce"`
	Monitor         int            `json:"monitor"`
	Enabled         int            `json:"enabled"`
	FileProfiles    int            `json:"file_profiles"`
	ProcessProfiles int            `json:"process_profiles"`
	Groups          int            `json:"groups"`
	DPIRules        int            `json:"dpi_rules"`
	DPIBindings     int            `json:"dpi_bindings"`
	NetworkRules    int            `json:"network_rules"`
	Unsupported     int            `json:"unsupported"`
	Engines         map[string]int `json:"engines"`
	Categories      map[string]int `json:"categories"`
	ReadOnly        bool           `json:"read_only"`
	RollbackHint    string         `json:"rollback_hint"`
}

type migrationPreviewDTO struct {
	ImportID        string                              `json:"import_id,omitempty"`
	Summary         migrationPreviewSummaryDTO          `json:"summary"`
	Policies        []migrationPreviewPolicyDTO         `json:"policies"`
	FileProfiles    []migrationPreviewFileProfileDTO    `json:"file_profiles"`
	ProcessProfiles []migrationPreviewProcessProfileDTO `json:"process_profiles"`
	Groups          []migrationPreviewGroupDTO          `json:"groups"`
	DPIRules        []migrationPreviewDPIRuleDTO        `json:"dpi_rules"`
	DPIBindings     []migrationPreviewDPIBindingDTO     `json:"dpi_bindings"`
	NetworkRules    []migrationPreviewNetworkRuleDTO    `json:"network_rules"`
	Unsupported     []migrationUnsupportedDTO           `json:"unsupported,omitempty"`
	RollbackBundle  string                              `json:"rollback_bundle"`
}

type migrationUnsupportedDTO struct {
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	Reason     string         `json:"reason"`
	Suggestion string         `json:"suggestion,omitempty"`
	Source     map[string]any `json:"source,omitempty"`
}

type migrationImportListItemDTO struct {
	ID             string                     `json:"id"`
	Source         string                     `json:"source"`
	Status         string                     `json:"status"`
	Summary        migrationPreviewSummaryDTO `json:"summary"`
	AppliedSummary map[string]int             `json:"applied_summary,omitempty"`
	Unsupported    []migrationUnsupportedDTO  `json:"unsupported,omitempty"`
	Error          string                     `json:"error,omitempty"`
	CreatedAt      string                     `json:"created_at"`
	AppliedAt      string                     `json:"applied_at,omitempty"`
	RolledBackAt   string                     `json:"rolled_back_at,omitempty"`
}

type policyRollbackSnapshot struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Engine      string `json:"engine"`
	Category    string `json:"category"`
	SpecYAML    string `json:"spec_yaml"`
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode"`
	Version     int    `json:"version"`
	CfgType     string `json:"cfg_type,omitempty"`
	Source      string `json:"source,omitempty"`
}

type migrationPolicyRollbackDTO struct {
	Name   string                  `json:"name"`
	Action string                  `json:"action"`
	ID     string                  `json:"id,omitempty"`
	Before *policyRollbackSnapshot `json:"before,omitempty"`
}

type dpiRuleRollbackSnapshot struct {
	ID          string          `json:"id"`
	ClusterID   string          `json:"cluster_id"`
	Name        string          `json:"name"`
	Category    string          `json:"category"`
	ApplyDir    int16           `json:"apply_dir"`
	Severity    int16           `json:"severity"`
	Mode        string          `json:"mode"`
	Patterns    json.RawMessage `json:"patterns"`
	ScopeMACs   json.RawMessage `json:"scope_macs,omitempty"`
	Description string          `json:"description"`
	Source      string          `json:"source,omitempty"`
	CfgType     string          `json:"cfg_type,omitempty"`
	SourcePath  string          `json:"source_path,omitempty"`
	Version     int64           `json:"version"`
}

type migrationDPIRuleRollbackDTO struct {
	Name   string                   `json:"name"`
	Action string                   `json:"action"`
	ID     string                   `json:"id,omitempty"`
	Before *dpiRuleRollbackSnapshot `json:"before,omitempty"`
}

type groupRollbackSnapshot struct {
	ID          string          `json:"id"`
	ClusterID   string          `json:"cluster_id,omitempty"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Comment     string          `json:"comment"`
	Criteria    json.RawMessage `json:"criteria"`
	Members     json.RawMessage `json:"members"`
	LearnedFrom string          `json:"learned_from,omitempty"`
	CfgType     string          `json:"cfg_type,omitempty"`
	PolicyMode  string          `json:"policy_mode,omitempty"`
	ProfileMode string          `json:"profile_mode,omitempty"`
}

type migrationGroupRollbackDTO struct {
	Name   string                 `json:"name"`
	Action string                 `json:"action"`
	ID     string                 `json:"id,omitempty"`
	Before *groupRollbackSnapshot `json:"before,omitempty"`
}

type migrationDPIBindingRollbackDTO struct {
	SourceGroup string `json:"source_group"`
	SensorKind  string `json:"sensor_kind"`
	Action      string `json:"action"`
	ID          string `json:"id,omitempty"`
}

type networkRuleRollbackSnapshot struct {
	ID        string          `json:"id"`
	ClusterID string          `json:"cluster_id"`
	FromGroup string          `json:"from_group"`
	ToGroup   string          `json:"to_group"`
	Ports     json.RawMessage `json:"ports"`
	Mode      string          `json:"mode"`
	Comment   string          `json:"comment"`
}

type migrationNetworkRuleRollbackDTO struct {
	Name      string                       `json:"name"`
	FromGroup string                       `json:"from_group"`
	ToGroup   string                       `json:"to_group"`
	Action    string                       `json:"action"`
	ID        string                       `json:"id,omitempty"`
	Before    *networkRuleRollbackSnapshot `json:"before,omitempty"`
}

type migrationObservedWorkload struct {
	WorkloadID string
	Namespace  string
	Name       string
}

type migrationParsedFileProfileFilter struct {
	Filter string
	Path   string
	Regex  string
}

type fileProfileStateRollbackSnapshot struct {
	ID               string     `json:"id"`
	ClusterID        string     `json:"cluster_id"`
	WorkloadID       string     `json:"workload_id"`
	Namespace        string     `json:"namespace"`
	Name             string     `json:"name"`
	Mode             string     `json:"mode"`
	LearnStartedAt   time.Time  `json:"learn_started_at"`
	MonitorStartedAt *time.Time `json:"monitor_started_at,omitempty"`
	EnforceStartedAt *time.Time `json:"enforce_started_at,omitempty"`
}

type fileProfileRuleRollbackSnapshot struct {
	ID           string   `json:"id"`
	ClusterID    string   `json:"cluster_id"`
	WorkloadID   string   `json:"workload_id"`
	Filter       string   `json:"filter"`
	Path         string   `json:"path"`
	Regex        string   `json:"regex"`
	Recursive    bool     `json:"recursive"`
	Behavior     string   `json:"behavior"`
	Applications []string `json:"applications"`
	Enabled      bool     `json:"enabled"`
	Description  string   `json:"description"`
}

type migrationFileProfileRuleRollbackDTO struct {
	Filter string                           `json:"filter"`
	Action string                           `json:"action"`
	ID     string                           `json:"id,omitempty"`
	Before *fileProfileRuleRollbackSnapshot `json:"before,omitempty"`
}

type migrationFileProfileRollbackDTO struct {
	Group      string                                `json:"group"`
	WorkloadID string                                `json:"workload_id"`
	Action     string                                `json:"action"`
	StateID    string                                `json:"state_id,omitempty"`
	Before     *fileProfileStateRollbackSnapshot     `json:"before,omitempty"`
	Rules      []migrationFileProfileRuleRollbackDTO `json:"rules,omitempty"`
}

type processBaselineStateRollbackSnapshot struct {
	ID               string     `json:"id"`
	ClusterID        string     `json:"cluster_id"`
	WorkloadID       string     `json:"workload_id"`
	Namespace        string     `json:"namespace"`
	Name             string     `json:"name"`
	Mode             string     `json:"mode"`
	LearnStartedAt   time.Time  `json:"learn_started_at"`
	MonitorStartedAt *time.Time `json:"monitor_started_at,omitempty"`
	EnforceStartedAt *time.Time `json:"enforce_started_at,omitempty"`
}

type processProfileRuleRollbackSnapshot struct {
	ID          string `json:"id"`
	ClusterID   string `json:"cluster_id"`
	WorkloadID  string `json:"workload_id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	ParentName  string `json:"parent_name"`
	Action      string `json:"action"`
	User        string `json:"user"`
	AllowUpdate bool   `json:"allow_update"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

type migrationProcessProfileRuleRollbackDTO struct {
	Name   string                              `json:"name"`
	Path   string                              `json:"path"`
	Action string                              `json:"action"`
	ID     string                              `json:"id,omitempty"`
	Before *processProfileRuleRollbackSnapshot `json:"before,omitempty"`
}

type migrationProcessProfileRollbackDTO struct {
	Group      string                                   `json:"group"`
	WorkloadID string                                   `json:"workload_id"`
	Action     string                                   `json:"action"`
	StateID    string                                   `json:"state_id,omitempty"`
	Before     *processBaselineStateRollbackSnapshot    `json:"before,omitempty"`
	Rules      []migrationProcessProfileRuleRollbackDTO `json:"rules,omitempty"`
}

var migrationRollbackFilenameUnsafe = regexp.MustCompile(`[^a-z0-9._-]+`)

func (h *Enterprise) MigrationPreview(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var req migrationPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid migration preview request"})
		return
	}
	source := strings.ToLower(strings.TrimSpace(req.Source))
	raw := []byte(req.Export)
	if source == "" || len(strings.TrimSpace(req.Export)) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "source and export are required"})
		return
	}
	sourceCounts, err := countMigrationSourceObjects(source, raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	subj, hasSubject := SubjectFrom(r.Context())
	if h != nil && h.db != nil && !hasSubject {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	policies, err := convertMigrationPreview(source, raw)
	if err != nil {
		if hasSubject {
			h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	fileProfiles, err := convertMigrationFileProfiles(source, raw)
	if err != nil {
		if hasSubject {
			h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	processProfiles, processUnsupported, err := convertMigrationProcessProfiles(source, raw)
	if err != nil {
		if hasSubject {
			h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	groups, groupUnsupported, err := convertMigrationGroups(source, raw)
	if err != nil {
		if hasSubject {
			h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	dpiRules, dpiBindings, dpiUnsupported, err := convertMigrationDPIRules(source, raw)
	if err != nil {
		if hasSubject {
			h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	networkRules, networkUnsupported, err := convertMigrationNetworkRules(source, raw)
	if err != nil {
		if hasSubject {
			h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	clusterIDRaw := strings.TrimSpace(req.ClusterID)
	needsCluster := len(groups) > 0 || len(processProfiles) > 0 || len(dpiRules) > 0 || len(dpiBindings) > 0 || len(networkRules) > 0
	if needsCluster || (len(fileProfiles) > 0 && clusterIDRaw != "") {
		clusterID, err := uuid.Parse(strings.TrimSpace(req.ClusterID))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target cluster_id is required for NeuVector group, process profile, network rule, and DLP/WAF imports"})
			return
		}
		if h != nil && h.db != nil {
			ok, err := h.migrationClusterExists(r, subj.OrgID, clusterID)
			if err != nil {
				if hasSubject {
					h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
				}
				jsonError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !ok {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target cluster_id does not belong to this organization"})
				return
			}
		}
		resolvedFileProfiles, fileProfileUnsupported, err := h.resolveMigrationFileProfiles(r, subj.OrgID, clusterID, fileProfiles, groups)
		if err != nil {
			if hasSubject {
				h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
			}
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		fileProfiles = resolvedFileProfiles
		groupUnsupported = append(groupUnsupported, fileProfileUnsupported...)
		resolvedProcessProfiles, processProfileUnsupported, err := h.resolveMigrationProcessProfiles(r, subj.OrgID, clusterID, processProfiles, groups)
		if err != nil {
			if hasSubject {
				h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
			}
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		processProfiles = resolvedProcessProfiles
		processUnsupported = append(processUnsupported, processProfileUnsupported...)
		existingGroups, err := h.existingMigrationGroupNames(r, subj.OrgID, clusterID)
		if err != nil {
			if hasSubject {
				h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
			}
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for i := range groups {
			groups[i].ClusterID = clusterID.String()
			if existingGroups[groups[i].Name] {
				groups[i].DiffAction = "update"
			} else {
				groups[i].DiffAction = "create"
			}
		}
		existingDPI, err := h.existingDPIRuleNames(r, subj.OrgID, clusterID)
		if err != nil {
			if hasSubject {
				h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
			}
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for i := range dpiRules {
			dpiRules[i].ClusterID = clusterID.String()
			if existingDPI[dpiRules[i].Name] {
				dpiRules[i].DiffAction = "update"
			} else {
				dpiRules[i].DiffAction = "create"
			}
		}
		resolvedBindings, bindingUnsupported, err := h.resolveMigrationDPIBindings(r, subj.OrgID, clusterID, dpiBindings, groups)
		if err != nil {
			if hasSubject {
				h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
			}
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		dpiBindings = resolvedBindings
		dpiUnsupported = append(dpiUnsupported, bindingUnsupported...)
		resolvedNetworkRules, ruleUnsupported, err := h.resolveMigrationNetworkRules(r, subj.OrgID, clusterID, networkRules, groups)
		if err != nil {
			if hasSubject {
				h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
			}
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		networkRules = resolvedNetworkRules
		networkUnsupported = append(networkUnsupported, ruleUnsupported...)
		existingEdges, err := h.existingMigrationNetworkEdgeKeys(r, subj.OrgID, clusterID)
		if err != nil {
			if hasSubject {
				h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
			}
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for i := range networkRules {
			networkRules[i].ClusterID = clusterID.String()
			if existingEdges[migrationNetworkRuleKey(networkRules[i].FromGroup, networkRules[i].ToGroup)] {
				networkRules[i].DiffAction = "update"
			} else {
				networkRules[i].DiffAction = "create"
			}
		}
	}
	existing, err := h.existingPolicyNames(r, subj.OrgID.String())
	if err != nil {
		if hasSubject {
			h.auditMigration(r, subj, "migration.import.preview.failed", source, map[string]any{"source": source, "error": err.Error()})
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range policies {
		if existing[policies[i].Name] {
			policies[i].DiffAction = "update"
		} else {
			policies[i].DiffAction = "create"
		}
	}

	out := migrationPreviewDTO{
		Summary:         summarizeMigrationPreview(source, sourceCounts, policies, fileProfiles, processProfiles, groups, dpiRules, dpiBindings, networkRules),
		Policies:        policies,
		FileProfiles:    fileProfiles,
		ProcessProfiles: processProfiles,
		Groups:          groups,
		DPIRules:        dpiRules,
		DPIBindings:     dpiBindings,
		NetworkRules:    networkRules,
		RollbackBundle:  renderMigrationRollbackBundle(source, policies, fileProfiles, processProfiles, groups, dpiRules, dpiBindings, networkRules),
	}
	out.Unsupported = migrationUnsupportedFromPreview(fileProfiles, clusterIDRaw, append(append(append(groupUnsupported, processUnsupported...), dpiUnsupported...), networkUnsupported...))
	out.Summary.Unsupported = len(out.Unsupported)
	if out.Summary.SourceTotal > out.Summary.Total+out.Summary.Unsupported {
		out.Summary.Unaccounted = out.Summary.SourceTotal - out.Summary.Total - out.Summary.Unsupported
	}
	if h != nil && h.db != nil {
		id, err := h.persistMigrationPreview(r, subj, source, raw, out)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out.ImportID = id.String()
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Enterprise) MigrationImports(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"imports": []migrationImportListItemDTO{}})
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, source, status, preview_json, applied_json, unsupported_json, error,
       created_at, applied_at, rolled_back_at
  FROM migration_imports
 WHERE org_id = $1
 ORDER BY created_at DESC
 LIMIT 25`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []migrationImportListItemDTO{}
	for rows.Next() {
		var (
			id             uuid.UUID
			source         string
			status         string
			previewRaw     json.RawMessage
			appliedRaw     json.RawMessage
			unsupportedRaw json.RawMessage
			errorText      string
			createdAt      time.Time
			appliedAt      *time.Time
			rolledBackAt   *time.Time
		)
		if err := rows.Scan(&id, &source, &status, &previewRaw, &appliedRaw, &unsupportedRaw, &errorText, &createdAt, &appliedAt, &rolledBackAt); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		var preview migrationPreviewDTO
		_ = json.Unmarshal(previewRaw, &preview)
		var applied map[string]int
		_ = json.Unmarshal(appliedRaw, &applied)
		var unsupported []migrationUnsupportedDTO
		_ = json.Unmarshal(unsupportedRaw, &unsupported)
		item := migrationImportListItemDTO{
			ID: id.String(), Source: source, Status: status, Summary: preview.Summary,
			AppliedSummary: applied, Unsupported: unsupported, Error: errorText,
			CreatedAt: createdAt.UTC().Format(time.RFC3339),
		}
		if appliedAt != nil {
			item.AppliedAt = appliedAt.UTC().Format(time.RFC3339)
		}
		if rolledBackAt != nil {
			item.RolledBackAt = rolledBackAt.UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"imports": out})
}

func (h *Enterprise) MigrationRollbackBundle(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	if !h.authorizeMigrationMutation(r, subj) {
		h.auditMigration(r, subj, "migration.import.rollback_bundle.failed", chi.URLParam(r, "id"), map[string]any{"reason": "forbidden", "verb": string(rbac.VerbManagePolicies)})
		jsonError(w, http.StatusForbidden, "forbidden: "+string(rbac.VerbManagePolicies))
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.auditMigration(r, subj, "migration.import.rollback_bundle.failed", chi.URLParam(r, "id"), map[string]any{"reason": "bad_import_id", "error": err.Error()})
		jsonError(w, http.StatusBadRequest, "bad import id")
		return
	}
	var source string
	var status string
	var rollbackRaw json.RawMessage
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT source, status, rollback_json
  FROM migration_imports
 WHERE id=$1 AND org_id=$2`, id, subj.OrgID).Scan(&source, &status, &rollbackRaw); err != nil {
		if err == pgx.ErrNoRows {
			h.auditMigration(r, subj, "migration.import.rollback_bundle.failed", id.String(), map[string]any{"reason": "not_found"})
			jsonError(w, http.StatusNotFound, "migration import not found")
			return
		}
		h.auditMigration(r, subj, "migration.import.rollback_bundle.failed", id.String(), map[string]any{"reason": "load_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if status != "applied" && status != "partial_applied" && status != "rolled_back" {
		h.auditMigration(r, subj, "migration.import.rollback_bundle.failed", id.String(), map[string]any{"source": source, "reason": "not_available", "status": status})
		jsonError(w, http.StatusConflict, "migration import has no replayable rollback bundle from status "+status)
		return
	}
	var bundle any
	if err := json.Unmarshal(rollbackRaw, &bundle); err != nil || bundle == nil {
		msg := "rollback bundle is invalid"
		if err != nil {
			msg = err.Error()
		}
		h.auditMigration(r, subj, "migration.import.rollback_bundle.failed", id.String(), map[string]any{"source": source, "reason": "invalid_rollback_bundle", "error": msg})
		jsonError(w, http.StatusInternalServerError, "invalid rollback bundle")
		return
	}
	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		h.auditMigration(r, subj, "migration.import.rollback_bundle.failed", id.String(), map[string]any{"source": source, "reason": "marshal_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditMigration(r, subj, "migration.import.rollback_bundle.download", id.String(), map[string]any{"source": source, "status": status})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, migrationRollbackBundleFilename(source, id)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (h *Enterprise) MigrationApply(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	if !h.authorizeMigrationMutation(r, subj) {
		h.auditMigration(r, subj, "migration.import.apply.failed", chi.URLParam(r, "id"), map[string]any{"reason": "forbidden", "verb": string(rbac.VerbManagePolicies)})
		jsonError(w, http.StatusForbidden, "forbidden: "+string(rbac.VerbManagePolicies))
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.auditMigration(r, subj, "migration.import.apply.failed", chi.URLParam(r, "id"), map[string]any{"reason": "bad_import_id", "error": err.Error()})
		jsonError(w, http.StatusBadRequest, "bad import id")
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	source, status, preview, err := h.loadMigrationImportForUpdate(r, tx, subj.OrgID, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"reason": "not_found"})
			jsonError(w, http.StatusNotFound, "migration import not found")
			return
		}
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"reason": "load_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if status == "applied" || status == "partial_applied" {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.apply.skipped", id.String(), map[string]any{"source": source, "reason": "already_applied", "status": status})
		writeJSON(w, http.StatusOK, map[string]any{"id": id.String(), "status": status, "already_applied": true})
		return
	}
	if status != "previewed" && status != "rolled_back" {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.apply.skipped", id.String(), map[string]any{"source": source, "reason": "not_applyable", "status": status})
		jsonError(w, http.StatusConflict, "migration import is not applyable from status "+status)
		return
	}

	applied, rollback, err := h.applyMigrationPolicies(r, tx, subj.OrgID, preview.Policies)
	if err != nil {
		_ = tx.Rollback(r.Context())
		_, _ = h.db.Pool().Exec(r.Context(), `UPDATE migration_imports SET status='failed', error=$3 WHERE id=$1 AND org_id=$2`, id, subj.OrgID, err.Error())
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"source": source, "reason": "apply_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	groupApplied, groupRollback, err := h.applyMigrationGroups(r, tx, subj, preview.Groups)
	if err != nil {
		_ = tx.Rollback(r.Context())
		_, _ = h.db.Pool().Exec(r.Context(), `UPDATE migration_imports SET status='failed', error=$3 WHERE id=$1 AND org_id=$2`, id, subj.OrgID, err.Error())
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"source": source, "reason": "apply_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mergeAppliedCounts(applied, groupApplied)
	processProfileApplied, processProfileRollback, err := h.applyMigrationProcessProfiles(r, tx, subj, preview.ProcessProfiles)
	if err != nil {
		_ = tx.Rollback(r.Context())
		_, _ = h.db.Pool().Exec(r.Context(), `UPDATE migration_imports SET status='failed', error=$3 WHERE id=$1 AND org_id=$2`, id, subj.OrgID, err.Error())
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"source": source, "reason": "apply_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mergeAppliedCounts(applied, processProfileApplied)
	fileProfileApplied, fileProfileRollback, err := h.applyMigrationFileProfiles(r, tx, subj, preview.FileProfiles)
	if err != nil {
		_ = tx.Rollback(r.Context())
		_, _ = h.db.Pool().Exec(r.Context(), `UPDATE migration_imports SET status='failed', error=$3 WHERE id=$1 AND org_id=$2`, id, subj.OrgID, err.Error())
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"source": source, "reason": "apply_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mergeAppliedCounts(applied, fileProfileApplied)
	networkApplied, networkRollback, err := h.applyMigrationNetworkRules(r, tx, subj, preview.NetworkRules)
	if err != nil {
		_ = tx.Rollback(r.Context())
		_, _ = h.db.Pool().Exec(r.Context(), `UPDATE migration_imports SET status='failed', error=$3 WHERE id=$1 AND org_id=$2`, id, subj.OrgID, err.Error())
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"source": source, "reason": "apply_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mergeAppliedCounts(applied, networkApplied)
	dpiApplied, dpiRollback, err := h.applyMigrationDPIRules(r, tx, subj, preview.DPIRules)
	if err != nil {
		_ = tx.Rollback(r.Context())
		_, _ = h.db.Pool().Exec(r.Context(), `UPDATE migration_imports SET status='failed', error=$3 WHERE id=$1 AND org_id=$2`, id, subj.OrgID, err.Error())
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"source": source, "reason": "apply_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mergeAppliedCounts(applied, dpiApplied)
	bindingApplied, bindingRollback, err := h.applyMigrationDPIBindings(r, tx, subj, preview.DPIBindings)
	if err != nil {
		_ = tx.Rollback(r.Context())
		_, _ = h.db.Pool().Exec(r.Context(), `UPDATE migration_imports SET status='failed', error=$3 WHERE id=$1 AND org_id=$2`, id, subj.OrgID, err.Error())
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"source": source, "reason": "apply_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mergeAppliedCounts(applied, bindingApplied)
	unsupported := preview.Unsupported
	if len(unsupported) == 0 {
		unresolvedFileProfiles := make([]migrationPreviewFileProfileDTO, 0)
		for _, profile := range preview.FileProfiles {
			if strings.TrimSpace(profile.ClusterID) == "" {
				unresolvedFileProfiles = append(unresolvedFileProfiles, profile)
			}
		}
		unsupported = migrationUnsupportedFromPreview(unresolvedFileProfiles, "", nil)
	}
	newStatus := "applied"
	if len(unsupported) > 0 {
		newStatus = "partial_applied"
	}
	appliedRaw, _ := json.Marshal(applied)
	rollbackRaw, _ := json.Marshal(map[string]any{"source": source, "generated_at": time.Now().UTC().Format(time.RFC3339), "policies": rollback, "groups": groupRollback, "file_profiles": fileProfileRollback, "process_profiles": processProfileRollback, "network_rules": networkRollback, "dpi_rules": dpiRollback, "dpi_bindings": bindingRollback})
	unsupportedRaw, _ := json.Marshal(unsupported)
	if _, err := tx.Exec(r.Context(), `
UPDATE migration_imports
   SET status=$3, applied_json=$4, rollback_json=$5, unsupported_json=$6,
       applied_by=$7, applied_at=NOW(), error=''
WHERE id=$1 AND org_id=$2`,
		id, subj.OrgID, newStatus, appliedRaw, rollbackRaw, unsupportedRaw, subj.UserID); err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"source": source, "reason": "status_update_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.auditMigration(r, subj, "migration.import.apply.failed", id.String(), map[string]any{"source": source, "reason": "commit_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditMigration(r, subj, "migration.import.apply", id.String(), map[string]any{"source": source, "status": newStatus, "applied": applied, "unsupported": unsupported})
	writeJSON(w, http.StatusOK, map[string]any{"id": id.String(), "status": newStatus, "applied": applied, "unsupported": unsupported})
}

func (h *Enterprise) MigrationRollback(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	if !h.authorizeMigrationMutation(r, subj) {
		h.auditMigration(r, subj, "migration.import.rollback.failed", chi.URLParam(r, "id"), map[string]any{"reason": "forbidden", "verb": string(rbac.VerbManagePolicies)})
		jsonError(w, http.StatusForbidden, "forbidden: "+string(rbac.VerbManagePolicies))
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.auditMigration(r, subj, "migration.import.rollback.failed", chi.URLParam(r, "id"), map[string]any{"reason": "bad_import_id", "error": err.Error()})
		jsonError(w, http.StatusBadRequest, "bad import id")
		return
	}
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	var source string
	var status string
	var rollbackRaw json.RawMessage
	if err := tx.QueryRow(r.Context(), `
SELECT source, status, rollback_json
  FROM migration_imports
 WHERE id=$1 AND org_id=$2
 FOR UPDATE`, id, subj.OrgID).Scan(&source, &status, &rollbackRaw); err != nil {
		if err == pgx.ErrNoRows {
			h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"reason": "not_found"})
			jsonError(w, http.StatusNotFound, "migration import not found")
			return
		}
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"reason": "load_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if status != "applied" && status != "partial_applied" {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.skipped", id.String(), map[string]any{"source": source, "reason": "not_rollbackable", "status": status})
		jsonError(w, http.StatusConflict, "migration import is not rollbackable from status "+status)
		return
	}
	var rollback struct {
		Policies        []migrationPolicyRollbackDTO         `json:"policies"`
		Groups          []migrationGroupRollbackDTO          `json:"groups"`
		FileProfiles    []migrationFileProfileRollbackDTO    `json:"file_profiles"`
		ProcessProfiles []migrationProcessProfileRollbackDTO `json:"process_profiles"`
		NetworkRules    []migrationNetworkRuleRollbackDTO    `json:"network_rules"`
		DPIRules        []migrationDPIRuleRollbackDTO        `json:"dpi_rules"`
		DPIBindings     []migrationDPIBindingRollbackDTO     `json:"dpi_bindings"`
	}
	if err := json.Unmarshal(rollbackRaw, &rollback); err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "invalid_rollback_bundle", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, "rollback bundle is invalid")
		return
	}
	restored, deleted, err := h.rollbackMigrationPolicies(r, tx, subj.OrgID, rollback.Policies)
	if err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "rollback_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dpiRestored, dpiDeleted, err := h.rollbackMigrationDPIRules(r, tx, subj.OrgID, rollback.DPIRules)
	if err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "rollback_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	restored += dpiRestored
	deleted += dpiDeleted
	bindingRestored, bindingDeleted, err := h.rollbackMigrationDPIBindings(r, tx, subj.OrgID, rollback.DPIBindings)
	if err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "rollback_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	restored += bindingRestored
	deleted += bindingDeleted
	networkRestored, networkDeleted, err := h.rollbackMigrationNetworkRules(r, tx, subj.OrgID, rollback.NetworkRules)
	if err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "rollback_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	restored += networkRestored
	deleted += networkDeleted
	fileProfileRestored, fileProfileDeleted, err := h.rollbackMigrationFileProfiles(r, tx, subj.OrgID, rollback.FileProfiles)
	if err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "rollback_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	restored += fileProfileRestored
	deleted += fileProfileDeleted
	processProfileRestored, processProfileDeleted, err := h.rollbackMigrationProcessProfiles(r, tx, subj.OrgID, rollback.ProcessProfiles)
	if err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "rollback_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	restored += processProfileRestored
	deleted += processProfileDeleted
	groupRestored, groupDeleted, err := h.rollbackMigrationGroups(r, tx, subj.OrgID, rollback.Groups)
	if err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "rollback_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	restored += groupRestored
	deleted += groupDeleted
	if _, err := tx.Exec(r.Context(), `
UPDATE migration_imports
   SET status='rolled_back', rolled_back_by=$3, rolled_back_at=NOW()
 WHERE id=$1 AND org_id=$2`, id, subj.OrgID, subj.UserID); err != nil {
		_ = tx.Rollback(r.Context())
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "status_update_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.auditMigration(r, subj, "migration.import.rollback.failed", id.String(), map[string]any{"source": source, "reason": "commit_failed", "error": err.Error()})
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditMigration(r, subj, "migration.import.rollback", id.String(), map[string]any{"source": source, "restored": restored, "deleted": deleted})
	writeJSON(w, http.StatusOK, map[string]any{"id": id.String(), "status": "rolled_back", "restored": restored, "deleted": deleted})
}

func (h *Enterprise) authorizeMigrationMutation(r *http.Request, subj Subject) bool {
	if !subj.HasTokenScope(rbac.VerbManagePolicies) {
		return false
	}
	var custom map[string][]rbac.Verb
	if h != nil && h.customRoles != nil {
		custom = h.customRoles.VerbsForOrg(r.Context(), subj.OrgID)
	}
	return rbac.AuthorizeWithCustom(subj.Assignments, rbac.VerbManagePolicies, rbac.Resource{OrgID: subj.OrgID}, custom) == nil
}

func migrationRollbackBundleFilename(source string, id uuid.UUID) string {
	slug := strings.ToLower(strings.TrimSpace(source))
	slug = migrationRollbackFilenameUnsafe.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-._")
	if slug == "" {
		slug = "migration"
	}
	return fmt.Sprintf("constellation-%s-rollback-%s.json", slug, id.String())
}

func convertMigrationPreview(source string, raw []byte) ([]migrationPreviewPolicyDTO, error) {
	switch source {
	case "stackrox", "rhacs":
		items, err := stackrox.Convert(raw)
		if err != nil {
			return nil, err
		}
		out := make([]migrationPreviewPolicyDTO, 0, len(items))
		for _, item := range items {
			out = append(out, migrationPreviewPolicyDTO{
				Name: item.Name, Description: item.Description, Engine: item.Engine, Category: item.Category,
				Enabled: item.Enabled, Mode: item.Mode, SpecYAML: item.SpecYAML, Imported: item.Imported,
			})
		}
		return out, nil
	case "neuvector":
		items, err := neuvector.Convert(raw)
		if err != nil {
			return nil, err
		}
		out := make([]migrationPreviewPolicyDTO, 0, len(items))
		for _, item := range items {
			out = append(out, migrationPreviewPolicyDTO{
				Name: item.Name, Description: item.Description, Engine: item.Engine, Category: item.Category,
				Enabled: item.Enabled, Mode: item.Mode, SpecYAML: item.SpecYAML, Imported: item.Imported,
			})
		}
		return out, nil
	case "aqua":
		items, err := aqua.Convert(raw)
		if err != nil {
			return nil, err
		}
		out := make([]migrationPreviewPolicyDTO, 0, len(items))
		for _, item := range items {
			out = append(out, migrationPreviewPolicyDTO{
				Name: item.Name, Description: item.Description, Engine: item.Engine, Category: item.Category,
				Enabled: item.Enabled, Mode: item.Mode, SpecYAML: item.SpecYAML, Imported: item.Imported,
			})
		}
		return out, nil
	case "prisma":
		items, err := prisma.Convert(raw)
		if err != nil {
			return nil, err
		}
		out := make([]migrationPreviewPolicyDTO, 0, len(items))
		for _, item := range items {
			out = append(out, migrationPreviewPolicyDTO{
				Name: item.Name, Description: item.Description, Engine: item.Engine, Category: item.Category,
				Enabled: item.Enabled, Mode: item.Mode, SpecYAML: item.SpecYAML, Imported: item.Imported,
			})
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported migration source %q", source)
	}
}

func convertMigrationFileProfiles(source string, raw []byte) ([]migrationPreviewFileProfileDTO, error) {
	if source != "neuvector" {
		return []migrationPreviewFileProfileDTO{}, nil
	}
	items, err := neuvector.ConvertFileProfiles(raw)
	if err != nil {
		return nil, err
	}
	out := make([]migrationPreviewFileProfileDTO, 0, len(items))
	for _, item := range items {
		rules := make([]fileProfilePortableRuleDTO, 0, len(item.Rules))
		for _, rule := range item.Rules {
			rules = append(rules, fileProfilePortableRuleDTO{
				Filter:       rule.Filter,
				Recursive:    rule.Recursive,
				Behavior:     rule.Behavior,
				Applications: nonNilStrings(rule.Applications),
				Enabled:      boolPtr(rule.Enabled),
				SourceGroup:  rule.SourceGroup,
				CfgType:      rule.CfgType,
			})
		}
		out = append(out, migrationPreviewFileProfileDTO{
			Group:       item.Group,
			Mode:        item.Mode,
			CfgType:     item.CfgType,
			Description: item.Description,
			Rules:       rules,
			Imported:    item.Imported,
			DiffAction:  "create",
		})
	}
	return out, nil
}

func convertMigrationProcessProfiles(source string, raw []byte) ([]migrationPreviewProcessProfileDTO, []migrationUnsupportedDTO, error) {
	if source != "neuvector" {
		return []migrationPreviewProcessProfileDTO{}, []migrationUnsupportedDTO{}, nil
	}
	items, unsupported, err := neuvector.ConvertProcessProfiles(raw)
	if err != nil {
		return nil, nil, err
	}
	out := make([]migrationPreviewProcessProfileDTO, 0, len(items))
	for _, item := range items {
		rules := make([]migrationProcessRuleDTO, 0, len(item.Rules))
		for _, rule := range item.Rules {
			rules = append(rules, migrationProcessRuleDTO{
				Name:        rule.Name,
				Path:        rule.Path,
				User:        rule.User,
				SHA256:      rule.SHA256,
				ParentName:  rule.ParentName,
				Action:      rule.Action,
				CfgType:     rule.CfgType,
				UUID:        rule.UUID,
				AllowUpdate: rule.AllowUpdate,
				Enabled:     rule.Enabled,
				Description: rule.Description,
			})
		}
		out = append(out, migrationPreviewProcessProfileDTO{
			Group:       item.Group,
			Mode:        item.Mode,
			Baseline:    item.Baseline,
			CfgType:     item.CfgType,
			Description: item.Description,
			Rules:       rules,
			Imported:    item.Imported,
			DiffAction:  "create",
		})
	}
	unsupportedOut := make([]migrationUnsupportedDTO, 0, len(unsupported))
	for _, item := range unsupported {
		unsupportedOut = append(unsupportedOut, migrationUnsupportedDTO{
			Kind:       item.Kind,
			Name:       item.Name,
			Reason:     item.Reason,
			Suggestion: item.Suggestion,
			Source:     item.Source,
		})
	}
	return out, unsupportedOut, nil
}

func convertMigrationGroups(source string, raw []byte) ([]migrationPreviewGroupDTO, []migrationUnsupportedDTO, error) {
	if source != "neuvector" {
		return []migrationPreviewGroupDTO{}, []migrationUnsupportedDTO{}, nil
	}
	items, unsupported, err := neuvector.ConvertGroups(raw)
	if err != nil {
		return nil, nil, err
	}
	out := make([]migrationPreviewGroupDTO, 0, len(items))
	for _, item := range items {
		criteria := make([]portableGroupCriterion, 0, len(item.Criteria))
		for _, criterion := range item.Criteria {
			criteria = append(criteria, portableGroupCriterion{
				Key:   criterion.Key,
				Op:    criterion.Op,
				Value: criterion.Value,
			})
		}
		out = append(out, migrationPreviewGroupDTO{
			Name:        item.Name,
			Kind:        item.Kind,
			Comment:     item.Comment,
			CfgType:     item.CfgType,
			PolicyMode:  item.PolicyMode,
			ProfileMode: item.ProfileMode,
			Criteria:    criteria,
			Imported:    item.Imported,
			DiffAction:  "create",
		})
	}
	unsupportedOut := make([]migrationUnsupportedDTO, 0, len(unsupported))
	for _, item := range unsupported {
		unsupportedOut = append(unsupportedOut, migrationUnsupportedDTO{
			Kind:       item.Kind,
			Name:       item.Name,
			Reason:     item.Reason,
			Suggestion: item.Suggestion,
			Source:     item.Source,
		})
	}
	return out, unsupportedOut, nil
}

func convertMigrationDPIRules(source string, raw []byte) ([]migrationPreviewDPIRuleDTO, []migrationPreviewDPIBindingDTO, []migrationUnsupportedDTO, error) {
	if source != "neuvector" {
		return []migrationPreviewDPIRuleDTO{}, []migrationPreviewDPIBindingDTO{}, []migrationUnsupportedDTO{}, nil
	}
	items, bindings, unsupported, err := neuvector.ConvertDPIRules(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	out := make([]migrationPreviewDPIRuleDTO, 0, len(items))
	for _, item := range items {
		patterns := make([]migrationDPIPatternDTO, 0, len(item.Patterns))
		for _, pattern := range item.Patterns {
			patterns = append(patterns, migrationDPIPatternDTO{
				Pattern: pattern.Pattern,
				Op:      pattern.Op,
				Context: pattern.Context,
			})
		}
		out = append(out, migrationPreviewDPIRuleDTO{
			Name:              item.Name,
			Category:          item.Category,
			ApplyDir:          item.ApplyDir,
			Severity:          item.Severity,
			Mode:              item.Mode,
			Patterns:          patterns,
			Description:       item.Description,
			SourceSensor:      item.SourceSensor,
			SourceGroups:      item.SourceGroups,
			SourcePath:        item.SourcePath,
			SourceCfgType:     item.SourceCfgType,
			SourceRuleCfgType: item.SourceRuleCfgType,
			Federated:         item.Federated,
			Imported:          item.Imported,
			DiffAction:        "create",
		})
	}
	bindingOut := make([]migrationPreviewDPIBindingDTO, 0, len(bindings))
	for _, item := range bindings {
		bindingOut = append(bindingOut, migrationPreviewDPIBindingDTO{
			SourceGroup:   item.SourceGroup,
			SensorKind:    item.SensorKind,
			SourceSensors: item.SourceSensors,
			Imported:      item.Imported,
			DiffAction:    "create",
		})
	}
	unsupportedOut := make([]migrationUnsupportedDTO, 0, len(unsupported))
	for _, item := range unsupported {
		unsupportedOut = append(unsupportedOut, migrationUnsupportedDTO{
			Kind:       item.Kind,
			Name:       item.Name,
			Reason:     item.Reason,
			Suggestion: item.Suggestion,
			Source:     item.Source,
		})
	}
	return out, bindingOut, unsupportedOut, nil
}

func convertMigrationNetworkRules(source string, raw []byte) ([]migrationPreviewNetworkRuleDTO, []migrationUnsupportedDTO, error) {
	if source != "neuvector" {
		return []migrationPreviewNetworkRuleDTO{}, []migrationUnsupportedDTO{}, nil
	}
	items, unsupported, err := neuvector.ConvertNetworkRules(raw)
	if err != nil {
		return nil, nil, err
	}
	out := make([]migrationPreviewNetworkRuleDTO, 0, len(items))
	for _, item := range items {
		ports := make([]migrationNetworkPortDTO, 0, len(item.Ports))
		for _, port := range item.Ports {
			ports = append(ports, migrationNetworkPortDTO{
				Protocol: port.Protocol,
				Port:     port.Port,
			})
		}
		out = append(out, migrationPreviewNetworkRuleDTO{
			Name:       item.Name,
			FromGroup:  item.FromGroup,
			ToGroup:    item.ToGroup,
			Ports:      ports,
			Mode:       item.Mode,
			Comment:    item.Comment,
			Priority:   item.Priority,
			Imported:   item.Imported,
			DiffAction: "create",
		})
	}
	unsupportedOut := make([]migrationUnsupportedDTO, 0, len(unsupported))
	for _, item := range unsupported {
		unsupportedOut = append(unsupportedOut, migrationUnsupportedDTO{
			Kind:       item.Kind,
			Name:       item.Name,
			Reason:     item.Reason,
			Suggestion: item.Suggestion,
			Source:     item.Source,
		})
	}
	return out, unsupportedOut, nil
}

func (h *Enterprise) existingPolicyNames(r *http.Request, orgID string) (map[string]bool, error) {
	out := map[string]bool{}
	if h == nil || h.db == nil || orgID == "" {
		return out, nil
	}
	rows, err := h.db.Pool().Query(r.Context(), `SELECT DISTINCT name FROM policies WHERE org_id = $1`, orgID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return out, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func (h *Enterprise) existingDPIRuleNames(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID) (map[string]bool, error) {
	out := map[string]bool{}
	if h == nil || h.db == nil || orgID == uuid.Nil || clusterID == uuid.Nil {
		return out, nil
	}
	rows, err := h.db.Pool().Query(r.Context(), `SELECT DISTINCT name FROM runtime_dlp_rules WHERE org_id = $1 AND cluster_id = $2`, orgID, clusterID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return out, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func (h *Enterprise) existingMigrationGroupNames(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID) (map[string]bool, error) {
	out := map[string]bool{}
	if h == nil || h.db == nil || orgID == uuid.Nil {
		return out, nil
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT DISTINCT name
  FROM groups
 WHERE org_id = $1`, orgID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return out, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func (h *Enterprise) existingMigrationNetworkEdgeKeys(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID) (map[string]bool, error) {
	out := map[string]bool{}
	if h == nil || h.db == nil || orgID == uuid.Nil || clusterID == uuid.Nil {
		return out, nil
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT from_group, to_group
  FROM group_rule_edges
 WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			return out, err
		}
		out[migrationNetworkRuleKey(from, to)] = true
	}
	return out, rows.Err()
}

func (h *Enterprise) migrationClusterExists(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID) (bool, error) {
	if h == nil || h.db == nil || orgID == uuid.Nil || clusterID == uuid.Nil {
		return false, nil
	}
	var exists bool
	err := h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, orgID, clusterID).Scan(&exists)
	return exists, err
}

func (h *Enterprise) resolveMigrationFileProfiles(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID, profiles []migrationPreviewFileProfileDTO, previewGroups []migrationPreviewGroupDTO) ([]migrationPreviewFileProfileDTO, []migrationUnsupportedDTO, error) {
	if len(profiles) == 0 {
		return []migrationPreviewFileProfileDTO{}, []migrationUnsupportedDTO{}, nil
	}
	previewMembers := map[string][]string{}
	for _, item := range previewGroups {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		criteria, err := migrationGroupCriteria(item.Criteria)
		if err != nil {
			continue
		}
		members, err := h.computeMigrationGroupMembersFromPool(r, orgID, clusterID, &group.Group{
			Name:     name,
			Kind:     group.Kind(normalizeMigrationGroupKind(item.Kind)),
			Criteria: criteria,
		})
		if err != nil {
			return nil, nil, err
		}
		previewMembers[name] = members
	}
	resolved := make([]migrationPreviewFileProfileDTO, 0, len(profiles))
	unsupported := []migrationUnsupportedDTO{}
	for _, profile := range profiles {
		groupName := strings.TrimSpace(profile.Group)
		if groupName == "" {
			unsupported = append(unsupported, migrationUnsupportedDTO{
				Kind:       "file_profile",
				Name:       "neuvector-file-profile",
				Reason:     "NeuVector file profile is missing a target group",
				Suggestion: "Add a group name to the NeuVector file profile export or import the profile manually for each target workload.",
			})
			continue
		}
		members, ok := previewMembers[groupName]
		if !ok {
			var found bool
			var err error
			members, found, err = h.migrationGroupMembers(r, orgID, clusterID, groupName)
			if err != nil {
				return nil, nil, err
			}
			if !found {
				unsupported = append(unsupported, migrationUnsupportedDTO{
					Kind:       "file_profile",
					Name:       groupName,
					Reason:     "NeuVector file profile references a group that does not exist in the target Constellation cluster",
					Suggestion: "Import or create the matching Constellation group, then rerun the migration preview.",
					Source:     map[string]any{"group": groupName, "rules": len(profile.Rules)},
				})
				continue
			}
		}
		members = normalizeMigrationWorkloadIDs(members)
		if len(members) == 0 {
			unsupported = append(unsupported, migrationUnsupportedDTO{
				Kind:       "file_profile",
				Name:       groupName,
				Reason:     "NeuVector file profile target group has no resolved workload members in the target cluster",
				Suggestion: "Wait for workload discovery or adjust the group selector, then rerun the migration preview.",
				Source:     map[string]any{"group": groupName, "rules": len(profile.Rules)},
			})
			continue
		}
		profile.ClusterID = clusterID.String()
		profile.TargetGroupName = groupName
		profile.TargetWorkloads = members
		profile.Mode = normalizeMigrationFileProfileMode(profile.Mode)
		profile.DiffAction = "create"
		resolved = append(resolved, profile)
	}
	return resolved, unsupported, nil
}

func (h *Enterprise) resolveMigrationProcessProfiles(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID, profiles []migrationPreviewProcessProfileDTO, previewGroups []migrationPreviewGroupDTO) ([]migrationPreviewProcessProfileDTO, []migrationUnsupportedDTO, error) {
	if len(profiles) == 0 {
		return []migrationPreviewProcessProfileDTO{}, []migrationUnsupportedDTO{}, nil
	}
	previewMembers := map[string][]string{}
	for _, item := range previewGroups {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		criteria, err := migrationGroupCriteria(item.Criteria)
		if err != nil {
			continue
		}
		members, err := h.computeMigrationGroupMembersFromPool(r, orgID, clusterID, &group.Group{
			Name:     name,
			Kind:     group.Kind(normalizeMigrationGroupKind(item.Kind)),
			Criteria: criteria,
		})
		if err != nil {
			return nil, nil, err
		}
		previewMembers[name] = members
	}
	resolved := make([]migrationPreviewProcessProfileDTO, 0, len(profiles))
	unsupported := []migrationUnsupportedDTO{}
	for _, profile := range profiles {
		groupName := strings.TrimSpace(profile.Group)
		if groupName == "" {
			unsupported = append(unsupported, migrationUnsupportedDTO{
				Kind:       "process_profile",
				Name:       "neuvector-process-profile",
				Reason:     "NeuVector process profile is missing a target group",
				Suggestion: "Add a group name to the NeuVector process profile export or import the profile manually for each target workload.",
			})
			continue
		}
		members, ok := previewMembers[groupName]
		if !ok {
			var found bool
			var err error
			members, found, err = h.migrationGroupMembers(r, orgID, clusterID, groupName)
			if err != nil {
				return nil, nil, err
			}
			if !found {
				unsupported = append(unsupported, migrationUnsupportedDTO{
					Kind:       "process_profile",
					Name:       groupName,
					Reason:     "NeuVector process profile references a group that does not exist in the target Constellation cluster",
					Suggestion: "Import or create the matching Constellation group, then rerun the migration preview.",
					Source:     map[string]any{"group": groupName, "rules": len(profile.Rules), "mode": profile.Mode, "baseline": profile.Baseline},
				})
				continue
			}
		}
		members = normalizeMigrationWorkloadIDs(members)
		if len(members) == 0 {
			unsupported = append(unsupported, migrationUnsupportedDTO{
				Kind:       "process_profile",
				Name:       groupName,
				Reason:     "NeuVector process profile target group has no resolved workload members in the target cluster",
				Suggestion: "Wait for workload discovery or adjust the group selector, then rerun the migration preview.",
				Source:     map[string]any{"group": groupName, "rules": len(profile.Rules), "mode": profile.Mode, "baseline": profile.Baseline},
			})
			continue
		}
		profile.ClusterID = clusterID.String()
		profile.TargetGroupName = groupName
		profile.TargetWorkloads = members
		profile.Mode = normalizeMigrationProcessProfileMode(profile.Mode)
		profile.DiffAction = "create"
		resolved = append(resolved, profile)
	}
	return resolved, unsupported, nil
}

func (h *Enterprise) resolveMigrationNetworkRules(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID, rules []migrationPreviewNetworkRuleDTO, previewGroups []migrationPreviewGroupDTO) ([]migrationPreviewNetworkRuleDTO, []migrationUnsupportedDTO, error) {
	if len(rules) == 0 {
		return []migrationPreviewNetworkRuleDTO{}, []migrationUnsupportedDTO{}, nil
	}
	previewGroupNames := map[string]bool{}
	for _, group := range previewGroups {
		if name := strings.TrimSpace(group.Name); name != "" {
			previewGroupNames[name] = true
		}
	}
	resolved := make([]migrationPreviewNetworkRuleDTO, 0, len(rules))
	unsupported := []migrationUnsupportedDTO{}
	for _, rule := range rules {
		rule.FromGroup = strings.TrimSpace(rule.FromGroup)
		rule.ToGroup = strings.TrimSpace(rule.ToGroup)
		rule.Mode = normalizeMigrationNetworkMode(rule.Mode)
		if rule.FromGroup == "" || rule.ToGroup == "" {
			unsupported = append(unsupported, migrationUnsupportedDTO{
				Kind:       "network_rule",
				Name:       rule.Name,
				Reason:     "NeuVector network rule is missing a source or destination group",
				Suggestion: "Create matching source and destination groups in Constellation, then rerun the migration preview.",
				Source:     map[string]any{"from_group": rule.FromGroup, "to_group": rule.ToGroup},
			})
			continue
		}
		missing := []string{}
		for _, groupName := range []string{rule.FromGroup, rule.ToGroup} {
			if previewGroupNames[groupName] {
				continue
			}
			_, _, found, err := h.findMigrationTargetGroup(r, orgID, clusterID, groupName)
			if err != nil {
				return nil, nil, err
			}
			if !found {
				missing = append(missing, groupName)
			}
		}
		if len(missing) > 0 {
			unsupported = append(unsupported, migrationUnsupportedDTO{
				Kind:       "network_rule",
				Name:       rule.Name,
				Reason:     "NeuVector network rule references groups that do not exist in the target Constellation cluster",
				Suggestion: "Import or create the missing groups, then rerun the migration preview before applying network edges.",
				Source: map[string]any{
					"from_group":     rule.FromGroup,
					"to_group":       rule.ToGroup,
					"missing_groups": missing,
				},
			})
			continue
		}
		resolved = append(resolved, rule)
	}
	sort.SliceStable(resolved, func(i, j int) bool {
		if resolved[i].Priority != resolved[j].Priority {
			return resolved[i].Priority < resolved[j].Priority
		}
		if resolved[i].FromGroup != resolved[j].FromGroup {
			return resolved[i].FromGroup < resolved[j].FromGroup
		}
		return resolved[i].ToGroup < resolved[j].ToGroup
	})
	return resolved, unsupported, nil
}

func (h *Enterprise) resolveMigrationDPIBindings(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID, bindings []migrationPreviewDPIBindingDTO, previewGroups []migrationPreviewGroupDTO) ([]migrationPreviewDPIBindingDTO, []migrationUnsupportedDTO, error) {
	if len(bindings) == 0 {
		return []migrationPreviewDPIBindingDTO{}, []migrationUnsupportedDTO{}, nil
	}
	previewGroupNames := map[string]string{}
	for _, group := range previewGroups {
		if name := strings.TrimSpace(group.Name); name != "" {
			previewGroupNames[name] = name
		}
	}
	resolved := make([]migrationPreviewDPIBindingDTO, 0, len(bindings))
	unsupported := make([]migrationUnsupportedDTO, 0)
	for _, binding := range bindings {
		kind, err := normalizeMigrationDPISensorKind(binding.SensorKind)
		if err != nil {
			unsupported = append(unsupported, migrationUnsupportedDTO{
				Kind:       "dpi_group_scope",
				Name:       binding.SourceGroup,
				Reason:     err.Error(),
				Suggestion: "Review the NeuVector DLP/WAF group export and retry with sensor_kind dlp or waf.",
				Source:     map[string]any{"group": binding.SourceGroup, "sensor_kind": binding.SensorKind},
			})
			continue
		}
		targetID, targetName, found, err := h.findMigrationTargetGroup(r, orgID, clusterID, binding.SourceGroup)
		if err != nil {
			return nil, nil, err
		}
		if !found {
			if previewName, ok := previewGroupNames[strings.TrimSpace(binding.SourceGroup)]; ok {
				binding.SensorKind = kind
				binding.TargetGroupID = ""
				binding.TargetGroupName = previewName
				binding.DiffAction = "create"
				resolved = append(resolved, binding)
				continue
			}
			unsupported = append(unsupported, migrationUnsupportedDTO{
				Kind:       kind + "_group_scope",
				Name:       binding.SourceGroup,
				Reason:     "NeuVector " + strings.ToUpper(kind) + " group-to-sensor scope references a group that does not exist in the target Constellation cluster",
				Suggestion: "Import or create the matching Constellation group, then rerun the migration preview or bind the group from the DLP/WAF group scope panel.",
				Source: map[string]any{
					"group":          binding.SourceGroup,
					"sensor_kind":    kind,
					"source_sensors": binding.SourceSensors,
				},
			})
			continue
		}
		exists, err := h.migrationDPIBindingExists(r, orgID, targetID, kind)
		if err != nil {
			return nil, nil, err
		}
		binding.SensorKind = kind
		binding.TargetGroupID = targetID.String()
		binding.TargetGroupName = targetName
		if exists {
			binding.DiffAction = "update"
		} else {
			binding.DiffAction = "create"
		}
		resolved = append(resolved, binding)
	}
	sort.SliceStable(resolved, func(i, j int) bool {
		if resolved[i].SensorKind != resolved[j].SensorKind {
			return resolved[i].SensorKind < resolved[j].SensorKind
		}
		return resolved[i].TargetGroupName < resolved[j].TargetGroupName
	})
	return resolved, unsupported, nil
}

func (h *Enterprise) findMigrationTargetGroup(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID, sourceGroup string) (uuid.UUID, string, bool, error) {
	name := strings.TrimSpace(sourceGroup)
	if h == nil || h.db == nil || name == "" {
		return uuid.Nil, "", false, nil
	}
	var id uuid.UUID
	var targetName string
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id, name
  FROM groups
 WHERE org_id=$1
   AND name=$2
   AND (cluster_id IS NULL OR cluster_id=$3)
 ORDER BY CASE WHEN cluster_id=$3 THEN 0 ELSE 1 END, updated_at DESC
 LIMIT 1`, orgID, name, clusterID).Scan(&id, &targetName)
	if err == pgx.ErrNoRows {
		return uuid.Nil, "", false, nil
	}
	if err != nil {
		return uuid.Nil, "", false, err
	}
	return id, targetName, true, nil
}

func (h *Enterprise) migrationDPIBindingExists(r *http.Request, orgID uuid.UUID, groupID uuid.UUID, sensorKind string) (bool, error) {
	if h == nil || h.db == nil || orgID == uuid.Nil || groupID == uuid.Nil {
		return false, nil
	}
	var exists bool
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT EXISTS(
  SELECT 1
    FROM group_dpi_sensor_bindings
   WHERE org_id=$1 AND group_id=$2 AND sensor_kind=$3
)`, orgID, groupID, sensorKind).Scan(&exists)
	return exists, err
}

func countMigrationSourceObjects(source string, raw []byte) (map[string]int, error) {
	switch source {
	case "neuvector":
		counts, err := neuvector.CountSourceObjects(raw)
		if err != nil {
			return nil, err
		}
		return counts.Map(), nil
	default:
		return nil, nil
	}
}

func summarizeMigrationPreview(source string, sourceCounts map[string]int, policies []migrationPreviewPolicyDTO, fileProfiles []migrationPreviewFileProfileDTO, processProfiles []migrationPreviewProcessProfileDTO, groups []migrationPreviewGroupDTO, dpiRules []migrationPreviewDPIRuleDTO, dpiBindings []migrationPreviewDPIBindingDTO, networkRules []migrationPreviewNetworkRuleDTO) migrationPreviewSummaryDTO {
	summary := migrationPreviewSummaryDTO{
		Source:          source,
		Total:           len(policies) + len(fileProfiles) + len(processProfiles) + len(groups) + len(dpiRules) + len(dpiBindings) + len(networkRules),
		SourceCounts:    sourceCounts,
		FileProfiles:    len(fileProfiles),
		ProcessProfiles: len(processProfiles),
		Groups:          len(groups),
		DPIRules:        len(dpiRules),
		DPIBindings:     len(dpiBindings),
		NetworkRules:    len(networkRules),
		Engines:         map[string]int{},
		Categories:      map[string]int{},
		ReadOnly:        true,
		RollbackHint:    "Preview only. Apply will require an audited rollback bundle before persistence.",
	}
	for _, count := range sourceCounts {
		summary.SourceTotal += count
	}
	summary.SourceTotal -= sourceCounts["admission_rules"]
	summary.SourceTotal -= sourceCounts["response_rules"]
	for _, policy := range policies {
		switch policy.DiffAction {
		case "update":
			summary.Update++
		default:
			summary.Create++
		}
		if policy.Mode == "enforce" {
			summary.Enforce++
		} else {
			summary.Monitor++
		}
		if policy.Enabled {
			summary.Enabled++
		}
		summary.Engines[policy.Engine]++
		summary.Categories[policy.Category]++
	}
	for _, profile := range fileProfiles {
		switch profile.DiffAction {
		case "update":
			summary.Update++
		default:
			summary.Create++
		}
		if profile.Mode == "enforce" {
			summary.Enforce++
		} else {
			summary.Monitor++
		}
		for _, rule := range profile.Rules {
			if rule.Enabled != nil && *rule.Enabled {
				summary.Enabled++
				break
			}
		}
		summary.Engines["constellation-file-monitor"]++
		summary.Categories["file-profile"]++
	}
	for _, profile := range processProfiles {
		switch profile.DiffAction {
		case "update":
			summary.Update++
		default:
			summary.Create++
		}
		if profile.Mode == "enforce" {
			summary.Enforce++
		} else {
			summary.Monitor++
		}
		if len(profile.Rules) == 0 {
			summary.Enabled++
		} else {
			for _, rule := range profile.Rules {
				if rule.Enabled {
					summary.Enabled++
					break
				}
			}
		}
		summary.Engines["process-baseline"]++
		summary.Categories["process-profile"]++
	}
	for _, group := range groups {
		switch group.DiffAction {
		case "update":
			summary.Update++
		default:
			summary.Create++
		}
		if group.PolicyMode == "protect" || group.ProfileMode == "protect" {
			summary.Enforce++
		} else {
			summary.Monitor++
		}
		summary.Enabled++
		summary.Engines["groups"]++
		summary.Categories["group"]++
	}
	for _, rule := range dpiRules {
		switch rule.DiffAction {
		case "update":
			summary.Update++
		default:
			summary.Create++
		}
		if rule.Mode == "enforce" {
			summary.Enforce++
		} else {
			summary.Monitor++
		}
		if rule.Mode != "disabled" {
			summary.Enabled++
		}
		summary.Engines["runtime-dpi"]++
		summary.Categories[rule.Category]++
	}
	for _, binding := range dpiBindings {
		switch binding.DiffAction {
		case "update":
			summary.Update++
		default:
			summary.Create++
		}
		summary.Enabled++
		summary.Engines["runtime-dpi"]++
		summary.Categories[binding.SensorKind+"_group_scope"]++
	}
	for _, rule := range networkRules {
		switch rule.DiffAction {
		case "update":
			summary.Update++
		default:
			summary.Create++
		}
		if rule.Mode == "protect" {
			summary.Enforce++
		} else {
			summary.Monitor++
		}
		summary.Enabled++
		summary.Engines["group-network-policy"]++
		summary.Categories["network-rule"]++
	}
	return summary
}

func renderMigrationRollbackBundle(source string, policies []migrationPreviewPolicyDTO, fileProfiles []migrationPreviewFileProfileDTO, processProfiles []migrationPreviewProcessProfileDTO, groups []migrationPreviewGroupDTO, dpiRules []migrationPreviewDPIRuleDTO, dpiBindings []migrationPreviewDPIBindingDTO, networkRules []migrationPreviewNetworkRuleDTO) string {
	names := make([]string, 0, len(policies))
	for _, policy := range policies {
		names = append(names, policy.Name)
	}
	fileProfileGroups := make([]string, 0, len(fileProfiles))
	for _, profile := range fileProfiles {
		fileProfileGroups = append(fileProfileGroups, profile.Group)
	}
	processProfileGroups := make([]string, 0, len(processProfiles))
	for _, profile := range processProfiles {
		processProfileGroups = append(processProfileGroups, profile.Group)
	}
	groupNames := make([]string, 0, len(groups))
	for _, group := range groups {
		groupNames = append(groupNames, group.Name)
	}
	dpiNames := make([]string, 0, len(dpiRules))
	dpiClusters := map[string]bool{}
	for _, rule := range dpiRules {
		dpiNames = append(dpiNames, rule.Name)
		if rule.ClusterID != "" {
			dpiClusters[rule.ClusterID] = true
		}
	}
	clusterIDs := make([]string, 0, len(dpiClusters))
	for id := range dpiClusters {
		clusterIDs = append(clusterIDs, id)
	}
	sort.Strings(clusterIDs)
	dpiBindingGroups := make([]string, 0, len(dpiBindings))
	for _, binding := range dpiBindings {
		dpiBindingGroups = append(dpiBindingGroups, binding.TargetGroupName)
	}
	networkRuleEdges := make([]string, 0, len(networkRules))
	for _, rule := range networkRules {
		networkRuleEdges = append(networkRuleEdges, rule.FromGroup+" -> "+rule.ToGroup)
	}
	b, _ := json.MarshalIndent(map[string]any{
		"source":                 source,
		"generated_at":           time.Now().UTC().Format(time.RFC3339),
		"read_only":              true,
		"policy_names":           names,
		"file_profile_groups":    fileProfileGroups,
		"process_profile_groups": processProfileGroups,
		"group_names":            groupNames,
		"dpi_rule_names":         dpiNames,
		"dpi_rule_clusters":      clusterIDs,
		"dpi_binding_groups":     dpiBindingGroups,
		"network_rule_edges":     networkRuleEdges,
		"actions":                []string{"delete newly-created policies", "restore previous policy versions for updates", "delete newly-created groups", "restore previous group definitions for updates", "delete newly-created network rule edges", "restore previous network rule edges for updates", "delete newly-created DLP/WAF rules", "restore previous DLP/WAF rule versions for updates", "delete newly-created DLP/WAF group bindings", "restore previous file profile bundles for migrated groups", "restore previous process baseline rules for migrated groups"},
	}, "", "  ")
	return string(b)
}

func (h *Enterprise) persistMigrationPreview(r *http.Request, subj Subject, source string, raw []byte, preview migrationPreviewDTO) (uuid.UUID, error) {
	preview.ImportID = ""
	previewRaw, err := json.Marshal(preview)
	if err != nil {
		return uuid.Nil, err
	}
	unsupportedRaw, err := json.Marshal(preview.Unsupported)
	if err != nil {
		return uuid.Nil, err
	}
	sum := sha256.Sum256(raw)
	var id uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO migration_imports (org_id, source, source_hash, preview_json, unsupported_json, created_by)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id`, subj.OrgID, source, hex.EncodeToString(sum[:]), previewRaw, unsupportedRaw, subj.UserID).Scan(&id); err != nil {
		return uuid.Nil, err
	}
	h.auditMigration(r, subj, "migration.import.preview", id.String(), map[string]any{
		"source": source, "summary": preview.Summary, "unsupported": preview.Unsupported,
	})
	for _, unsupported := range preview.Unsupported {
		h.auditMigration(r, subj, "migration.import.skipped_object", id.String(), map[string]any{
			"source": source, "kind": unsupported.Kind, "name": unsupported.Name,
			"reason": unsupported.Reason, "suggestion": unsupported.Suggestion, "sample": unsupported.Source,
		})
	}
	return id, nil
}

func migrationUnsupportedFromPreview(fileProfiles []migrationPreviewFileProfileDTO, clusterID string, extra []migrationUnsupportedDTO) []migrationUnsupportedDTO {
	out := make([]migrationUnsupportedDTO, 0, len(fileProfiles)+len(extra))
	if strings.TrimSpace(clusterID) == "" {
		for _, profile := range fileProfiles {
			out = append(out, migrationUnsupportedDTO{
				Kind:       "file_profile",
				Name:       profile.Group,
				Reason:     "file profile apply requires a target cluster_id so the NeuVector group can resolve to Constellation workloads",
				Suggestion: "Select a target cluster, ensure the matching group has workload members, then rerun the migration preview.",
				Source: map[string]any{
					"group": profile.Group,
					"mode":  profile.Mode,
					"rules": len(profile.Rules),
				},
			})
		}
	}
	out = append(out, extra...)
	return out
}

func (h *Enterprise) loadMigrationImportForUpdate(r *http.Request, tx pgx.Tx, orgID uuid.UUID, id uuid.UUID) (string, string, migrationPreviewDTO, error) {
	var source, status string
	var previewRaw json.RawMessage
	if err := tx.QueryRow(r.Context(), `
SELECT source, status, preview_json
  FROM migration_imports
 WHERE id=$1 AND org_id=$2
 FOR UPDATE`, id, orgID).Scan(&source, &status, &previewRaw); err != nil {
		return "", "", migrationPreviewDTO{}, err
	}
	var preview migrationPreviewDTO
	if err := json.Unmarshal(previewRaw, &preview); err != nil {
		return "", "", migrationPreviewDTO{}, err
	}
	return source, status, preview, nil
}

func (h *Enterprise) applyMigrationPolicies(r *http.Request, tx pgx.Tx, orgID uuid.UUID, policies []migrationPreviewPolicyDTO) (map[string]int, []migrationPolicyRollbackDTO, error) {
	applied := map[string]int{"created": 0, "updated": 0, "policies": 0}
	rollback := make([]migrationPolicyRollbackDTO, 0, len(policies))
	for _, policy := range policies {
		before, exists, err := migrationPolicySnapshot(r, tx, orgID, policy.Name)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			if _, err := tx.Exec(r.Context(), `
UPDATE policies
   SET description=$3, engine=$4, category=$5, spec_yaml=$6, enabled=$7,
       mode=$8, source='declarative', cfg_type='user', updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`, before.ID, orgID, policy.Description, policy.Engine, policy.Category, policy.SpecYAML, policy.Enabled, normalizeMigrationMode(policy.Mode)); err != nil {
				return nil, nil, err
			}
			applied["updated"]++
			rollback = append(rollback, migrationPolicyRollbackDTO{Name: policy.Name, Action: "restore", ID: before.ID, Before: &before})
		} else {
			var id uuid.UUID
			if err := tx.QueryRow(r.Context(), `
INSERT INTO policies (org_id, name, description, engine, category, spec_yaml, enabled, mode, source, cfg_type)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'declarative','user')
RETURNING id`, orgID, policy.Name, policy.Description, policy.Engine, policy.Category, policy.SpecYAML, policy.Enabled, normalizeMigrationMode(policy.Mode)).Scan(&id); err != nil {
				return nil, nil, err
			}
			applied["created"]++
			rollback = append(rollback, migrationPolicyRollbackDTO{Name: policy.Name, Action: "delete", ID: id.String()})
		}
		applied["policies"]++
	}
	return applied, rollback, nil
}

func (h *Enterprise) applyMigrationGroups(r *http.Request, tx pgx.Tx, subj Subject, groups []migrationPreviewGroupDTO) (map[string]int, []migrationGroupRollbackDTO, error) {
	applied := map[string]int{"created": 0, "updated": 0, "groups": 0}
	rollback := make([]migrationGroupRollbackDTO, 0, len(groups))
	clusterCache := map[uuid.UUID]bool{}
	for _, item := range groups {
		clusterID, err := uuid.Parse(strings.TrimSpace(item.ClusterID))
		if err != nil {
			return nil, nil, fmt.Errorf("group %s is missing a valid target cluster_id", item.Name)
		}
		ok, cached := clusterCache[clusterID]
		if !cached {
			if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, subj.OrgID, clusterID).Scan(&ok); err != nil {
				return nil, nil, err
			}
			clusterCache[clusterID] = ok
		}
		if !ok {
			return nil, nil, fmt.Errorf("group %s targets a cluster outside this organization", item.Name)
		}
		criteria, err := migrationGroupCriteria(item.Criteria)
		if err != nil {
			return nil, nil, fmt.Errorf("group %s: %w", item.Name, err)
		}
		g := &group.Group{
			Name:        strings.TrimSpace(item.Name),
			Kind:        group.Kind(normalizeMigrationGroupKind(item.Kind)),
			Comment:     item.Comment,
			Criteria:    criteria,
			CfgType:     normalizeMigrationGroupCfgType(item.CfgType),
			PolicyMode:  group.Mode(normalizeMigrationGroupMode(item.PolicyMode)),
			ProfileMode: group.Mode(normalizeMigrationGroupMode(item.ProfileMode)),
		}
		if err := g.Validate(); err != nil {
			return nil, nil, err
		}
		members, err := migrationComputeGroupMembers(r, tx, subj.OrgID, clusterID, g)
		if err != nil {
			return nil, nil, err
		}
		criteriaJSON, _ := json.Marshal(g.Criteria)
		membersJSON, _ := json.Marshal(members)
		before, exists, err := migrationGroupSnapshot(r, tx, subj.OrgID, g.Name)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			if _, err := tx.Exec(r.Context(), `
UPDATE groups
   SET kind=$3, comment=$4, criteria=$5::jsonb, members=$6::jsonb,
       learned_from='', cfg_type=$7, policy_mode=$8, profile_mode=$9, updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`,
				before.ID, subj.OrgID, g.Kind, g.Comment, string(criteriaJSON), string(membersJSON), g.CfgType, g.PolicyMode, g.ProfileMode); err != nil {
				return nil, nil, err
			}
			applied["updated"]++
			rollback = append(rollback, migrationGroupRollbackDTO{Name: g.Name, Action: "restore", ID: before.ID, Before: &before})
		} else {
			var id uuid.UUID
			if err := tx.QueryRow(r.Context(), `
INSERT INTO groups (org_id, cluster_id, name, kind, comment, criteria, members, learned_from, cfg_type, policy_mode, profile_mode, created_by)
VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,'',$8,$9,$10,$11)
RETURNING id`, subj.OrgID, clusterID, g.Name, g.Kind, g.Comment, string(criteriaJSON), string(membersJSON), g.CfgType, g.PolicyMode, g.ProfileMode, subj.UserID).Scan(&id); err != nil {
				return nil, nil, err
			}
			applied["created"]++
			rollback = append(rollback, migrationGroupRollbackDTO{Name: g.Name, Action: "delete", ID: id.String()})
		}
		applied["groups"]++
	}
	return applied, rollback, nil
}

func (h *Enterprise) applyMigrationProcessProfiles(r *http.Request, tx pgx.Tx, subj Subject, profiles []migrationPreviewProcessProfileDTO) (map[string]int, []migrationProcessProfileRollbackDTO, error) {
	applied := map[string]int{"created": 0, "updated": 0, "process_profiles": 0, "process_profile_rules": 0, "process_profile_workloads": 0}
	rollback := make([]migrationProcessProfileRollbackDTO, 0)
	for _, profile := range profiles {
		clusterID, err := uuid.Parse(strings.TrimSpace(profile.ClusterID))
		if err != nil {
			return nil, nil, fmt.Errorf("process profile %s is missing a valid target cluster_id", profile.Group)
		}
		members := normalizeMigrationWorkloadIDs(profile.TargetWorkloads)
		if len(members) == 0 {
			var found bool
			members, found, err = migrationGroupMembersTx(r, tx, subj.OrgID, clusterID, firstNonEmpty(profile.TargetGroupName, profile.Group))
			if err != nil {
				return nil, nil, err
			}
			if !found || len(members) == 0 {
				return nil, nil, fmt.Errorf("process profile %s has no resolved target workloads", profile.Group)
			}
		}
		mode := normalizeMigrationProcessProfileMode(profile.Mode)
		for _, workloadID := range members {
			wl, found, err := migrationFindWorkload(r, tx, subj.OrgID, clusterID, workloadID)
			if err != nil {
				return nil, nil, err
			}
			if !found {
				return nil, nil, fmt.Errorf("process profile %s target workload %s no longer exists", profile.Group, workloadID)
			}
			stateBefore, stateExists, err := migrationProcessBaselineStateSnapshot(r, tx, subj.OrgID, clusterID, workloadID)
			if err != nil {
				return nil, nil, err
			}
			stateID, err := upsertMigrationProcessBaselineState(r, tx, subj.OrgID, clusterID, wl, mode, subj.UserID)
			if err != nil {
				return nil, nil, fmt.Errorf("process profile %s workload %s: %w", profile.Group, workloadID, err)
			}
			item := migrationProcessProfileRollbackDTO{
				Group:      profile.Group,
				WorkloadID: workloadID,
				Action:     "restore",
				StateID:    stateID.String(),
				Rules:      make([]migrationProcessProfileRuleRollbackDTO, 0, len(profile.Rules)),
			}
			if stateExists {
				item.Before = &stateBefore
				applied["updated"]++
			} else {
				item.Action = "delete"
				applied["created"]++
			}
			for _, rule := range profile.Rules {
				name, pathValue, sha, parent, action, user, allowUpdate, enabled, description, err := migrationProcessProfileRuleParts(rule)
				if err != nil {
					return nil, nil, fmt.Errorf("process profile %s workload %s: %w", profile.Group, workloadID, err)
				}
				ruleBefore, ruleExists, err := migrationProcessProfileRuleSnapshot(r, tx, subj.OrgID, clusterID, workloadID, name, pathValue)
				if err != nil {
					return nil, nil, err
				}
				ruleID, err := upsertMigrationProcessProfileRule(r, tx, subj.OrgID, clusterID, workloadID, name, pathValue, sha, parent, action, user, allowUpdate, enabled, description, subj.UserID)
				if err != nil {
					return nil, nil, fmt.Errorf("process profile %s workload %s rule %s%s: %w", profile.Group, workloadID, name, pathValue, err)
				}
				rb := migrationProcessProfileRuleRollbackDTO{Name: name, Path: pathValue, Action: "delete", ID: ruleID.String()}
				if ruleExists {
					rb.Action = "restore"
					rb.ID = ruleBefore.ID
					rb.Before = &ruleBefore
				}
				item.Rules = append(item.Rules, rb)
				applied["process_profile_rules"]++
			}
			rollback = append(rollback, item)
			applied["process_profile_workloads"]++
		}
		applied["process_profiles"]++
	}
	return applied, rollback, nil
}

func (h *Enterprise) applyMigrationFileProfiles(r *http.Request, tx pgx.Tx, subj Subject, profiles []migrationPreviewFileProfileDTO) (map[string]int, []migrationFileProfileRollbackDTO, error) {
	applied := map[string]int{"created": 0, "updated": 0, "file_profiles": 0, "file_profile_rules": 0, "file_profile_workloads": 0}
	rollback := make([]migrationFileProfileRollbackDTO, 0)
	for _, profile := range profiles {
		if strings.TrimSpace(profile.ClusterID) == "" {
			continue
		}
		clusterID, err := uuid.Parse(strings.TrimSpace(profile.ClusterID))
		if err != nil {
			return nil, nil, fmt.Errorf("file profile %s is missing a valid target cluster_id", profile.Group)
		}
		members := normalizeMigrationWorkloadIDs(profile.TargetWorkloads)
		if len(members) == 0 {
			var found bool
			members, found, err = migrationGroupMembersTx(r, tx, subj.OrgID, clusterID, firstNonEmpty(profile.TargetGroupName, profile.Group))
			if err != nil {
				return nil, nil, err
			}
			if !found || len(members) == 0 {
				return nil, nil, fmt.Errorf("file profile %s has no resolved target workloads", profile.Group)
			}
		}
		mode := normalizeMigrationFileProfileMode(profile.Mode)
		for _, workloadID := range members {
			wl, found, err := migrationFindWorkload(r, tx, subj.OrgID, clusterID, workloadID)
			if err != nil {
				return nil, nil, err
			}
			if !found {
				return nil, nil, fmt.Errorf("file profile %s target workload %s no longer exists", profile.Group, workloadID)
			}
			stateBefore, stateExists, err := migrationFileProfileStateSnapshot(r, tx, subj.OrgID, clusterID, workloadID)
			if err != nil {
				return nil, nil, err
			}
			stateID, err := upsertMigrationFileProfileState(r, tx, subj.OrgID, clusterID, wl, mode, subj.UserID)
			if err != nil {
				return nil, nil, fmt.Errorf("file profile %s workload %s: %w", profile.Group, workloadID, err)
			}
			item := migrationFileProfileRollbackDTO{
				Group:      profile.Group,
				WorkloadID: workloadID,
				Action:     "restore",
				StateID:    stateID.String(),
				Rules:      make([]migrationFileProfileRuleRollbackDTO, 0, len(profile.Rules)),
			}
			if stateExists {
				item.Before = &stateBefore
				applied["updated"]++
			} else {
				item.Action = "delete"
				applied["created"]++
			}
			for _, rule := range profile.Rules {
				parsed, recursive, behavior, applications, enabled, description, err := migrationFileProfileRuleParts(rule)
				if err != nil {
					return nil, nil, fmt.Errorf("file profile %s workload %s: %w", profile.Group, workloadID, err)
				}
				ruleBefore, ruleExists, err := migrationFileProfileRuleSnapshot(r, tx, subj.OrgID, clusterID, workloadID, parsed.Filter)
				if err != nil {
					return nil, nil, err
				}
				ruleID, err := upsertMigrationFileProfileRule(r, tx, subj.OrgID, clusterID, workloadID, parsed, recursive, behavior, applications, enabled, description, subj.UserID)
				if err != nil {
					return nil, nil, fmt.Errorf("file profile %s workload %s rule %s: %w", profile.Group, workloadID, parsed.Filter, err)
				}
				rb := migrationFileProfileRuleRollbackDTO{Filter: parsed.Filter, Action: "delete", ID: ruleID.String()}
				if ruleExists {
					rb.Action = "restore"
					rb.ID = ruleBefore.ID
					rb.Before = &ruleBefore
				}
				item.Rules = append(item.Rules, rb)
				applied["file_profile_rules"]++
			}
			rollback = append(rollback, item)
			applied["file_profile_workloads"]++
		}
		applied["file_profiles"]++
	}
	return applied, rollback, nil
}

func (h *Enterprise) applyMigrationNetworkRules(r *http.Request, tx pgx.Tx, subj Subject, rules []migrationPreviewNetworkRuleDTO) (map[string]int, []migrationNetworkRuleRollbackDTO, error) {
	applied := map[string]int{"created": 0, "updated": 0, "network_rules": 0}
	rollback := make([]migrationNetworkRuleRollbackDTO, 0, len(rules))
	clusterCache := map[uuid.UUID]bool{}
	for _, rule := range rules {
		clusterID, err := uuid.Parse(strings.TrimSpace(rule.ClusterID))
		if err != nil {
			return nil, nil, fmt.Errorf("network rule %s is missing a valid target cluster_id", rule.Name)
		}
		ok, cached := clusterCache[clusterID]
		if !cached {
			if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, subj.OrgID, clusterID).Scan(&ok); err != nil {
				return nil, nil, err
			}
			clusterCache[clusterID] = ok
		}
		if !ok {
			return nil, nil, fmt.Errorf("network rule %s targets a cluster outside this organization", rule.Name)
		}
		ports, err := migrationNetworkPorts(rule.Ports)
		if err != nil {
			return nil, nil, fmt.Errorf("network rule %s: %w", rule.Name, err)
		}
		edge := netpolicy.GroupEdge{
			FromGroup: strings.TrimSpace(rule.FromGroup),
			ToGroup:   strings.TrimSpace(rule.ToGroup),
			Ports:     ports,
			Mode:      normalizeMigrationNetworkMode(rule.Mode),
			Comment:   strings.TrimSpace(rule.Comment),
		}
		if err := edge.Validate(); err != nil {
			return nil, nil, fmt.Errorf("network rule %s: %w", rule.Name, err)
		}
		if err := migrationNetworkGroupsExist(r, tx, subj.OrgID, clusterID, edge.FromGroup, edge.ToGroup); err != nil {
			return nil, nil, fmt.Errorf("network rule %s: %w", rule.Name, err)
		}
		portsJSON, err := json.Marshal(edge.Ports)
		if err != nil {
			return nil, nil, err
		}
		before, exists, err := migrationNetworkRuleSnapshot(r, tx, subj.OrgID, clusterID, edge.FromGroup, edge.ToGroup)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			if _, err := tx.Exec(r.Context(), `
UPDATE group_rule_edges
   SET ports=$3::jsonb, mode=$4, comment=$5, updated_by=$6, updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`,
				before.ID, subj.OrgID, string(portsJSON), edge.Mode, edge.Comment, subj.UserID); err != nil {
				return nil, nil, err
			}
			applied["updated"]++
			rollback = append(rollback, migrationNetworkRuleRollbackDTO{
				Name:      rule.Name,
				FromGroup: edge.FromGroup,
				ToGroup:   edge.ToGroup,
				Action:    "restore",
				ID:        before.ID,
				Before:    &before,
			})
		} else {
			var id uuid.UUID
			if err := tx.QueryRow(r.Context(), `
INSERT INTO group_rule_edges
  (org_id, cluster_id, from_group, to_group, ports, mode, comment, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$8)
RETURNING id`, subj.OrgID, clusterID, edge.FromGroup, edge.ToGroup, string(portsJSON), edge.Mode, edge.Comment, subj.UserID).Scan(&id); err != nil {
				return nil, nil, err
			}
			applied["created"]++
			rollback = append(rollback, migrationNetworkRuleRollbackDTO{
				Name:      rule.Name,
				FromGroup: edge.FromGroup,
				ToGroup:   edge.ToGroup,
				Action:    "delete",
				ID:        id.String(),
			})
		}
		applied["network_rules"]++
	}
	return applied, rollback, nil
}

func (h *Enterprise) applyMigrationDPIRules(r *http.Request, tx pgx.Tx, subj Subject, rules []migrationPreviewDPIRuleDTO) (map[string]int, []migrationDPIRuleRollbackDTO, error) {
	applied := map[string]int{"created": 0, "updated": 0, "dpi_rules": 0}
	rollback := make([]migrationDPIRuleRollbackDTO, 0, len(rules))
	clusterCache := map[uuid.UUID]bool{}
	for _, rule := range rules {
		clusterID, err := uuid.Parse(strings.TrimSpace(rule.ClusterID))
		if err != nil {
			return nil, nil, fmt.Errorf("DLP/WAF rule %s is missing a valid target cluster_id", rule.Name)
		}
		ok, cached := clusterCache[clusterID]
		if !cached {
			if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, subj.OrgID, clusterID).Scan(&ok); err != nil {
				return nil, nil, err
			}
			clusterCache[clusterID] = ok
		}
		if !ok {
			return nil, nil, fmt.Errorf("DLP/WAF rule %s targets a cluster outside this organization", rule.Name)
		}
		category, err := normalizeMigrationDPICategory(rule.Category)
		if err != nil {
			return nil, nil, fmt.Errorf("DLP/WAF rule %s: %w", rule.Name, err)
		}
		mode := normalizeMigrationDPIMode(rule.Mode)
		applyDir := rule.ApplyDir
		if applyDir == 0 {
			applyDir = defaultMigrationDPIApplyDir(category)
		}
		if applyDir < 1 || applyDir > 3 {
			return nil, nil, fmt.Errorf("DLP/WAF rule %s: apply_dir must be 1, 2, or 3", rule.Name)
		}
		severity := rule.Severity
		if severity == 0 {
			severity = 5
		}
		if severity < 1 || severity > 9 {
			return nil, nil, fmt.Errorf("DLP/WAF rule %s: severity must be 1..9", rule.Name)
		}
		patterns, err := migrationDPIPatternsJSON(rule.Patterns)
		if err != nil {
			return nil, nil, fmt.Errorf("DLP/WAF rule %s: %w", rule.Name, err)
		}
		before, exists, err := migrationDPIRuleSnapshot(r, tx, subj.OrgID, clusterID, rule.Name)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			cfgType := migrationDPIRuleCfgType(rule)
			if _, err := tx.Exec(r.Context(), `
	UPDATE runtime_dlp_rules
	   SET category=$3, apply_dir=$4, severity=$5, mode=$6, patterns=$7::jsonb,
	       description=$8, updated_by=$9, cfg_type=$10, source='neuvector',
	       source_path=$11, updated_at=NOW()
	 WHERE id=$1::uuid AND org_id=$2`,
				before.ID, subj.OrgID, category, applyDir, severity, mode, string(patterns), rule.Description, subj.UserID, cfgType, rule.SourcePath); err != nil {
				return nil, nil, err
			}
			applied["updated"]++
			rollback = append(rollback, migrationDPIRuleRollbackDTO{Name: rule.Name, Action: "restore", ID: before.ID, Before: &before})
		} else {
			cfgType := migrationDPIRuleCfgType(rule)
			var id uuid.UUID
			if err := tx.QueryRow(r.Context(), `
	INSERT INTO runtime_dlp_rules
	  (org_id, cluster_id, name, category, apply_dir, severity, mode, patterns,
	   description, created_by, updated_by, source, cfg_type, source_path)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$10,'neuvector',$11,$12)
	RETURNING id`, subj.OrgID, clusterID, rule.Name, category, applyDir, severity, mode, string(patterns), rule.Description, subj.UserID, cfgType, rule.SourcePath).Scan(&id); err != nil {
				return nil, nil, err
			}
			applied["created"]++
			rollback = append(rollback, migrationDPIRuleRollbackDTO{Name: rule.Name, Action: "delete", ID: id.String()})
		}
		applied["dpi_rules"]++
	}
	return applied, rollback, nil
}

func (h *Enterprise) applyMigrationDPIBindings(r *http.Request, tx pgx.Tx, subj Subject, bindings []migrationPreviewDPIBindingDTO) (map[string]int, []migrationDPIBindingRollbackDTO, error) {
	applied := map[string]int{"created": 0, "updated": 0, "dpi_bindings": 0}
	rollback := make([]migrationDPIBindingRollbackDTO, 0, len(bindings))
	for _, binding := range bindings {
		groupID, err := migrationBindingTargetGroupID(r, tx, subj.OrgID, binding)
		if err != nil {
			return nil, nil, err
		}
		kind, err := normalizeMigrationDPISensorKind(binding.SensorKind)
		if err != nil {
			return nil, nil, fmt.Errorf("DLP/WAF binding for group %s: %w", binding.SourceGroup, err)
		}
		var groupExists bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM groups WHERE org_id=$1 AND id=$2)`, subj.OrgID, groupID).Scan(&groupExists); err != nil {
			return nil, nil, err
		}
		if !groupExists {
			return nil, nil, fmt.Errorf("DLP/WAF binding target group %s no longer exists", binding.TargetGroupID)
		}
		var existingID string
		err = tx.QueryRow(r.Context(), `
SELECT id::text
  FROM group_dpi_sensor_bindings
 WHERE org_id=$1 AND group_id=$2 AND sensor_kind=$3
 ORDER BY created_at ASC
 LIMIT 1`, subj.OrgID, groupID, kind).Scan(&existingID)
		if err != nil && err != pgx.ErrNoRows {
			return nil, nil, err
		}
		if err == nil {
			applied["updated"]++
			applied["dpi_bindings"]++
			continue
		}

		sensorID := defaultMigrationDPISensorID(kind)
		if sensorID == uuid.Nil {
			return nil, nil, fmt.Errorf("DLP/WAF binding for group %s has unsupported sensor kind %s", binding.SourceGroup, kind)
		}
		var id uuid.UUID
		if err := tx.QueryRow(r.Context(), `
INSERT INTO group_dpi_sensor_bindings (org_id, group_id, sensor_kind, sensor_id, created_by)
VALUES ($1,$2,$3,$4,$5)
RETURNING id`, subj.OrgID, groupID, kind, sensorID, subj.UserID).Scan(&id); err != nil {
			return nil, nil, err
		}
		applied["created"]++
		applied["dpi_bindings"]++
		rollback = append(rollback, migrationDPIBindingRollbackDTO{
			SourceGroup: binding.SourceGroup,
			SensorKind:  kind,
			Action:      "delete",
			ID:          id.String(),
		})
	}
	return applied, rollback, nil
}

func migrationPolicySnapshot(r *http.Request, tx pgx.Tx, orgID uuid.UUID, name string) (policyRollbackSnapshot, bool, error) {
	var snap policyRollbackSnapshot
	err := tx.QueryRow(r.Context(), `
SELECT id::text, name, COALESCE(description,''), engine, category, spec_yaml, enabled, mode, version, cfg_type, source
  FROM policies
 WHERE org_id=$1 AND name=$2
 ORDER BY version DESC, updated_at DESC
 LIMIT 1`, orgID, name).Scan(&snap.ID, &snap.Name, &snap.Description, &snap.Engine, &snap.Category, &snap.SpecYAML, &snap.Enabled, &snap.Mode, &snap.Version, &snap.CfgType, &snap.Source)
	if err == pgx.ErrNoRows {
		return policyRollbackSnapshot{}, false, nil
	}
	if err != nil {
		return policyRollbackSnapshot{}, false, err
	}
	return snap, true, nil
}

func migrationDPIRuleSnapshot(r *http.Request, tx pgx.Tx, orgID, clusterID uuid.UUID, name string) (dpiRuleRollbackSnapshot, bool, error) {
	var snap dpiRuleRollbackSnapshot
	var patternsText, scopeText string
	err := tx.QueryRow(r.Context(), `
SELECT id::text, cluster_id::text, name, category, apply_dir, severity, mode,
       patterns::text, COALESCE(scope_macs::text,'null'), COALESCE(description,''),
       COALESCE(source,'user'), COALESCE(cfg_type,'user_created'), COALESCE(source_path,''), version
  FROM runtime_dlp_rules
 WHERE org_id=$1 AND cluster_id=$2 AND name=$3
 ORDER BY updated_at DESC
 LIMIT 1`, orgID, clusterID, name).Scan(
		&snap.ID, &snap.ClusterID, &snap.Name, &snap.Category, &snap.ApplyDir, &snap.Severity, &snap.Mode,
		&patternsText, &scopeText, &snap.Description, &snap.Source, &snap.CfgType, &snap.SourcePath, &snap.Version,
	)
	if err == pgx.ErrNoRows {
		return dpiRuleRollbackSnapshot{}, false, nil
	}
	if err != nil {
		return dpiRuleRollbackSnapshot{}, false, err
	}
	snap.Patterns = json.RawMessage(patternsText)
	if strings.TrimSpace(scopeText) != "" && strings.TrimSpace(scopeText) != "null" {
		snap.ScopeMACs = json.RawMessage(scopeText)
	}
	return snap, true, nil
}

func migrationGroupSnapshot(r *http.Request, tx pgx.Tx, orgID uuid.UUID, name string) (groupRollbackSnapshot, bool, error) {
	var snap groupRollbackSnapshot
	var criteriaText, membersText string
	err := tx.QueryRow(r.Context(), `
SELECT id::text, COALESCE(cluster_id::text,''), name, kind, COALESCE(comment,''),
       criteria::text, members::text, COALESCE(learned_from,''), COALESCE(cfg_type,'user'),
       COALESCE(policy_mode,'monitor'), COALESCE(profile_mode,'monitor')
  FROM groups
 WHERE org_id=$1 AND name=$2
 ORDER BY updated_at DESC
 LIMIT 1`, orgID, name).Scan(
		&snap.ID, &snap.ClusterID, &snap.Name, &snap.Kind, &snap.Comment,
		&criteriaText, &membersText, &snap.LearnedFrom, &snap.CfgType, &snap.PolicyMode, &snap.ProfileMode,
	)
	if err == pgx.ErrNoRows {
		return groupRollbackSnapshot{}, false, nil
	}
	if err != nil {
		return groupRollbackSnapshot{}, false, err
	}
	snap.Criteria = json.RawMessage(emptyDefault(criteriaText, "[]"))
	snap.Members = json.RawMessage(emptyDefault(membersText, "[]"))
	return snap, true, nil
}

func migrationNetworkRuleSnapshot(r *http.Request, tx pgx.Tx, orgID, clusterID uuid.UUID, fromGroup, toGroup string) (networkRuleRollbackSnapshot, bool, error) {
	var snap networkRuleRollbackSnapshot
	var portsText string
	err := tx.QueryRow(r.Context(), `
SELECT id::text, cluster_id::text, from_group, to_group, ports::text, mode, COALESCE(comment,'')
  FROM group_rule_edges
 WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3 AND to_group=$4
 ORDER BY updated_at DESC
 LIMIT 1`, orgID, clusterID, fromGroup, toGroup).Scan(
		&snap.ID, &snap.ClusterID, &snap.FromGroup, &snap.ToGroup, &portsText, &snap.Mode, &snap.Comment,
	)
	if err == pgx.ErrNoRows {
		return networkRuleRollbackSnapshot{}, false, nil
	}
	if err != nil {
		return networkRuleRollbackSnapshot{}, false, err
	}
	snap.Ports = json.RawMessage(emptyDefault(portsText, "[]"))
	return snap, true, nil
}

func migrationFileProfileStateSnapshot(r *http.Request, tx pgx.Tx, orgID, clusterID uuid.UUID, workloadID string) (fileProfileStateRollbackSnapshot, bool, error) {
	var snap fileProfileStateRollbackSnapshot
	err := tx.QueryRow(r.Context(), `
SELECT id::text, cluster_id::text, workload_id, namespace, name, mode,
       learn_started_at, monitor_started_at, enforce_started_at
  FROM file_profile_states
 WHERE org_id=$1 AND cluster_id=$2 AND workload_id=$3
 LIMIT 1`, orgID, clusterID, workloadID).Scan(
		&snap.ID, &snap.ClusterID, &snap.WorkloadID, &snap.Namespace, &snap.Name, &snap.Mode,
		&snap.LearnStartedAt, &snap.MonitorStartedAt, &snap.EnforceStartedAt,
	)
	if err == pgx.ErrNoRows {
		return fileProfileStateRollbackSnapshot{}, false, nil
	}
	if err != nil {
		return fileProfileStateRollbackSnapshot{}, false, err
	}
	return snap, true, nil
}

func migrationFileProfileRuleSnapshot(r *http.Request, tx pgx.Tx, orgID, clusterID uuid.UUID, workloadID, filter string) (fileProfileRuleRollbackSnapshot, bool, error) {
	var snap fileProfileRuleRollbackSnapshot
	err := tx.QueryRow(r.Context(), `
SELECT id::text, cluster_id::text, workload_id, filter, path, regex, recursive,
       behavior, applications, enabled, COALESCE(description,'')
  FROM file_profile_rules
 WHERE org_id=$1 AND cluster_id=$2 AND workload_id=$3 AND filter=$4
 LIMIT 1`, orgID, clusterID, workloadID, filter).Scan(
		&snap.ID, &snap.ClusterID, &snap.WorkloadID, &snap.Filter, &snap.Path, &snap.Regex,
		&snap.Recursive, &snap.Behavior, &snap.Applications, &snap.Enabled, &snap.Description,
	)
	if err == pgx.ErrNoRows {
		return fileProfileRuleRollbackSnapshot{}, false, nil
	}
	if err != nil {
		return fileProfileRuleRollbackSnapshot{}, false, err
	}
	return snap, true, nil
}

func migrationProcessBaselineStateSnapshot(r *http.Request, tx pgx.Tx, orgID, clusterID uuid.UUID, workloadID string) (processBaselineStateRollbackSnapshot, bool, error) {
	var snap processBaselineStateRollbackSnapshot
	err := tx.QueryRow(r.Context(), `
SELECT id::text, cluster_id::text, workload_id, namespace, name, mode,
       learn_started_at, monitor_started_at, enforce_started_at
  FROM process_baseline_states
 WHERE org_id=$1 AND cluster_id=$2 AND workload_id=$3
 LIMIT 1`, orgID, clusterID, workloadID).Scan(
		&snap.ID, &snap.ClusterID, &snap.WorkloadID, &snap.Namespace, &snap.Name, &snap.Mode,
		&snap.LearnStartedAt, &snap.MonitorStartedAt, &snap.EnforceStartedAt,
	)
	if err == pgx.ErrNoRows {
		return processBaselineStateRollbackSnapshot{}, false, nil
	}
	if err != nil {
		return processBaselineStateRollbackSnapshot{}, false, err
	}
	return snap, true, nil
}

func migrationProcessProfileRuleSnapshot(r *http.Request, tx pgx.Tx, orgID, clusterID uuid.UUID, workloadID, name, pathValue string) (processProfileRuleRollbackSnapshot, bool, error) {
	var snap processProfileRuleRollbackSnapshot
	err := tx.QueryRow(r.Context(), `
SELECT id::text, cluster_id::text, workload_id, name, path,
       COALESCE(sha256,''), COALESCE(parent_name,''), action, proc_user,
       allow_update, enabled, COALESCE(description,'')
  FROM process_profile_rules
 WHERE org_id=$1 AND cluster_id=$2 AND workload_id=$3 AND name=$4 AND path=$5
 LIMIT 1`, orgID, clusterID, workloadID, name, pathValue).Scan(
		&snap.ID, &snap.ClusterID, &snap.WorkloadID, &snap.Name, &snap.Path, &snap.SHA256,
		&snap.ParentName, &snap.Action, &snap.User, &snap.AllowUpdate, &snap.Enabled, &snap.Description,
	)
	if err == pgx.ErrNoRows {
		return processProfileRuleRollbackSnapshot{}, false, nil
	}
	if err != nil {
		return processProfileRuleRollbackSnapshot{}, false, err
	}
	return snap, true, nil
}

func migrationGroupCriteria(criteria []portableGroupCriterion) ([]group.Criterion, error) {
	out := make([]group.Criterion, 0, len(criteria))
	for _, criterion := range criteria {
		item := group.Criterion{
			Key:   strings.TrimSpace(criterion.Key),
			Op:    group.Op(emptyDefault(strings.TrimSpace(criterion.Op), string(group.OpEq))),
			Value: strings.TrimSpace(criterion.Value),
		}
		out = append(out, item)
	}
	g := &group.Group{Name: "migration-validation", Kind: group.KindGround, Criteria: out}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

func migrationComputeGroupMembers(r *http.Request, tx pgx.Tx, orgID uuid.UUID, clusterID uuid.UUID, g *group.Group) ([]string, error) {
	rows, err := tx.Query(r.Context(), `
SELECT namespace, name, COALESCE(cluster_id::text,''), labels
  FROM deployments
 WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	workloads := []group.Workload{}
	for rows.Next() {
		var namespace, name, clusterText string
		var labelsRaw []byte
		if err := rows.Scan(&namespace, &name, &clusterText, &labelsRaw); err != nil {
			return nil, err
		}
		labels := map[string]string{}
		_ = json.Unmarshal(labelsRaw, &labels)
		workloads = append(workloads, group.Workload{
			ID:        namespace + "/" + name,
			Cluster:   clusterText,
			Namespace: namespace,
			Labels:    labels,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return g.ComputeMembers(workloads), nil
}

func (h *Enterprise) computeMigrationGroupMembersFromPool(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID, g *group.Group) ([]string, error) {
	if h == nil || h.db == nil {
		return nil, nil
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT namespace, name, COALESCE(cluster_id::text,''), labels
  FROM deployments
 WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	workloads := []group.Workload{}
	for rows.Next() {
		var namespace, name, clusterText string
		var labelsRaw []byte
		if err := rows.Scan(&namespace, &name, &clusterText, &labelsRaw); err != nil {
			return nil, err
		}
		labels := map[string]string{}
		_ = json.Unmarshal(labelsRaw, &labels)
		workloads = append(workloads, group.Workload{
			ID:        namespace + "/" + name,
			Cluster:   clusterText,
			Namespace: namespace,
			Labels:    labels,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return g.ComputeMembers(workloads), nil
}

func (h *Enterprise) migrationGroupMembers(r *http.Request, orgID uuid.UUID, clusterID uuid.UUID, groupName string) ([]string, bool, error) {
	if h == nil || h.db == nil || strings.TrimSpace(groupName) == "" {
		return nil, false, nil
	}
	var raw json.RawMessage
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT members
  FROM groups
 WHERE org_id=$1
   AND name=$2
   AND (cluster_id IS NULL OR cluster_id=$3)
 ORDER BY CASE WHEN cluster_id=$3 THEN 0 ELSE 1 END, updated_at DESC
 LIMIT 1`, orgID, strings.TrimSpace(groupName), clusterID).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	members := []string{}
	if len(raw) > 0 && string(raw) != "null" {
		_ = json.Unmarshal(raw, &members)
	}
	return normalizeMigrationWorkloadIDs(members), true, nil
}

func migrationGroupMembersTx(r *http.Request, tx pgx.Tx, orgID uuid.UUID, clusterID uuid.UUID, groupName string) ([]string, bool, error) {
	var raw json.RawMessage
	err := tx.QueryRow(r.Context(), `
SELECT members
  FROM groups
 WHERE org_id=$1
   AND name=$2
   AND (cluster_id IS NULL OR cluster_id=$3)
 ORDER BY CASE WHEN cluster_id=$3 THEN 0 ELSE 1 END, updated_at DESC
 LIMIT 1`, orgID, strings.TrimSpace(groupName), clusterID).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	members := []string{}
	if len(raw) > 0 && string(raw) != "null" {
		_ = json.Unmarshal(raw, &members)
	}
	return normalizeMigrationWorkloadIDs(members), true, nil
}

func migrationFindWorkload(r *http.Request, tx pgx.Tx, orgID uuid.UUID, clusterID uuid.UUID, workloadID string) (migrationObservedWorkload, bool, error) {
	namespace, name := splitMigrationWorkloadID(workloadID)
	if namespace == "" || name == "" {
		return migrationObservedWorkload{}, false, nil
	}
	var wl migrationObservedWorkload
	err := tx.QueryRow(r.Context(), `
SELECT namespace, name
  FROM deployments
 WHERE org_id=$1 AND cluster_id=$2 AND namespace=$3 AND name=$4
 LIMIT 1`, orgID, clusterID, namespace, name).Scan(&wl.Namespace, &wl.Name)
	if err == pgx.ErrNoRows {
		return migrationObservedWorkload{}, false, nil
	}
	if err != nil {
		return migrationObservedWorkload{}, false, err
	}
	wl.WorkloadID = namespace + "/" + name
	return wl, true, nil
}

func splitMigrationWorkloadID(workloadID string) (string, string) {
	namespace, name, ok := strings.Cut(strings.TrimSpace(workloadID), "/")
	if !ok || strings.TrimSpace(namespace) == "" || strings.TrimSpace(name) == "" {
		return "", ""
	}
	return strings.TrimSpace(namespace), strings.TrimSpace(name)
}

func normalizeMigrationWorkloadIDs(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func upsertMigrationFileProfileState(r *http.Request, tx pgx.Tx, orgID uuid.UUID, clusterID uuid.UUID, wl migrationObservedWorkload, mode string, userID uuid.UUID) (uuid.UUID, error) {
	now := time.Now().UTC()
	var id uuid.UUID
	err := tx.QueryRow(r.Context(), `
INSERT INTO file_profile_states (
    org_id, cluster_id, workload_id, namespace, name, mode, learn_started_at,
    monitor_started_at, enforce_started_at, created_by, updated_by, created_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7::timestamptz,
    CASE WHEN $6='monitor' THEN $7::timestamptz ELSE NULL END,
    CASE WHEN $6='enforce' THEN $7::timestamptz ELSE NULL END,
    $8,$8,$7::timestamptz,$7::timestamptz
)
ON CONFLICT (org_id, cluster_id, workload_id) DO UPDATE
   SET namespace=EXCLUDED.namespace,
       name=EXCLUDED.name,
       mode=EXCLUDED.mode,
       monitor_started_at=CASE WHEN EXCLUDED.mode='monitor' AND file_profile_states.monitor_started_at IS NULL THEN EXCLUDED.monitor_started_at ELSE file_profile_states.monitor_started_at END,
       enforce_started_at=CASE WHEN EXCLUDED.mode='enforce' THEN EXCLUDED.enforce_started_at ELSE file_profile_states.enforce_started_at END,
       updated_by=EXCLUDED.updated_by,
       updated_at=EXCLUDED.updated_at
RETURNING id`, orgID, clusterID, wl.WorkloadID, wl.Namespace, wl.Name, mode, now, userID).Scan(&id)
	return id, err
}

func upsertMigrationFileProfileRule(r *http.Request, tx pgx.Tx, orgID uuid.UUID, clusterID uuid.UUID, workloadID string, parsed migrationParsedFileProfileFilter, recursive bool, behavior string, applications []string, enabled bool, description string, userID uuid.UUID) (uuid.UUID, error) {
	now := time.Now().UTC()
	var id uuid.UUID
	err := tx.QueryRow(r.Context(), `
INSERT INTO file_profile_rules (
    org_id, cluster_id, workload_id, filter, path, regex, recursive, behavior,
    applications, enabled, description, created_by, updated_by, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,$13,$13)
ON CONFLICT (org_id, cluster_id, workload_id, filter) DO UPDATE
   SET path=EXCLUDED.path,
       regex=EXCLUDED.regex,
       recursive=EXCLUDED.recursive,
       behavior=EXCLUDED.behavior,
       applications=EXCLUDED.applications,
       enabled=EXCLUDED.enabled,
       description=EXCLUDED.description,
       updated_by=EXCLUDED.updated_by,
       updated_at=EXCLUDED.updated_at
RETURNING id`, orgID, clusterID, workloadID, parsed.Filter, parsed.Path, parsed.Regex, recursive, behavior, applications, enabled, description, userID, now).Scan(&id)
	return id, err
}

func upsertMigrationProcessBaselineState(r *http.Request, tx pgx.Tx, orgID uuid.UUID, clusterID uuid.UUID, wl migrationObservedWorkload, mode string, userID uuid.UUID) (uuid.UUID, error) {
	now := time.Now().UTC()
	var id uuid.UUID
	err := tx.QueryRow(r.Context(), `
INSERT INTO process_baseline_states (
    org_id, cluster_id, workload_id, namespace, name, mode, learn_started_at,
    monitor_started_at, enforce_started_at, created_by, updated_by, created_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7::timestamptz,
    CASE WHEN $6='monitor' THEN $7::timestamptz ELSE NULL END,
    CASE WHEN $6='enforce' THEN $7::timestamptz ELSE NULL END,
    $8,$8,$7::timestamptz,$7::timestamptz
)
ON CONFLICT (org_id, cluster_id, workload_id) DO UPDATE
   SET namespace=EXCLUDED.namespace,
       name=EXCLUDED.name,
       mode=EXCLUDED.mode,
       monitor_started_at=CASE WHEN EXCLUDED.mode='monitor' AND process_baseline_states.monitor_started_at IS NULL THEN EXCLUDED.monitor_started_at ELSE process_baseline_states.monitor_started_at END,
       enforce_started_at=CASE WHEN EXCLUDED.mode='enforce' THEN EXCLUDED.enforce_started_at ELSE process_baseline_states.enforce_started_at END,
       updated_by=EXCLUDED.updated_by,
       updated_at=EXCLUDED.updated_at
RETURNING id`, orgID, clusterID, wl.WorkloadID, wl.Namespace, wl.Name, mode, now, userID).Scan(&id)
	return id, err
}

func upsertMigrationProcessProfileRule(r *http.Request, tx pgx.Tx, orgID uuid.UUID, clusterID uuid.UUID, workloadID string, name string, pathValue string, sha string, parent string, action string, user string, allowUpdate bool, enabled bool, description string, userID uuid.UUID) (uuid.UUID, error) {
	now := time.Now().UTC()
	var id uuid.UUID
	err := tx.QueryRow(r.Context(), `
INSERT INTO process_profile_rules (
    org_id, cluster_id, workload_id, name, path, sha256, parent_name, action,
    proc_user, allow_update, enabled, description, created_by, updated_by,
    created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$14)
ON CONFLICT (org_id, cluster_id, workload_id, name, path) DO UPDATE
   SET sha256=EXCLUDED.sha256,
       parent_name=EXCLUDED.parent_name,
       action=EXCLUDED.action,
       proc_user=EXCLUDED.proc_user,
       allow_update=EXCLUDED.allow_update,
       enabled=EXCLUDED.enabled,
       description=EXCLUDED.description,
       updated_by=EXCLUDED.updated_by,
       updated_at=EXCLUDED.updated_at
RETURNING id`, orgID, clusterID, workloadID, name, pathValue, sha, parent, action, user, allowUpdate, enabled, description, userID, now).Scan(&id)
	return id, err
}

func migrationProcessProfileRuleParts(rule migrationProcessRuleDTO) (string, string, string, string, string, string, bool, bool, string, error) {
	name := strings.TrimSpace(rule.Name)
	pathValue := strings.TrimSpace(rule.Path)
	if name == "" && pathValue == "" {
		return "", "", "", "", "", "", false, false, "", fmt.Errorf("process rule requires a name or path")
	}
	if name == "*" || pathValue == "*" || pathValue == "/*" {
		return "", "", "", "", "", "", false, false, "", fmt.Errorf("wildcard process rules require manual review")
	}
	action, err := normalizeMigrationProcessRuleAction(rule.Action)
	if err != nil {
		return "", "", "", "", "", "", false, false, "", err
	}
	return name,
		pathValue,
		strings.ToLower(strings.TrimSpace(rule.SHA256)),
		strings.TrimSpace(rule.ParentName),
		action,
		strings.TrimSpace(rule.User),
		rule.AllowUpdate,
		rule.Enabled,
		strings.TrimSpace(rule.Description),
		nil
}

func migrationFileProfileRuleParts(rule fileProfilePortableRuleDTO) (migrationParsedFileProfileFilter, bool, string, []string, bool, string, error) {
	parsed, err := parseMigrationFileProfileFilter(rule.Filter)
	if err != nil {
		return migrationParsedFileProfileFilter{}, false, "", nil, false, "", err
	}
	behavior, err := normalizeMigrationFileProfileRuleBehavior(rule.Behavior)
	if err != nil {
		return migrationParsedFileProfileFilter{}, false, "", nil, false, "", err
	}
	enabled := true
	if rule.Enabled != nil {
		enabled = *rule.Enabled
	}
	return parsed, rule.Recursive, behavior, normalizeMigrationApplications(rule.Applications), enabled, strings.TrimSpace(rule.Description), nil
}

func migrationNetworkPorts(ports []migrationNetworkPortDTO) ([]netpolicy.PortSpec, error) {
	out := make([]netpolicy.PortSpec, 0, len(ports))
	for _, port := range ports {
		out = append(out, netpolicy.PortSpec{
			Protocol: strings.ToUpper(strings.TrimSpace(port.Protocol)),
			Port:     port.Port,
		})
	}
	edge := netpolicy.GroupEdge{FromGroup: "from", ToGroup: "to", Ports: out, Mode: "monitor"}
	if err := edge.Validate(); err != nil {
		return nil, err
	}
	return edge.Ports, nil
}

func migrationNetworkGroupsExist(r *http.Request, tx pgx.Tx, orgID, clusterID uuid.UUID, groups ...string) error {
	for _, groupName := range groups {
		groupName = strings.TrimSpace(groupName)
		if groupName == "" {
			return fmt.Errorf("group name is required")
		}
		var exists bool
		if err := tx.QueryRow(r.Context(), `
SELECT EXISTS(
  SELECT 1
    FROM groups
   WHERE org_id=$1
     AND name=$2
     AND (cluster_id IS NULL OR cluster_id=$3)
)`, orgID, groupName, clusterID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("target group %s no longer exists", groupName)
		}
	}
	return nil
}

func migrationBindingTargetGroupID(r *http.Request, tx pgx.Tx, orgID uuid.UUID, binding migrationPreviewDPIBindingDTO) (uuid.UUID, error) {
	if idText := strings.TrimSpace(binding.TargetGroupID); idText != "" {
		groupID, err := uuid.Parse(idText)
		if err != nil {
			return uuid.Nil, fmt.Errorf("DLP/WAF binding for group %s has invalid target_group_id %s", binding.SourceGroup, idText)
		}
		return groupID, nil
	}
	name := strings.TrimSpace(firstNonEmpty(binding.TargetGroupName, binding.SourceGroup))
	if name == "" {
		return uuid.Nil, fmt.Errorf("DLP/WAF binding for group %s is missing a target group", binding.SourceGroup)
	}
	var groupID uuid.UUID
	if err := tx.QueryRow(r.Context(), `
SELECT id
  FROM groups
 WHERE org_id=$1 AND name=$2
 ORDER BY updated_at DESC
 LIMIT 1`, orgID, name).Scan(&groupID); err != nil {
		if err == pgx.ErrNoRows {
			return uuid.Nil, fmt.Errorf("DLP/WAF binding target group %s no longer exists", name)
		}
		return uuid.Nil, err
	}
	return groupID, nil
}

func (h *Enterprise) rollbackMigrationPolicies(r *http.Request, tx pgx.Tx, orgID uuid.UUID, policies []migrationPolicyRollbackDTO) (int, int, error) {
	var restored, deleted int
	for _, item := range policies {
		switch item.Action {
		case "delete":
			if item.ID == "" {
				continue
			}
			tag, err := tx.Exec(r.Context(), `DELETE FROM policies WHERE id=$1::uuid AND org_id=$2`, item.ID, orgID)
			if err != nil {
				return restored, deleted, err
			}
			deleted += int(tag.RowsAffected())
		case "restore":
			if item.Before == nil {
				continue
			}
			before := item.Before
			tag, err := tx.Exec(r.Context(), `
UPDATE policies
   SET name=$3, description=$4, engine=$5, category=$6, spec_yaml=$7,
       enabled=$8, mode=$9, version=$10, cfg_type=$11, source=$12, updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`,
				before.ID, orgID, before.Name, before.Description, before.Engine, before.Category, before.SpecYAML,
				before.Enabled, before.Mode, before.Version, emptyDefault(before.CfgType, "user"), emptyDefault(before.Source, "imperative"))
			if err != nil {
				return restored, deleted, err
			}
			restored += int(tag.RowsAffected())
		}
	}
	return restored, deleted, nil
}

func (h *Enterprise) rollbackMigrationDPIRules(r *http.Request, tx pgx.Tx, orgID uuid.UUID, rules []migrationDPIRuleRollbackDTO) (int, int, error) {
	var restored, deleted int
	for _, item := range rules {
		switch item.Action {
		case "delete":
			if item.ID == "" {
				continue
			}
			tag, err := tx.Exec(r.Context(), `DELETE FROM runtime_dlp_rules WHERE id=$1::uuid AND org_id=$2`, item.ID, orgID)
			if err != nil {
				return restored, deleted, err
			}
			deleted += int(tag.RowsAffected())
		case "restore":
			if item.Before == nil {
				continue
			}
			before := item.Before
			patterns := before.Patterns
			if len(patterns) == 0 {
				patterns = json.RawMessage(`[]`)
			}
			var scope any
			if len(before.ScopeMACs) > 0 {
				scope = string(before.ScopeMACs)
			}
			tag, err := tx.Exec(r.Context(), `
	UPDATE runtime_dlp_rules
	   SET cluster_id=$3::uuid, name=$4, category=$5, apply_dir=$6, severity=$7,
	       mode=$8, patterns=$9::jsonb, scope_macs=$10::jsonb, description=$11,
	       version=$12, source=$13, cfg_type=$14, source_path=$15, updated_at=NOW()
	 WHERE id=$1::uuid AND org_id=$2`,
				before.ID, orgID, before.ClusterID, before.Name, before.Category, before.ApplyDir, before.Severity,
				before.Mode, string(patterns), scope, before.Description, before.Version,
				emptyDefault(before.Source, "user"), emptyDefault(before.CfgType, "user_created"), before.SourcePath)
			if err != nil {
				return restored, deleted, err
			}
			rows := int(tag.RowsAffected())
			if rows > 0 {
				if _, err := tx.Exec(r.Context(), `UPDATE runtime_dlp_rules SET version=$3 WHERE id=$1::uuid AND org_id=$2`, before.ID, orgID, before.Version); err != nil {
					return restored, deleted, err
				}
			}
			restored += rows
		}
	}
	return restored, deleted, nil
}

func (h *Enterprise) rollbackMigrationNetworkRules(r *http.Request, tx pgx.Tx, orgID uuid.UUID, rules []migrationNetworkRuleRollbackDTO) (int, int, error) {
	var restored, deleted int
	for _, item := range rules {
		switch item.Action {
		case "delete":
			if item.ID == "" {
				continue
			}
			tag, err := tx.Exec(r.Context(), `DELETE FROM group_rule_edges WHERE id=$1::uuid AND org_id=$2`, item.ID, orgID)
			if err != nil {
				return restored, deleted, err
			}
			deleted += int(tag.RowsAffected())
		case "restore":
			if item.Before == nil {
				continue
			}
			before := item.Before
			ports := before.Ports
			if len(ports) == 0 {
				ports = json.RawMessage(`[]`)
			}
			tag, err := tx.Exec(r.Context(), `
UPDATE group_rule_edges
   SET cluster_id=$3::uuid, from_group=$4, to_group=$5, ports=$6::jsonb,
       mode=$7, comment=$8, updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`,
				before.ID, orgID, before.ClusterID, before.FromGroup, before.ToGroup, string(ports),
				normalizeMigrationNetworkMode(before.Mode), before.Comment)
			if err != nil {
				return restored, deleted, err
			}
			restored += int(tag.RowsAffected())
		}
	}
	return restored, deleted, nil
}

func (h *Enterprise) rollbackMigrationProcessProfiles(r *http.Request, tx pgx.Tx, orgID uuid.UUID, profiles []migrationProcessProfileRollbackDTO) (int, int, error) {
	var restored, deleted int
	for _, profile := range profiles {
		for _, rule := range profile.Rules {
			switch rule.Action {
			case "delete":
				if rule.ID == "" {
					continue
				}
				tag, err := tx.Exec(r.Context(), `DELETE FROM process_profile_rules WHERE id=$1::uuid AND org_id=$2`, rule.ID, orgID)
				if err != nil {
					return restored, deleted, err
				}
				deleted += int(tag.RowsAffected())
			case "restore":
				if rule.Before == nil {
					continue
				}
				before := rule.Before
				tag, err := tx.Exec(r.Context(), `
UPDATE process_profile_rules
   SET cluster_id=$3::uuid, workload_id=$4, name=$5, path=$6,
       sha256=$7, parent_name=$8, action=$9, proc_user=$10,
       allow_update=$11, enabled=$12, description=$13, updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`,
					before.ID, orgID, before.ClusterID, before.WorkloadID, before.Name, before.Path,
					before.SHA256, before.ParentName, before.Action, before.User, before.AllowUpdate,
					before.Enabled, before.Description)
				if err != nil {
					return restored, deleted, err
				}
				restored += int(tag.RowsAffected())
			}
		}
		switch profile.Action {
		case "delete":
			if profile.StateID == "" {
				continue
			}
			tag, err := tx.Exec(r.Context(), `DELETE FROM process_baseline_states WHERE id=$1::uuid AND org_id=$2`, profile.StateID, orgID)
			if err != nil {
				return restored, deleted, err
			}
			deleted += int(tag.RowsAffected())
		case "restore":
			if profile.Before == nil {
				continue
			}
			before := profile.Before
			tag, err := tx.Exec(r.Context(), `
UPDATE process_baseline_states
   SET cluster_id=$3::uuid, workload_id=$4, namespace=$5, name=$6, mode=$7,
       learn_started_at=$8, monitor_started_at=$9, enforce_started_at=$10,
       updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`,
				before.ID, orgID, before.ClusterID, before.WorkloadID, before.Namespace, before.Name,
				normalizeMigrationProcessProfileMode(before.Mode), before.LearnStartedAt,
				before.MonitorStartedAt, before.EnforceStartedAt)
			if err != nil {
				return restored, deleted, err
			}
			restored += int(tag.RowsAffected())
		}
	}
	return restored, deleted, nil
}

func (h *Enterprise) rollbackMigrationFileProfiles(r *http.Request, tx pgx.Tx, orgID uuid.UUID, profiles []migrationFileProfileRollbackDTO) (int, int, error) {
	var restored, deleted int
	for _, profile := range profiles {
		for _, rule := range profile.Rules {
			switch rule.Action {
			case "delete":
				if rule.ID == "" {
					continue
				}
				tag, err := tx.Exec(r.Context(), `DELETE FROM file_profile_rules WHERE id=$1::uuid AND org_id=$2`, rule.ID, orgID)
				if err != nil {
					return restored, deleted, err
				}
				deleted += int(tag.RowsAffected())
			case "restore":
				if rule.Before == nil {
					continue
				}
				before := rule.Before
				tag, err := tx.Exec(r.Context(), `
UPDATE file_profile_rules
   SET cluster_id=$3::uuid, workload_id=$4, filter=$5, path=$6, regex=$7,
       recursive=$8, behavior=$9, applications=$10, enabled=$11,
       description=$12, updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`,
					before.ID, orgID, before.ClusterID, before.WorkloadID, before.Filter, before.Path,
					before.Regex, before.Recursive, before.Behavior, before.Applications, before.Enabled,
					before.Description)
				if err != nil {
					return restored, deleted, err
				}
				restored += int(tag.RowsAffected())
			}
		}
		switch profile.Action {
		case "delete":
			if profile.StateID == "" {
				continue
			}
			tag, err := tx.Exec(r.Context(), `DELETE FROM file_profile_states WHERE id=$1::uuid AND org_id=$2`, profile.StateID, orgID)
			if err != nil {
				return restored, deleted, err
			}
			deleted += int(tag.RowsAffected())
		case "restore":
			if profile.Before == nil {
				continue
			}
			before := profile.Before
			tag, err := tx.Exec(r.Context(), `
UPDATE file_profile_states
   SET cluster_id=$3::uuid, workload_id=$4, namespace=$5, name=$6, mode=$7,
       learn_started_at=$8, monitor_started_at=$9, enforce_started_at=$10,
       updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`,
				before.ID, orgID, before.ClusterID, before.WorkloadID, before.Namespace, before.Name,
				normalizeMigrationFileProfileMode(before.Mode), before.LearnStartedAt, before.MonitorStartedAt,
				before.EnforceStartedAt)
			if err != nil {
				return restored, deleted, err
			}
			restored += int(tag.RowsAffected())
		}
	}
	return restored, deleted, nil
}

func (h *Enterprise) rollbackMigrationGroups(r *http.Request, tx pgx.Tx, orgID uuid.UUID, groups []migrationGroupRollbackDTO) (int, int, error) {
	var restored, deleted int
	for _, item := range groups {
		switch item.Action {
		case "delete":
			if item.ID == "" {
				continue
			}
			tag, err := tx.Exec(r.Context(), `DELETE FROM groups WHERE id=$1::uuid AND org_id=$2`, item.ID, orgID)
			if err != nil {
				return restored, deleted, err
			}
			deleted += int(tag.RowsAffected())
		case "restore":
			if item.Before == nil {
				continue
			}
			before := item.Before
			criteria := before.Criteria
			if len(criteria) == 0 {
				criteria = json.RawMessage(`[]`)
			}
			members := before.Members
			if len(members) == 0 {
				members = json.RawMessage(`[]`)
			}
			tag, err := tx.Exec(r.Context(), `
UPDATE groups
   SET cluster_id=$3::uuid, name=$4, kind=$5, comment=$6, criteria=$7::jsonb,
       members=$8::jsonb, learned_from=$9, cfg_type=$10, policy_mode=$11,
       profile_mode=$12, updated_at=NOW()
 WHERE id=$1::uuid AND org_id=$2`,
				before.ID, orgID, nullableUUIDText(before.ClusterID), before.Name, before.Kind, before.Comment,
				string(criteria), string(members), before.LearnedFrom, emptyDefault(before.CfgType, "user"),
				emptyDefault(before.PolicyMode, "monitor"), emptyDefault(before.ProfileMode, "monitor"))
			if err != nil {
				return restored, deleted, err
			}
			restored += int(tag.RowsAffected())
		}
	}
	return restored, deleted, nil
}

func (h *Enterprise) rollbackMigrationDPIBindings(r *http.Request, tx pgx.Tx, orgID uuid.UUID, bindings []migrationDPIBindingRollbackDTO) (int, int, error) {
	var restored, deleted int
	for _, item := range bindings {
		switch item.Action {
		case "delete":
			if item.ID == "" {
				continue
			}
			tag, err := tx.Exec(r.Context(), `DELETE FROM group_dpi_sensor_bindings WHERE id=$1::uuid AND org_id=$2`, item.ID, orgID)
			if err != nil {
				return restored, deleted, err
			}
			deleted += int(tag.RowsAffected())
		}
	}
	return restored, deleted, nil
}

func normalizeMigrationGroupKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "learned":
		return "learned"
	case "federated", "federal", "fed":
		return "federated"
	default:
		return "ground"
	}
}

func normalizeMigrationGroupCfgType(cfgType string) string {
	switch strings.ToLower(strings.TrimSpace(cfgType)) {
	case "learned":
		return "learned"
	case "fed", "federal":
		return "fed"
	default:
		return "user"
	}
}

func normalizeMigrationGroupMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "learn", "learning", "discover", "discovery":
		return "discover"
	case "protect", "enforce", "enforced":
		return "protect"
	default:
		return "monitor"
	}
}

func normalizeMigrationNetworkMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "learn", "learning", "discover", "discovery":
		return "discover"
	case "protect", "enforce", "enforced":
		return "protect"
	default:
		return "monitor"
	}
}

func normalizeMigrationFileProfileMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "protect", "enforce", "enforced":
		return "enforce"
	case "learn", "learning", "discover", "discovery":
		return "learn"
	default:
		return "monitor"
	}
}

func normalizeMigrationProcessProfileMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "protect", "enforce", "enforced":
		return "enforce"
	case "learn", "learning", "discover", "discovery":
		return "learn"
	default:
		return "monitor"
	}
}

func normalizeMigrationProcessRuleAction(action string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow":
		return "allow", nil
	case "deny", "alert":
		return "deny", nil
	default:
		return "", fmt.Errorf("process rule action must be allow or deny")
	}
}

func normalizeMigrationFileProfileRuleBehavior(behavior string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(behavior)) {
	case "", "monitor", "monitor_change":
		return "monitor_change", nil
	case "deny", "block", "block_access":
		return "block_access", nil
	default:
		return "", fmt.Errorf("behavior must be monitor_change or block_access")
	}
}

func normalizeMigrationApplications(apps []string) []string {
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

func parseMigrationFileProfileFilter(filter string) (migrationParsedFileProfileFilter, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter required")
	}
	if len(filter) > 512 {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter is too long")
	}
	if strings.ContainsRune(filter, '\x00') {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter contains invalid character")
	}
	if !strings.HasPrefix(filter, "/") {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter must be an absolute path")
	}
	if strings.ContainsAny(filter, "[]()<>") || strings.Contains(filter, "..") || strings.Contains(filter, "/./") {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter supports only absolute paths and simple * wildcards")
	}
	if strings.HasSuffix(filter, "/") {
		filter += "*"
	}
	cleaned := path.Clean(filter)
	if cleaned == "." || cleaned == "/" || cleaned == "/*" {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter must target a path below /")
	}
	derived := strings.ReplaceAll(cleaned, ".", "\\.")
	derived = strings.ReplaceAll(derived, "*", ".*")
	idx := strings.LastIndex(derived, "/")
	if idx < 0 {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter must be an absolute path")
	}
	base := derived[:idx]
	regex := derived[idx+1:]
	if regex == "" {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter must target a file or wildcard below /")
	}
	if !strings.Contains(regex, "*") {
		base += "/" + regex
		regex = ""
	}
	if _, err := regexp.Compile(base); err != nil {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter path wildcard is invalid")
	}
	if _, err := regexp.Compile(regex); err != nil {
		return migrationParsedFileProfileFilter{}, fmt.Errorf("filter wildcard is invalid")
	}
	return migrationParsedFileProfileFilter{Filter: cleaned, Path: base, Regex: regex}, nil
}

func migrationNetworkRuleKey(fromGroup, toGroup string) string {
	return strings.TrimSpace(fromGroup) + "\x00" + strings.TrimSpace(toGroup)
}

func nullableUUIDText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func normalizeMigrationMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "learn", "discover":
		return "learn"
	case "enforce", "protect":
		return "enforce"
	default:
		return "monitor"
	}
}

func normalizeMigrationDPICategory(category string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "dlp", "waf", "signature":
		return strings.ToLower(strings.TrimSpace(category)), nil
	default:
		return "", fmt.Errorf("category must be dlp, waf, or signature")
	}
}

func normalizeMigrationDPIMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "enforce", "protect":
		return "enforce"
	case "disabled", "disable":
		return "disabled"
	default:
		return "monitor"
	}
}

func migrationDPIRuleCfgType(rule migrationPreviewDPIRuleDTO) string {
	if rule.Federated {
		return "federated"
	}
	return "imported"
}

func defaultMigrationDPIApplyDir(category string) int16 {
	if category == "waf" {
		return 2
	}
	if category == "signature" {
		return 3
	}
	return 1
}

func normalizeMigrationDPISensorKind(kind string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "dlp", "waf":
		return strings.ToLower(strings.TrimSpace(kind)), nil
	default:
		return "", fmt.Errorf("sensor_kind must be dlp or waf")
	}
}

func defaultMigrationDPISensorID(kind string) uuid.UUID {
	switch kind {
	case "dlp":
		return uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	case "waf":
		return uuid.MustParse("00000000-0000-4000-8000-0000000000af")
	default:
		return uuid.Nil
	}
}

func migrationDPIPatternsJSON(patterns []migrationDPIPatternDTO) (json.RawMessage, error) {
	specs := make([]dlp.PatternSpec, 0, len(patterns))
	for _, pattern := range patterns {
		specs = append(specs, dlp.PatternSpec{
			Pattern: strings.TrimSpace(pattern.Pattern),
			Op:      strings.TrimSpace(pattern.Op),
			Context: strings.TrimSpace(pattern.Context),
		})
	}
	if err := dlp.ValidateSpecs(specs); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(specs)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func mergeAppliedCounts(dst map[string]int, src map[string]int) {
	for key, value := range src {
		dst[key] += value
	}
}

func emptyDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func (h *Enterprise) auditMigration(r *http.Request, subj Subject, action string, targetID string, after any) {
	if h == nil || h.audit == nil {
		return
	}
	oid, uid := subj.OrgID, subj.UserID
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: action, TargetKind: "migration-import", TargetID: targetID,
		After: after,
	})
}
