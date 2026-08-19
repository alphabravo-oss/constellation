package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/migration/aqua"
	"github.com/alphabravocompany/constellation/internal/migration/neuvector"
	"github.com/alphabravocompany/constellation/internal/migration/prisma"
	"github.com/alphabravocompany/constellation/internal/migration/stackrox"
)

type migrationPreviewRequest struct {
	Source string `json:"source"`
	Export string `json:"export"`
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
	Group       string                       `json:"group"`
	Mode        string                       `json:"mode"`
	CfgType     string                       `json:"cfg_type,omitempty"`
	Description string                       `json:"description,omitempty"`
	Rules       []fileProfilePortableRuleDTO `json:"rules"`
	Imported    map[string]string            `json:"imported_from,omitempty"`
	DiffAction  string                       `json:"diff_action"`
}

type migrationPreviewSummaryDTO struct {
	Source       string         `json:"source"`
	Total        int            `json:"total"`
	Create       int            `json:"create"`
	Update       int            `json:"update"`
	Enforce      int            `json:"enforce"`
	Monitor      int            `json:"monitor"`
	Enabled      int            `json:"enabled"`
	FileProfiles int            `json:"file_profiles"`
	Engines      map[string]int `json:"engines"`
	Categories   map[string]int `json:"categories"`
	ReadOnly     bool           `json:"read_only"`
	RollbackHint string         `json:"rollback_hint"`
}

type migrationPreviewDTO struct {
	Summary        migrationPreviewSummaryDTO       `json:"summary"`
	Policies       []migrationPreviewPolicyDTO      `json:"policies"`
	FileProfiles   []migrationPreviewFileProfileDTO `json:"file_profiles"`
	RollbackBundle string                           `json:"rollback_bundle"`
}

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

	policies, err := convertMigrationPreview(source, raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	fileProfiles, err := convertMigrationFileProfiles(source, raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	existing, _ := h.existingPolicyNames(r, subj.OrgID.String())
	for i := range policies {
		if existing[policies[i].Name] {
			policies[i].DiffAction = "update"
		} else {
			policies[i].DiffAction = "create"
		}
	}

	out := migrationPreviewDTO{
		Summary:        summarizeMigrationPreview(source, policies, fileProfiles),
		Policies:       policies,
		FileProfiles:   fileProfiles,
		RollbackBundle: renderMigrationRollbackBundle(source, policies, fileProfiles),
	}
	writeJSON(w, http.StatusOK, out)
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

func summarizeMigrationPreview(source string, policies []migrationPreviewPolicyDTO, fileProfiles []migrationPreviewFileProfileDTO) migrationPreviewSummaryDTO {
	summary := migrationPreviewSummaryDTO{
		Source:       source,
		Total:        len(policies) + len(fileProfiles),
		FileProfiles: len(fileProfiles),
		Engines:      map[string]int{},
		Categories:   map[string]int{},
		ReadOnly:     true,
		RollbackHint: "Preview only. Apply will require an audited rollback bundle before persistence.",
	}
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
	return summary
}

func renderMigrationRollbackBundle(source string, policies []migrationPreviewPolicyDTO, fileProfiles []migrationPreviewFileProfileDTO) string {
	names := make([]string, 0, len(policies))
	for _, policy := range policies {
		names = append(names, policy.Name)
	}
	groups := make([]string, 0, len(fileProfiles))
	for _, profile := range fileProfiles {
		groups = append(groups, profile.Group)
	}
	b, _ := json.MarshalIndent(map[string]any{
		"source":              source,
		"generated_at":        time.Now().UTC().Format(time.RFC3339),
		"read_only":           true,
		"policy_names":        names,
		"file_profile_groups": groups,
		"actions":             []string{"delete newly-created policies", "restore previous policy versions for updates", "restore previous file profile bundles for migrated groups"},
	}, "", "  ")
	return string(b)
}
