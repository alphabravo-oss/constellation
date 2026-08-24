package runtime

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/runtime/dlp"
)

// GitOps YAML portability for DLP/WAF rules (NV parity). DLP rules are per-cluster, so both
// endpoints require ?cluster_id=. Only the authored config travels: name/category/apply_dir/
// severity/mode/patterns/scope_macs/description. Engine-assigned ids (dp_rule_id) and
// timestamps are never exported and are re-minted on import.

type portableDLPRule struct {
	Name        string               `yaml:"name" json:"name"`
	Category    string               `yaml:"category,omitempty" json:"category,omitempty"`
	ApplyDir    int16                `yaml:"apply_dir,omitempty" json:"apply_dir,omitempty"`
	Severity    int16                `yaml:"severity" json:"severity"`
	Mode        string               `yaml:"mode,omitempty" json:"mode,omitempty"`
	Patterns    []portableDLPPattern `yaml:"patterns" json:"patterns"`
	ScopeMACs   []string             `yaml:"scope_macs,omitempty" json:"scope_macs,omitempty"`
	Description string               `yaml:"description,omitempty" json:"description,omitempty"`
	Source      string               `yaml:"source,omitempty" json:"source,omitempty"`
	CfgType     string               `yaml:"cfg_type,omitempty" json:"cfg_type,omitempty"`
	SourcePath  string               `yaml:"source_path,omitempty" json:"source_path,omitempty"`
}

type dlpBundle struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind" json:"kind"`
	Rules      []portableDLPRule `yaml:"rules" json:"rules"`
}

type portableDLPPattern struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	Op      string `yaml:"op,omitempty" json:"op,omitempty"`
	Context string `yaml:"context,omitempty" json:"context,omitempty"`
}

func (p portableDLPPattern) MarshalYAML() (any, error) {
	if strings.TrimSpace(p.Op) == "" && strings.TrimSpace(p.Context) == "" {
		return p.Pattern, nil
	}
	type pattern portableDLPPattern
	return pattern(p), nil
}

func (p *portableDLPPattern) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		p.Pattern = value.Value
		p.Op = ""
		p.Context = ""
		return nil
	}
	type pattern portableDLPPattern
	var decoded pattern
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*p = portableDLPPattern(decoded)
	return nil
}

// Export serializes the cluster's DLP rules to a YAML bundle.
// GET /api/v1/runtime-dlp-rules:export?cluster_id=
func (h *RuntimeDLPHTTP) Export(w http.ResponseWriter, r *http.Request) {
	exportRuntimeDLPBundle(w, r, h.store, "DLPRuleBundle", "constellation-dlp-rules.yaml", CategoryDLP)
}

// Import creates DLP rules from a YAML bundle into the target cluster. Existing rules (by
// name) are skipped rather than overwritten — a DLP rule carries an engine-assigned id and
// live match state, so import is create-only to avoid silently mutating an active rule. New
// rules always land in monitor mode (promotion is a separate, deliberate step).
// POST /api/v1/runtime-dlp-rules:import?cluster_id=
func (h *RuntimeDLPHTTP) Import(w http.ResponseWriter, r *http.Request) {
	importRuntimeDLPBundle(w, r, h.store, CategoryDLP, map[DLPCategory]bool{CategoryDLP: true})
}

// Export serializes custom DPI signatures plus imported WAF rules to a YAML bundle.
// GET /api/v1/runtime-signatures:export?cluster_id=
func (h *RuntimeSignaturesHTTP) Export(w http.ResponseWriter, r *http.Request) {
	exportRuntimeDLPBundle(w, r, h.store, "DPISignatureBundle", "constellation-dpi-signatures.yaml", CategorySignature, CategoryWAF)
}

// Import creates custom DPI signatures and WAF rules from a YAML bundle.
// POST /api/v1/runtime-signatures:import?cluster_id=
func (h *RuntimeSignaturesHTTP) Import(w http.ResponseWriter, r *http.Request) {
	importRuntimeDLPBundle(w, r, h.store, CategorySignature, map[DLPCategory]bool{CategorySignature: true, CategoryWAF: true})
}

func exportRuntimeDLPBundle(w http.ResponseWriter, r *http.Request, store *RuntimeDLPStore, kind, filename string, categories ...DLPCategory) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	rows := []*DLPRule{}
	for _, category := range categories {
		categoryRows, err := store.ListForCluster(r.Context(), sub.OrgID, clusterID, category)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		rows = append(rows, categoryRows...)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].Name < rows[j].Name
	})
	bundle := dlpBundle{APIVersion: "constellation/v1", Kind: kind, Rules: []portableDLPRule{}}
	for _, rule := range rows {
		patterns := portablePatterns(rule)
		bundle.Rules = append(bundle.Rules, portableDLPRule{
			Name: rule.Name, Category: string(rule.Category), ApplyDir: rule.ApplyDir,
			Severity: rule.Severity, Mode: string(rule.Mode), Patterns: patterns,
			ScopeMACs: rule.ScopeMACs, Description: rule.Description,
			Source: rule.Source, CfgType: rule.CfgType, SourcePath: rule.SourcePath,
		})
	}
	out, err := yaml.Marshal(bundle)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write(out)
}

func importRuntimeDLPBundle(w http.ResponseWriter, r *http.Request, store *RuntimeDLPStore, defaultCategory DLPCategory, allowed map[DLPCategory]bool) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "read body")
		return
	}
	var bundle dlpBundle
	if err := yaml.Unmarshal(raw, &bundle); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid bundle: "+err.Error())
		return
	}
	if len(bundle.Rules) == 0 {
		jsonError(w, http.StatusBadRequest, "bundle contains no rules")
		return
	}
	type result struct {
		Name   string `json:"name"`
		Status string `json:"status"` // created | skipped | error
		Error  string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(bundle.Rules))
	created := 0
	for _, pr := range bundle.Rules {
		res := result{Name: pr.Name}
		category := DLPCategory(strings.TrimSpace(pr.Category))
		if category == "" {
			category = defaultCategory
		}
		if !allowed[category] {
			res.Status = "error"
			res.Error = "category " + string(category) + " is not accepted by this endpoint"
			results = append(results, res)
			continue
		}
		mode := DLPModeMonitor
		if DLPMode(pr.Mode) == DLPModeDisabled {
			mode = DLPModeDisabled
		}
		patternsJSON, err := json.Marshal(portablePatternSpecs(pr.Patterns))
		if err != nil {
			res.Status, res.Error = "error", err.Error()
			results = append(results, res)
			continue
		}
		rule := &DLPRule{
			OrgID: sub.OrgID, ClusterID: clusterID,
			Name: strings.TrimSpace(pr.Name), Category: category, ApplyDir: pr.ApplyDir,
			Severity: pr.Severity, Mode: mode, Patterns: patternsJSON,
			ScopeMACs: pr.ScopeMACs, Description: pr.Description, CreatedBy: &sub.UserID,
			Source:     emptyDefaultString(pr.Source, "import"),
			CfgType:    emptyDefaultString(pr.CfgType, "imported"),
			SourcePath: strings.TrimSpace(pr.SourcePath),
		}
		if _, err := store.Insert(r.Context(), rule, requestIDFrom(r)); err != nil {
			if strings.Contains(err.Error(), "duplicate") {
				res.Status = "skipped"
			} else {
				res.Status, res.Error = "error", err.Error()
			}
			results = append(results, res)
			continue
		}
		res.Status = "created"
		created++
		results = append(results, res)
	}
	updated := 0 // DLP import is create-only (see doc comment); reported for a uniform client shape.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"created": created, "updated": updated, "results": results})
}

func emptyDefaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func portablePatterns(rule *DLPRule) []portableDLPPattern {
	specs, err := rule.DecodePatternSpecs()
	if err == nil {
		out := make([]portableDLPPattern, 0, len(specs))
		for _, spec := range specs {
			out = append(out, portableDLPPattern{Pattern: spec.Pattern, Op: spec.Op, Context: spec.Context})
		}
		return out
	}
	legacy, _ := rule.DecodePatterns()
	out := make([]portableDLPPattern, 0, len(legacy))
	for _, pattern := range legacy {
		out = append(out, portableDLPPattern{Pattern: pattern})
	}
	return out
}

func portablePatternSpecs(patterns []portableDLPPattern) []dlp.PatternSpec {
	out := make([]dlp.PatternSpec, 0, len(patterns))
	for _, pattern := range patterns {
		out = append(out, dlp.PatternSpec{
			Pattern: strings.TrimSpace(pattern.Pattern),
			Op:      strings.TrimSpace(pattern.Op),
			Context: strings.TrimSpace(pattern.Context),
		})
	}
	return out
}
