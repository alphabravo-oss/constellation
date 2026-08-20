package runtime

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// GitOps YAML portability for DLP/WAF rules (NV parity). DLP rules are per-cluster, so both
// endpoints require ?cluster_id=. Only the authored config travels: name/category/apply_dir/
// severity/mode/patterns/scope_macs/description. Engine-assigned ids (dp_rule_id) and
// timestamps are never exported and are re-minted on import.

type portableDLPRule struct {
	Name        string   `yaml:"name" json:"name"`
	Category    string   `yaml:"category,omitempty" json:"category,omitempty"`
	ApplyDir    int16    `yaml:"apply_dir,omitempty" json:"apply_dir,omitempty"`
	Severity    int16    `yaml:"severity" json:"severity"`
	Mode        string   `yaml:"mode,omitempty" json:"mode,omitempty"`
	Patterns    []string `yaml:"patterns" json:"patterns"`
	ScopeMACs   []string `yaml:"scope_macs,omitempty" json:"scope_macs,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
}

type dlpBundle struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind" json:"kind"`
	Rules      []portableDLPRule `yaml:"rules" json:"rules"`
}

// Export serializes the cluster's DLP/WAF rules to a YAML bundle.
// GET /api/v1/runtime-dlp-rules:export?cluster_id=
func (h *RuntimeDLPHTTP) Export(w http.ResponseWriter, r *http.Request) {
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
	rows, err := h.store.ListForCluster(r.Context(), sub.OrgID, clusterID, "")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	bundle := dlpBundle{APIVersion: "constellation/v1", Kind: "DLPRuleBundle", Rules: []portableDLPRule{}}
	for _, rule := range rows {
		pats, _ := rule.DecodePatterns()
		bundle.Rules = append(bundle.Rules, portableDLPRule{
			Name: rule.Name, Category: string(rule.Category), ApplyDir: rule.ApplyDir,
			Severity: rule.Severity, Mode: string(rule.Mode), Patterns: pats,
			ScopeMACs: rule.ScopeMACs, Description: rule.Description,
		})
	}
	out, err := yaml.Marshal(bundle)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="constellation-dlp-rules.yaml"`)
	_, _ = w.Write(out)
}

// Import creates DLP rules from a YAML bundle into the target cluster. Existing rules (by
// name) are skipped rather than overwritten — a DLP rule carries an engine-assigned id and
// live match state, so import is create-only to avoid silently mutating an active rule. New
// rules always land in monitor mode (promotion is a separate, deliberate step).
// POST /api/v1/runtime-dlp-rules:import?cluster_id=
func (h *RuntimeDLPHTTP) Import(w http.ResponseWriter, r *http.Request) {
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
		mode := DLPModeMonitor
		if DLPMode(pr.Mode) == DLPModeDisabled {
			mode = DLPModeDisabled
		}
		patternsJSON, _ := json.Marshal(pr.Patterns)
		rule := &DLPRule{
			OrgID: sub.OrgID, ClusterID: clusterID,
			Name: strings.TrimSpace(pr.Name), Category: DLPCategory(pr.Category), ApplyDir: pr.ApplyDir,
			Severity: pr.Severity, Mode: mode, Patterns: patternsJSON,
			ScopeMACs: pr.ScopeMACs, Description: pr.Description, CreatedBy: &sub.UserID,
		}
		if _, err := h.store.Insert(r.Context(), rule, requestIDFrom(r)); err != nil {
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
