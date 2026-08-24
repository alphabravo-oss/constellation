package network

import (
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Network-rule YAML portability exports authored policy intent only: manual
// rules and learned-rule overrides. Pure learned observations are runtime data
// and are intentionally omitted.

type portableNetworkRule struct {
	From         string   `yaml:"from" json:"from"`
	To           string   `yaml:"to" json:"to"`
	Ports        string   `yaml:"ports,omitempty" json:"ports,omitempty"`
	Applications []string `yaml:"applications,omitempty" json:"applications,omitempty"`
	Action       string   `yaml:"action,omitempty" json:"action,omitempty"`
	Disable      bool     `yaml:"disable,omitempty" json:"disable,omitempty"`
	Comment      string   `yaml:"comment,omitempty" json:"comment,omitempty"`
	Priority     int      `yaml:"priority,omitempty" json:"priority,omitempty"`
	CfgType      string   `yaml:"cfg_type,omitempty" json:"cfg_type,omitempty"`
}

type networkRuleBundle struct {
	APIVersion string                `yaml:"apiVersion" json:"apiVersion"`
	Kind       string                `yaml:"kind" json:"kind"`
	Rules      []portableNetworkRule `yaml:"rules" json:"rules"`
}

// ExportNetworkRules serializes manual network rules and learned overrides.
// GET /api/v1/clusters/{id}/network-rules:export
func (h *Network) ExportNetworkRules(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	clusterID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster id"})
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT from_ep, to_ep, ports, applications, action, disable, comment, priority, cfg_type
  FROM network_rule_overrides
 WHERE org_id = $1 AND cluster_id = $2
 ORDER BY priority, from_ep, to_ep`, subj.OrgID, clusterID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	bundle := networkRuleBundle{APIVersion: "constellation/v1", Kind: "NetworkRuleBundle", Rules: []portableNetworkRule{}}
	for rows.Next() {
		var rule portableNetworkRule
		if err := rows.Scan(&rule.From, &rule.To, &rule.Ports, &rule.Applications, &rule.Action, &rule.Disable, &rule.Comment, &rule.Priority, &rule.CfgType); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		bundle.Rules = append(bundle.Rules, rule)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out, err := yaml.Marshal(bundle)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="constellation-network-rules.yaml"`)
	_, _ = w.Write(out)
}

// ImportNetworkRules upserts manual network rules and learned overrides into a
// target cluster. The imported cfg_type is advisory; the target cluster's learned
// flow history decides whether each row is a user_created rule or learned_override.
// POST /api/v1/clusters/{id}/network-rules:import
func (h *Network) ImportNetworkRules(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	clusterID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster id"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	var bundle networkRuleBundle
	if err := yaml.Unmarshal(raw, &bundle); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid bundle: " + err.Error()})
		return
	}
	if len(bundle.Rules) == 0 {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bundle contains no rules"})
		return
	}
	type result struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Status string `json:"status"` // created | updated | error
		Error  string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(bundle.Rules))
	created, updated := 0, 0
	for _, rule := range bundle.Rules {
		rule.From = strings.TrimSpace(rule.From)
		rule.To = strings.TrimSpace(rule.To)
		res := result{From: rule.From, To: rule.To}
		if rule.From == "" || rule.To == "" {
			res.Status, res.Error = "error", "from and to are required"
			results = append(results, res)
			continue
		}
		if rule.Action != "deny" {
			rule.Action = "allow"
		}
		if strings.TrimSpace(rule.Ports) == "" {
			rule.Ports = "any"
		}
		if rule.Priority <= 0 {
			rule.Priority = 1000
		}
		rule.Applications = normalizeNetworkRuleApplications(rule.Applications)
		cfgType := "user_created"
		var learned bool
		_ = h.db.Pool().QueryRow(r.Context(), `
SELECT EXISTS (
  SELECT 1 FROM network_flow_rollups
   WHERE org_id = $1 AND cluster_id = $2 AND src_workload = $3 AND dst_workload = $4)`,
			subj.OrgID, clusterID, rule.From, rule.To).Scan(&learned)
		if learned {
			cfgType = "learned_override"
		}
		var wasInsert bool
		if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO network_rule_overrides
  (org_id, cluster_id, from_ep, to_ep, ports, applications, action, disable, comment, priority, cfg_type, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
ON CONFLICT (org_id, cluster_id, from_ep, to_ep) DO UPDATE SET
  ports = EXCLUDED.ports, applications = EXCLUDED.applications, action = EXCLUDED.action,
  disable = EXCLUDED.disable, comment = EXCLUDED.comment, priority = EXCLUDED.priority,
  cfg_type = EXCLUDED.cfg_type, updated_by = EXCLUDED.updated_by, updated_at = NOW()
RETURNING (xmax = 0)`,
			subj.OrgID, clusterID, rule.From, rule.To, rule.Ports, rule.Applications,
			rule.Action, rule.Disable, rule.Comment, rule.Priority, cfgType, subj.UserID).Scan(&wasInsert); err != nil {
			res.Status, res.Error = "error", err.Error()
			results = append(results, res)
			continue
		}
		if wasInsert {
			res.Status = "created"
			created++
		} else {
			res.Status = "updated"
			updated++
		}
		results = append(results, res)
	}
	if h.audit != nil {
		oid, uid := subj.OrgID, subj.UserID
		_, _, _ = h.audit.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
			Action: "network_rule.import", TargetKind: "network_rule", TargetID: "",
			After: map[string]any{"cluster_id": clusterID.String(), "created": created, "updated": updated, "total": len(bundle.Rules)}})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"created": created, "updated": updated, "results": results})
}

func normalizeNetworkRuleApplications(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, app := range in {
		app = strings.TrimSpace(app)
		if app == "" {
			continue
		}
		if _, ok := seen[app]; ok {
			continue
		}
		seen[app] = struct{}{}
		out = append(out, app)
	}
	return out
}
