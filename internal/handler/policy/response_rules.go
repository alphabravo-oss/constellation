package policy

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type ResponseRules struct {
	db       *db.DB
	auditLog *audit.Logger
}

func NewResponseRules(args ...any) *ResponseRules {
	h := &ResponseRules{}
	for _, arg := range args {
		switch v := arg.(type) {
		case *db.DB:
			h.db = v
		case *audit.Logger:
			h.auditLog = v
		}
	}
	return h
}

type responseRuleDTO struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	EventType      string   `json:"event_type"`
	Match          string   `json:"match"`
	Actions        []string `json:"actions"`
	Mode           string   `json:"mode"`
	DefaultMode    string   `json:"default_mode"`
	Enabled        bool     `json:"enabled"`
	DefaultEnabled bool     `json:"default_enabled"`
	Severity       string   `json:"severity"`
	Source         string   `json:"source"`
	OverrideReason string   `json:"override_reason,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
	Managed        bool     `json:"managed"`
	Drifted        bool     `json:"drifted"`
}

type responseRuleUpdateBody struct {
	Mode    *string `json:"mode,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
	Reason  string  `json:"reason,omitempty"`
}

type responseRulePreviewDTO struct {
	RuleID             string   `json:"rule_id"`
	CurrentMode        string   `json:"current_mode"`
	NextMode           string   `json:"next_mode"`
	CurrentEnabled     bool     `json:"current_enabled"`
	NextEnabled        bool     `json:"next_enabled"`
	Actions            []string `json:"actions"`
	Persists           bool     `json:"persists"`
	RequiresPrivileged bool     `json:"requires_privileged_agent"`
	Impact             string   `json:"impact"`
	Warnings           []string `json:"warnings"`
}

func (h *ResponseRules) List(w http.ResponseWriter, r *http.Request) {
	rules := cloneResponseRulesCatalog()
	if h.db != nil {
		if subj, ok := authctx.SubjectFrom(r.Context()); ok {
			var err error
			rules, err = h.applyOverrides(r, subj.OrgID.String(), rules)
			if err != nil {
				httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"rules": rules,
		"summary": map[string]int{
			"total":    len(rules),
			"enabled":  countResponseRules(rules, func(r responseRuleDTO) bool { return r.Enabled }),
			"monitor":  countResponseRules(rules, func(r responseRuleDTO) bool { return r.Mode == "monitor" }),
			"enforce":  countResponseRules(rules, func(r responseRuleDTO) bool { return r.Mode == "enforce" }),
			"disabled": countResponseRules(rules, func(r responseRuleDTO) bool { return !r.Enabled }),
			"managed":  countResponseRules(rules, func(r responseRuleDTO) bool { return r.Managed }),
		},
	})
}

func (h *ResponseRules) Preview(w http.ResponseWriter, r *http.Request) {
	current, next, ok := h.ruleChangeFromRequest(w, r)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"preview": responseRulePreview(current, next, false)})
}

func (h *ResponseRules) Update(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "response rule storage unavailable"})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	current, next, ok := h.ruleChangeFromRequest(w, r)
	if !ok {
		return
	}
	// ENT-2: a fed (master-authored) override is read-only on a joint; it may only
	// change via the next sync, otherwise the joint drifts from its master.
	if isFed, err := handler.ResponseRuleOverrideIsFed(r.Context(), h.db.Pool(), subj.OrgID, current.ID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	} else if isFed {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]string{"error": handler.ErrFedReadOnly().Error()})
		return
	}
	if strings.TrimSpace(next.OverrideReason) == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "reason is required for response rule changes"})
		return
	}
	now := time.Now().UTC()
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO response_rule_overrides (org_id, rule_id, mode, enabled, reason, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,NOW())
ON CONFLICT (org_id, rule_id) DO UPDATE SET
    mode = EXCLUDED.mode,
    enabled = EXCLUDED.enabled,
    reason = EXCLUDED.reason,
    updated_by = EXCLUDED.updated_by,
    updated_at = NOW()`,
		subj.OrgID, next.ID, next.Mode, next.Enabled, next.OverrideReason, subj.UserID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	next.Managed = true
	next.Drifted = next.Mode != next.DefaultMode || next.Enabled != next.DefaultEnabled
	next.UpdatedAt = now.Format(time.RFC3339)
	h.logResponseRuleAudit(r, subj.OrgID, subj.UserID, current, next)
	// G3a: record a federated revision when this org is the master.
	handler.LogFedRevision(r.Context(), h.db.Pool(), subj.OrgID, "response_rule", next.ID, next)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"rule":    next,
		"preview": responseRulePreview(current, next, true),
	})
}

var responseRulesCatalog = []responseRuleDTO{
	{
		ID:             "container-process-shell",
		Name:           "Container shell spawned",
		Description:    "Detects interactive shells started inside application containers.",
		EventType:      "process",
		Match:          "process.name in [sh,bash,zsh] and container.image != trusted-tools",
		Actions:        []string{"alert", "capture_process_tree"},
		Mode:           "monitor",
		DefaultMode:    "monitor",
		Enabled:        true,
		DefaultEnabled: true,
		Severity:       "high",
		Source:         "NeuVector response rule",
	},
	{
		ID:             "network-unauthorized-egress",
		Name:           "Unauthorized external egress",
		Description:    "Flags workloads communicating with destinations outside learned policy.",
		EventType:      "network",
		Match:          "direction=egress and dst.zone=external and service not in allowlist",
		Actions:        []string{"alert", "quarantine_workload"},
		Mode:           "enforce",
		DefaultMode:    "enforce",
		Enabled:        true,
		DefaultEnabled: true,
		Severity:       "critical",
		Source:         "NeuVector response rule",
	},
	{
		ID:             "file-sensitive-path-write",
		Name:           "Sensitive path write",
		Description:    "Watches writes to certificate, token, and package manager paths.",
		EventType:      "file",
		Match:          "operation=write and path matches /etc/* or /var/run/secrets/*",
		Actions:        []string{"alert", "snapshot_pod"},
		Mode:           "monitor",
		DefaultMode:    "monitor",
		Enabled:        true,
		DefaultEnabled: true,
		Severity:       "medium",
		Source:         "NeuVector response rule",
	},
	{
		ID:             "admission-vulnerable-image",
		Name:           "Critical image admitted",
		Description:    "Responds when admission allows an image with critical unfixed CVEs.",
		EventType:      "admission",
		Match:          "image.critical_cves > 0 and namespace not in breakglass",
		Actions:        []string{"alert", "create_ticket"},
		Mode:           "monitor",
		DefaultMode:    "monitor",
		Enabled:        true,
		DefaultEnabled: true,
		Severity:       "critical",
		Source:         "Constellation policy bridge",
	},
	{
		ID:             "dlp-secret-exfiltration",
		Name:           "Secret exfiltration pattern",
		Description:    "Correlates outbound traffic with DLP findings for known secret formats.",
		EventType:      "dlp",
		Match:          "payload contains secret_pattern and direction=egress",
		Actions:        []string{"alert", "block_connection", "snapshot_pod"},
		Mode:           "learn",
		DefaultMode:    "learn",
		Enabled:        false,
		DefaultEnabled: false,
		Severity:       "high",
		Source:         "NeuVector response rule",
	},
}

func countResponseRules(rules []responseRuleDTO, match func(responseRuleDTO) bool) int {
	total := 0
	for _, rule := range rules {
		if match(rule) {
			total++
		}
	}
	return total
}

func cloneResponseRulesCatalog() []responseRuleDTO {
	out := make([]responseRuleDTO, len(responseRulesCatalog))
	copy(out, responseRulesCatalog)
	for i := range out {
		out[i].Actions = append([]string{}, responseRulesCatalog[i].Actions...)
		if out[i].DefaultMode == "" {
			out[i].DefaultMode = out[i].Mode
		}
		out[i].DefaultEnabled = out[i].Enabled
	}
	return out
}

func (h *ResponseRules) applyOverrides(r *http.Request, orgID string, rules []responseRuleDTO) ([]responseRuleDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT rule_id, mode, enabled, reason, updated_at
  FROM response_rule_overrides
 WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := map[string]int{}
	for i := range rules {
		byID[rules[i].ID] = i
	}
	for rows.Next() {
		var ruleID, mode, reason string
		var enabled bool
		var updatedAt time.Time
		if err := rows.Scan(&ruleID, &mode, &enabled, &reason, &updatedAt); err != nil {
			return nil, err
		}
		idx, ok := byID[ruleID]
		if !ok {
			continue
		}
		rules[idx].Mode = mode
		rules[idx].Enabled = enabled
		rules[idx].OverrideReason = reason
		rules[idx].UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		rules[idx].Managed = true
		rules[idx].Drifted = rules[idx].Mode != rules[idx].DefaultMode || rules[idx].Enabled != rules[idx].DefaultEnabled
	}
	return rules, rows.Err()
}

func (h *ResponseRules) ruleChangeFromRequest(w http.ResponseWriter, r *http.Request) (responseRuleDTO, responseRuleDTO, bool) {
	ruleID := strings.TrimSpace(chi.URLParam(r, "id"))
	current, found := findResponseRule(ruleID, cloneResponseRulesCatalog())
	if !found {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "response rule not found"})
		return responseRuleDTO{}, responseRuleDTO{}, false
	}
	if h.db != nil {
		if subj, ok := authctx.SubjectFrom(r.Context()); ok {
			rules, err := h.applyOverrides(r, subj.OrgID.String(), []responseRuleDTO{current})
			if err != nil {
				httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return responseRuleDTO{}, responseRuleDTO{}, false
			}
			current = rules[0]
		}
	}
	var body responseRuleUpdateBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return responseRuleDTO{}, responseRuleDTO{}, false
	}
	next := current
	if body.Mode != nil {
		mode := strings.TrimSpace(*body.Mode)
		if !validResponseRuleMode(mode) {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be learn, monitor, or enforce"})
			return responseRuleDTO{}, responseRuleDTO{}, false
		}
		next.Mode = mode
	}
	if body.Enabled != nil {
		next.Enabled = *body.Enabled
	}
	next.OverrideReason = strings.TrimSpace(body.Reason)
	next.Drifted = next.Mode != next.DefaultMode || next.Enabled != next.DefaultEnabled
	return current, next, true
}

func findResponseRule(ruleID string, rules []responseRuleDTO) (responseRuleDTO, bool) {
	for _, rule := range rules {
		if rule.ID == ruleID {
			return rule, true
		}
	}
	return responseRuleDTO{}, false
}

func validResponseRuleMode(mode string) bool {
	return mode == "learn" || mode == "monitor" || mode == "enforce"
}

func responseRulePreview(current, next responseRuleDTO, persists bool) responseRulePreviewDTO {
	warnings := []string{}
	if next.Mode == "enforce" && !next.Enabled {
		warnings = append(warnings, "enforce mode is configured but the rule is disabled")
	}
	if next.Mode == "enforce" && responseRuleRequiresPrivilegedAgent(next) {
		warnings = append(warnings, "enforcement depends on the privileged Linux runtime agent")
	}
	if next.Mode == "learn" {
		warnings = append(warnings, "learn mode records evidence but does not block")
	}
	impact := "No runtime behavior change."
	if current.Mode != next.Mode || current.Enabled != next.Enabled {
		impact = "Updates runtime response posture for " + next.Name + " from " + current.Mode + "/" + enabledWord(current.Enabled) + " to " + next.Mode + "/" + enabledWord(next.Enabled) + "."
	}
	return responseRulePreviewDTO{
		RuleID:             next.ID,
		CurrentMode:        current.Mode,
		NextMode:           next.Mode,
		CurrentEnabled:     current.Enabled,
		NextEnabled:        next.Enabled,
		Actions:            append([]string{}, next.Actions...),
		Persists:           persists,
		RequiresPrivileged: responseRuleRequiresPrivilegedAgent(next),
		Impact:             impact,
		Warnings:           warnings,
	}
}

func responseRuleRequiresPrivilegedAgent(rule responseRuleDTO) bool {
	if rule.EventType == "network" || rule.EventType == "dlp" || rule.EventType == "file" || rule.EventType == "process" {
		return true
	}
	for _, action := range rule.Actions {
		if action == "block_connection" || action == "quarantine_workload" || action == "snapshot_pod" || action == "capture_process_tree" {
			return true
		}
	}
	return false
}

func enabledWord(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func (h *ResponseRules) logResponseRuleAudit(r *http.Request, orgID, userID uuid.UUID, before, after responseRuleDTO) {
	if h.auditLog == nil {
		return
	}
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    actorIP,
		Action:     "response_rule.update",
		TargetKind: "response-rule",
		TargetID:   after.ID,
		Before: map[string]any{
			"mode":    before.Mode,
			"enabled": before.Enabled,
		},
		After: map[string]any{
			"mode":    after.Mode,
			"enabled": after.Enabled,
			"reason":  after.OverrideReason,
		},
		RequestID: chimw.GetReqID(r.Context()),
	})
}
