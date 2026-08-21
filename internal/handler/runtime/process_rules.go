// Process Profile Rules — per-process allow/deny CRUD attached to a workload's process
// baseline (NeuVector parity). NV attaches an editable allow/deny process rule list to
// each group; Constellation's baselines were mode-only with a read-only learned-exec
// list. These handlers author the rule object (name/path/action/user/allow_update) so an
// operator can allow or deny a specific process from the console.
//
//	GET    /api/v1/runtime/baselines/{workload_id}/rules
//	POST   /api/v1/runtime/baselines/{workload_id}/rules
//	PUT    /api/v1/runtime/baselines/{workload_id}/rules/{rule_id}
//	DELETE /api/v1/runtime/baselines/{workload_id}/rules/{rule_id}
//
// ponytail: rules are stored + surfaced in the console; distribution to the runtime
// agent (via the process baseline bundle) is a follow-up — the agent runs monitor-only
// today, so authored rules are advisory until the bundle carries them.
package runtime

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type processRuleDTO struct {
	RuleID      string `json:"rule_id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Sha256      string `json:"sha256"`
	ParentName  string `json:"parent_name"`
	Action      string `json:"action"`
	User        string `json:"user"`
	AllowUpdate bool   `json:"allow_update"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	UpdatedAt   string `json:"updated_at"`
}

type processRuleBody struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Sha256      string `json:"sha256"`
	ParentName  string `json:"parent_name"`
	Action      string `json:"action"`
	User        string `json:"user"`
	AllowUpdate bool   `json:"allow_update"`
	Enabled     *bool  `json:"enabled"`
	Description string `json:"description"`
}

// loadProcessRules returns the authored allow/deny rules for a workload. Degrades to an
// empty list if the table hasn't been migrated yet, so the baseline page never blanks.
func (h *Baselines) loadProcessRules(ctx context.Context, orgID uuid.UUID, clusterID, workloadID string) []processRuleDTO {
	out := []processRuleDTO{}
	cid, err := uuid.Parse(clusterID)
	if err != nil {
		return out
	}
	rows, err := h.db.Pool().Query(ctx, `
SELECT id::text, name, path, COALESCE(sha256,''), COALESCE(parent_name,''), action, proc_user, allow_update, enabled, description, updated_at
  FROM process_profile_rules
 WHERE org_id = $1 AND cluster_id = $2 AND workload_id = $3
 ORDER BY action DESC, name`, orgID, cid, workloadID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var d processRuleDTO
		var updated time.Time
		if err := rows.Scan(&d.RuleID, &d.Name, &d.Path, &d.Sha256, &d.ParentName, &d.Action, &d.User, &d.AllowUpdate, &d.Enabled, &d.Description, &updated); err != nil {
			return out
		}
		d.UpdatedAt = updated.UTC().Format(time.RFC3339)
		out = append(out, d)
	}
	return out
}

func (h *Baselines) resolveRuleWorkload(w http.ResponseWriter, r *http.Request) (authctx.Subject, observedWorkload, bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return subj, observedWorkload{}, false
	}
	workloadID := workloadIDParam(r)
	if workloadID == "" {
		jsonError(w, http.StatusBadRequest, "workload_id required")
		return subj, observedWorkload{}, false
	}
	wl, found, err := h.findWorkload(r.Context(), subj.OrgID, nil, workloadID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return subj, observedWorkload{}, false
	}
	if !found {
		jsonError(w, http.StatusNotFound, "workload not found")
		return subj, observedWorkload{}, false
	}
	return subj, wl, true
}

func normalizeProcessRuleBody(b processRuleBody) (processRuleBody, error) {
	b.Name = strings.TrimSpace(b.Name)
	b.Path = strings.TrimSpace(b.Path)
	b.Sha256 = strings.ToLower(strings.TrimSpace(b.Sha256))
	b.ParentName = strings.TrimSpace(b.ParentName)
	b.User = strings.TrimSpace(b.User)
	if b.Name == "" && b.Path == "" {
		return b, errProcessRule("name or path is required")
	}
	if b.Action != "deny" {
		b.Action = "allow"
	}
	return b, nil
}

type errProcessRule string

func (e errProcessRule) Error() string { return string(e) }

// ListRules returns the authored process rules for a workload.
func (h *Baselines) ListRules(w http.ResponseWriter, r *http.Request) {
	subj, wl, ok := h.resolveRuleWorkload(w, r)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rules": h.loadProcessRules(r.Context(), subj.OrgID, wl.ClusterID, wl.WorkloadID)})
}

// CreateRule authors a new allow/deny process rule (upsert on name+path).
func (h *Baselines) CreateRule(w http.ResponseWriter, r *http.Request) {
	subj, wl, ok := h.resolveRuleWorkload(w, r)
	if !ok {
		return
	}
	var body processRuleBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	body, err := normalizeProcessRuleBody(body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	cid, _ := uuid.Parse(wl.ClusterID)
	var d processRuleDTO
	var updated time.Time
	err = h.db.Pool().QueryRow(r.Context(), `
INSERT INTO process_profile_rules
  (org_id, cluster_id, workload_id, name, path, sha256, parent_name, action, proc_user, allow_update, enabled, description, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)
ON CONFLICT (org_id, cluster_id, workload_id, name, path) DO UPDATE SET
  sha256 = EXCLUDED.sha256, parent_name = EXCLUDED.parent_name,
  action = EXCLUDED.action, proc_user = EXCLUDED.proc_user, allow_update = EXCLUDED.allow_update,
  enabled = EXCLUDED.enabled, description = EXCLUDED.description, updated_by = EXCLUDED.updated_by, updated_at = NOW()
RETURNING id::text, name, path, COALESCE(sha256,''), COALESCE(parent_name,''), action, proc_user, allow_update, enabled, description, updated_at`,
		subj.OrgID, cid, wl.WorkloadID, body.Name, body.Path, body.Sha256, body.ParentName, body.Action, body.User, body.AllowUpdate, enabled, body.Description, subj.UserID).
		Scan(&d.RuleID, &d.Name, &d.Path, &d.Sha256, &d.ParentName, &d.Action, &d.User, &d.AllowUpdate, &d.Enabled, &d.Description, &updated)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.UpdatedAt = updated.UTC().Format(time.RFC3339)
	h.auditProcessRule(r, subj, "process_profile.rule.upsert", wl.WorkloadID, d)
	httpx.WriteJSON(w, http.StatusCreated, d)
}

// UpdateRule edits an existing process rule by id.
func (h *Baselines) UpdateRule(w http.ResponseWriter, r *http.Request) {
	subj, wl, ok := h.resolveRuleWorkload(w, r)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "rule_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid rule_id")
		return
	}
	var body processRuleBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	body, err = normalizeProcessRuleBody(body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	cid, _ := uuid.Parse(wl.ClusterID)
	var d processRuleDTO
	var updated time.Time
	err = h.db.Pool().QueryRow(r.Context(), `
UPDATE process_profile_rules
   SET name = $1, path = $2, sha256 = $3, parent_name = $4, action = $5, proc_user = $6, allow_update = $7,
       enabled = $8, description = $9, updated_by = $10, updated_at = NOW()
 WHERE org_id = $11 AND cluster_id = $12 AND workload_id = $13 AND id = $14
RETURNING id::text, name, path, COALESCE(sha256,''), COALESCE(parent_name,''), action, proc_user, allow_update, enabled, description, updated_at`,
		body.Name, body.Path, body.Sha256, body.ParentName, body.Action, body.User, body.AllowUpdate, enabled, body.Description, subj.UserID,
		subj.OrgID, cid, wl.WorkloadID, ruleID).
		Scan(&d.RuleID, &d.Name, &d.Path, &d.Sha256, &d.ParentName, &d.Action, &d.User, &d.AllowUpdate, &d.Enabled, &d.Description, &updated)
	if err != nil {
		jsonError(w, http.StatusNotFound, "rule not found")
		return
	}
	d.UpdatedAt = updated.UTC().Format(time.RFC3339)
	h.auditProcessRule(r, subj, "process_profile.rule.update", wl.WorkloadID, d)
	httpx.WriteJSON(w, http.StatusOK, d)
}

// DeleteRule removes a process rule by id.
func (h *Baselines) DeleteRule(w http.ResponseWriter, r *http.Request) {
	subj, wl, ok := h.resolveRuleWorkload(w, r)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "rule_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid rule_id")
		return
	}
	cid, _ := uuid.Parse(wl.ClusterID)
	tag, err := h.db.Pool().Exec(r.Context(), `
DELETE FROM process_profile_rules
 WHERE org_id = $1 AND cluster_id = $2 AND workload_id = $3 AND id = $4`,
		subj.OrgID, cid, wl.WorkloadID, ruleID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "rule not found")
		return
	}
	h.auditProcessRule(r, subj, "process_profile.rule.delete", wl.WorkloadID, processRuleDTO{RuleID: ruleID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": ruleID.String()})
}

func (h *Baselines) auditProcessRule(r *http.Request, subj authctx.Subject, action, workloadID string, d processRuleDTO) {
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
		Action:     action,
		TargetKind: "process-baseline-rule",
		TargetID:   workloadID,
		After:      map[string]any{"rule_id": d.RuleID, "name": d.Name, "path": d.Path, "action": d.Action, "enabled": d.Enabled},
		RequestID:  chimw.GetReqID(r.Context()),
	})
}
