package policy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/response"
)

// ResponseRulesV2 is the NeuVector-style condition-catalog API. Distinct from the
// v1 ResponseRules handler which mutates the hardcoded catalog via override rows.
type ResponseRulesV2 struct {
	db       *db.DB
	auditLog *audit.Logger
}

func NewResponseRulesV2(d *db.DB, a *audit.Logger) *ResponseRulesV2 {
	return &ResponseRulesV2{db: d, auditLog: a}
}

type responseRuleV2DTO struct {
	ID            uuid.UUID                 `json:"id"`
	Name          string                    `json:"name"`
	Description   string                    `json:"description"`
	Enabled       bool                      `json:"enabled"`
	Priority      int                       `json:"priority"`
	EventType     string                    `json:"event_type"`
	Conditions    []response.Condition      `json:"conditions"`
	Actions       []response.Action         `json:"actions"`
	WorkloadMatch response.WorkloadSelector `json:"workload_match"`
	CreatedAt     time.Time                 `json:"created_at"`
	UpdatedAt     time.Time                 `json:"updated_at"`
}

type responseRuleV2Body struct {
	Name          string                    `json:"name"`
	Description   string                    `json:"description"`
	Enabled       bool                      `json:"enabled"`
	EventType     string                    `json:"event_type"`
	Conditions    []response.Condition      `json:"conditions"`
	Actions       []response.Action         `json:"actions"`
	WorkloadMatch response.WorkloadSelector `json:"workload_match"`
}

func (h *ResponseRulesV2) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, name, description, enabled, priority, event_type, conditions, actions, workload_match, created_at, updated_at
  FROM response_rules_v2
 WHERE org_id=$1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
 ORDER BY priority, name`, subj.OrgID, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []responseRuleV2DTO{}
	for rows.Next() {
		var d responseRuleV2DTO
		var conditions, actions, sel []byte
		if err := rows.Scan(&d.ID, &d.Name, &d.Description, &d.Enabled, &d.Priority, &d.EventType,
			&conditions, &actions, &sel, &d.CreatedAt, &d.UpdatedAt); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_ = json.Unmarshal(conditions, &d.Conditions)
		_ = json.Unmarshal(actions, &d.Actions)
		_ = json.Unmarshal(sel, &d.WorkloadMatch)
		out = append(out, d)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rules": out})
}

func (h *ResponseRulesV2) Create(w http.ResponseWriter, r *http.Request) {
	var body responseRuleV2Body
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	rule := response.Rule{
		Name:       strings.TrimSpace(body.Name),
		Enabled:    body.Enabled,
		EventType:  response.EventType(body.EventType),
		Conditions: body.Conditions,
		Actions:    body.Actions,
		Selector:   body.WorkloadMatch,
	}
	if err := rule.Validate(); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	conds, _ := json.Marshal(body.Conditions)
	acts, _ := json.Marshal(body.Actions)
	sel, _ := json.Marshal(body.WorkloadMatch)
	var id uuid.UUID
	// New rules append to the end of the evaluation order (lowest precedence) so adding
	// a rule never silently reshuffles existing precedence.
	if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO response_rules_v2 (org_id, cluster_id, name, description, enabled, priority, event_type, conditions, actions, workload_match, created_by)
VALUES ($1,$2,$3,$4,$5,
        (SELECT COALESCE(MAX(priority),0)+10 FROM response_rules_v2 WHERE org_id=$1),
        $6,$7,$8,$9,$10) RETURNING id`,
		subj.OrgID, clusterArg, rule.Name, body.Description, body.Enabled, body.EventType, conds, acts, sel, subj.UserID).Scan(&id); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "response_rule_v2.create", TargetKind: "response-rule-v2", TargetID: id.String(),
		After: map[string]any{"name": rule.Name}})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *ResponseRulesV2) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	var body responseRuleV2Body
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	rule := response.Rule{Name: body.Name, EventType: response.EventType(body.EventType),
		Conditions: body.Conditions, Actions: body.Actions, Selector: body.WorkloadMatch, Enabled: body.Enabled}
	if err := rule.Validate(); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	conds, _ := json.Marshal(body.Conditions)
	acts, _ := json.Marshal(body.Actions)
	sel, _ := json.Marshal(body.WorkloadMatch)
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE response_rules_v2 SET name=$1, description=$2, enabled=$3, event_type=$4,
       conditions=$5, actions=$6, workload_match=$7, updated_at=NOW()
 WHERE id=$8 AND org_id=$9`,
		body.Name, body.Description, body.Enabled, body.EventType, conds, acts, sel, id, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tag.RowsAffected() == 0 {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "response_rule_v2.update", TargetKind: "response-rule-v2", TargetID: id.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (h *ResponseRulesV2) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	if _, err := h.db.Pool().Exec(r.Context(), `DELETE FROM response_rules_v2 WHERE id=$1 AND org_id=$2`, id, subj.OrgID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "response_rule_v2.delete", TargetKind: "response-rule-v2", TargetID: id.String()})
	httpx.WriteJSON(w, http.StatusNoContent, nil)
}

type reorderBody struct {
	OrderedIDs []string `json:"ordered_ids"`
}

// Reorder sets the evaluation precedence of the org's response rules from a client-supplied
// ordered id list (top = evaluated first). NeuVector's insert-before/after/first/last, done
// as a whole-list reorder: the UI moves a row up/down and sends the new order. Priorities are
// reassigned 10,20,30… so later single-position inserts have room. PATCH /response-rules-v2:reorder
func (h *ResponseRulesV2) Reorder(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	var body reorderBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.OrderedIDs) == 0 {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "ordered_ids required"})
		return
	}
	ids := make([]uuid.UUID, 0, len(body.OrderedIDs))
	for _, s := range body.OrderedIDs {
		id, err := uuid.Parse(strings.TrimSpace(s))
		if err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id in ordered_ids"})
			return
		}
		ids = append(ids, id)
	}
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	for i, id := range ids {
		// org-scoped so a caller can only reorder their own rules; unknown ids no-op.
		if _, err := tx.Exec(r.Context(),
			`UPDATE response_rules_v2 SET priority=$1, updated_at=NOW() WHERE id=$2 AND org_id=$3`,
			(i+1)*10, id, subj.OrgID); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "response_rule_v2.reorder", TargetKind: "response-rule-v2", TargetID: "",
		After: map[string]any{"count": len(ids)}})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(ids)})
}
