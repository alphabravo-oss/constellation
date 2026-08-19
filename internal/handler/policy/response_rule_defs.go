// E1 — declarative response-rule engine: server-side CRUD, evaluation, webhook
// delivery, and the agent :sync bundle.
//
// ResponseRuleDefs is the RBAC-gated CRUD surface (gated by rbac.VerbManageResponseRules
// in the router) over the response_rules table. It also hosts:
//   - Evaluate: the server-side evaluation entry point. Given a runtime event it loads the
//     org's enabled rules, returns the ordered matching actions (pure pkg/responserule),
//     and fires any webhook actions through the existing pkg/notify dispatcher.
//   - AgentSyncBundle: the agent-facing :sync pull (runtime-agent-token auth) that serves
//     the enabled rules to the runtime-agent, mirroring the other :bundle pull endpoints.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// ResponseRuleDefs is the E1 declarative response-rule handler. dispatcher is optional —
// when nil, webhook actions are recorded but not delivered (matching the other handlers'
// nil-dispatcher tolerance).
type ResponseRuleDefs struct {
	db         *db.DB
	auditLog   *audit.Logger
	dispatcher *notify.Dispatcher
}

// NewResponseRuleDefs constructs the handler. Call WithDispatcher to wire webhook delivery.
func NewResponseRuleDefs(d *db.DB, a *audit.Logger) *ResponseRuleDefs {
	return &ResponseRuleDefs{db: d, auditLog: a}
}

// WithDispatcher wires the notify dispatcher used to deliver webhook actions.
func (h *ResponseRuleDefs) WithDispatcher(d *notify.Dispatcher) *ResponseRuleDefs {
	h.dispatcher = d
	return h
}

type responseRuleDefDTO struct {
	ID         uuid.UUID                `json:"id"`
	Name       string                   `json:"name"`
	Enabled    bool                     `json:"enabled"`
	Priority   int                      `json:"priority"`
	EventType  responserule.EventType   `json:"event_type"`
	Conditions []responserule.Condition `json:"conditions"`
	Actions    []responserule.Action    `json:"actions"`
	CreatedAt  time.Time                `json:"created_at"`
	UpdatedAt  time.Time                `json:"updated_at"`
}

type responseRuleDefBody struct {
	Name       string                   `json:"name"`
	Enabled    bool                     `json:"enabled"`
	Priority   int                      `json:"priority"`
	EventType  responserule.EventType   `json:"event_type"`
	Conditions []responserule.Condition `json:"conditions"`
	Actions    []responserule.Action    `json:"actions"`
}

func (b *responseRuleDefBody) toRule(orgID uuid.UUID) responserule.ResponseRule {
	conds := b.Conditions
	if conds == nil {
		conds = []responserule.Condition{}
	}
	acts := b.Actions
	if acts == nil {
		acts = []responserule.Action{}
	}
	return responserule.ResponseRule{
		OrgID:      orgID,
		Name:       b.Name,
		Enabled:    b.Enabled,
		Priority:   b.Priority,
		EventType:  b.EventType,
		Conditions: conds,
		Actions:    acts,
	}
}

// List returns the org's response rules ordered by priority then name.
func (h *ResponseRuleDefs) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	rules, err := h.loadRules(r.Context(), subj.OrgID, false)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]responseRuleDefDTO, 0, len(rules))
	for i := range rules {
		out = append(out, toDTO(rules[i]))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rules": out})
}

// Get returns a single rule by id (scoped to the caller's org).
func (h *ResponseRuleDefs) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	var d responseRuleDefDTO
	var conds, acts []byte
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT id, name, enabled, priority, event_type, conditions, actions, created_at, updated_at
  FROM response_rules WHERE id=$1 AND org_id=$2`, id, subj.OrgID).
		Scan(&d.ID, &d.Name, &d.Enabled, &d.Priority, &d.EventType, &conds, &acts, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	_ = json.Unmarshal(conds, &d.Conditions)
	_ = json.Unmarshal(acts, &d.Actions)
	httpx.WriteJSON(w, http.StatusOK, d)
}

// Create validates and inserts a new rule.
func (h *ResponseRuleDefs) Create(w http.ResponseWriter, r *http.Request) {
	var body responseRuleDefBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	rule := body.toRule(subj.OrgID)
	if err := rule.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.validateReceivers(r.Context(), subj.OrgID, rule); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	conds, _ := json.Marshal(rule.Conditions)
	acts, _ := json.Marshal(rule.Actions)
	var id uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO response_rules (org_id, name, enabled, priority, event_type, conditions, actions, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		subj.OrgID, rule.Name, rule.Enabled, rule.Priority, rule.EventType, conds, acts, subj.UserID).Scan(&id); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "response_rule.create", TargetKind: "response-rule", TargetID: id.String(),
		After: map[string]any{"name": rule.Name, "event_type": rule.EventType}})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// Update validates and replaces a rule.
func (h *ResponseRuleDefs) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	var body responseRuleDefBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	rule := body.toRule(subj.OrgID)
	if err := rule.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.validateReceivers(r.Context(), subj.OrgID, rule); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	conds, _ := json.Marshal(rule.Conditions)
	acts, _ := json.Marshal(rule.Actions)
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE response_rules SET name=$1, enabled=$2, priority=$3, event_type=$4,
       conditions=$5, actions=$6, updated_at=NOW()
 WHERE id=$7 AND org_id=$8`,
		rule.Name, rule.Enabled, rule.Priority, rule.EventType, conds, acts, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "response_rule.update", TargetKind: "response-rule", TargetID: id.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": id})
}

// Delete removes a rule (scoped to the caller's org).
func (h *ResponseRuleDefs) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	tag, err := h.db.Pool().Exec(r.Context(), `DELETE FROM response_rules WHERE id=$1 AND org_id=$2`, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "response_rule.delete", TargetKind: "response-rule", TargetID: id.String()})
	httpx.WriteJSON(w, http.StatusNoContent, nil)
}

// ----------------------------- agent :sync bundle ----------------------------

type responseRuleSyncBundle struct {
	GeneratedAt string                        `json:"generated_at"`
	Rules       []responseRuleDefDTO          `json:"rules"`
}

// AgentSyncBundle serves the org's ENABLED response rules to the runtime-agent, ordered by
// priority. It mirrors the other agent pull endpoints (process-baselines:bundle,
// dlp-rules:bundle): runtime-agent-token auth, org-scoped, priority-ordered so the agent's
// stream evaluator can apply them in precedence order.
func (h *ResponseRuleDefs) AgentSyncBundle(w http.ResponseWriter, r *http.Request) {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return
	}
	rules, err := h.loadRules(r.Context(), tok.OrgID, true)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	bundle := responseRuleSyncBundle{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Rules:       make([]responseRuleDefDTO, 0, len(rules)),
	}
	for i := range rules {
		bundle.Rules = append(bundle.Rules, toDTO(rules[i]))
	}
	httpx.WriteJSON(w, http.StatusOK, bundle)
}

// ----------------------------- evaluation + webhook --------------------------

// Evaluate is the server-side evaluation entry point. It loads the org's enabled rules,
// returns the ordered matching actions (priority-ordered, pure pkg/responserule), and
// fires any webhook actions through the notify dispatcher. The returned actions let the
// caller (the ingest path) apply quarantine/suppress_log/tag effects in its own data plane.
func (h *ResponseRuleDefs) Evaluate(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error) {
	rules, err := h.loadRules(ctx, orgID, true)
	if err != nil {
		return nil, err
	}
	matched := responserule.MatchRules(rules, ev)
	actions := []responserule.Action{}
	for i := range matched {
		for _, a := range matched[i].Actions {
			actions = append(actions, a)
			if a.Type == responserule.ActionWebhook {
				h.fireWebhook(ctx, orgID, matched[i], a, ev)
			}
		}
	}
	return actions, nil
}

// fireWebhook delivers a webhook action to its NAMED receiver (RSP-WEBHOOK-04). The rule's
// Params["receiver"] is required by Validate, so we route with DispatchTo the resolved
// receiver instead of Dispatch (which fans out to every subscriber). Best-effort: a nil
// dispatcher (e.g. in tests), an unresolved receiver, or a delivery error is swallowed — the
// engine's contract is to return the matching actions; delivery is a side effect tracked in
// receiver_deliveries.
func (h *ResponseRuleDefs) fireWebhook(ctx context.Context, orgID uuid.UUID, rule responserule.ResponseRule, a responserule.Action, ev *responserule.Event) {
	if h.dispatcher == nil {
		return
	}
	receiverID, err := h.resolveReceiverID(ctx, orgID, a.Params["receiver"])
	if err != nil {
		slog.Default().Warn("response rule webhook: unresolved receiver",
			slog.String("rule", rule.Name), slog.String("receiver", a.Params["receiver"]),
			slog.String("err", err.Error()))
		return
	}
	labels := map[string]string{"rule": rule.Name, "event_type": string(ev.Type)}
	for k, v := range ev.Fields {
		labels[k] = v
	}
	_, _ = h.dispatcher.DispatchTo(ctx, receiverID, notify.Event{
		Kind:     "response_rule.webhook",
		OrgID:    orgID,
		Severity: "high",
		Title:    "Response rule fired: " + rule.Name,
		Labels:   labels,
		Payload:  map[string]any{"rule": rule.Name, "event_type": ev.Type, "fields": ev.Fields, "params": a.Params},
	})
}

// resolveReceiverID resolves a webhook action's receiver reference (name or id, the two
// forms the RT-2 adapter accepts) to a receiver id, org-scoped and non-paused. Mirrors
// buildReceiverMap in internal/handler/runtime/response_runtime.go. Used both to route a
// firing webhook (fireWebhook) and to validate the receiver exists at rule-save time.
func (h *ResponseRuleDefs) resolveReceiverID(ctx context.Context, orgID uuid.UUID, ref string) (uuid.UUID, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return uuid.Nil, fmt.Errorf("webhook action requires a 'receiver' param")
	}
	var id uuid.UUID
	err := h.db.Pool().QueryRow(ctx, `
SELECT id FROM receivers
 WHERE org_id = $1 AND COALESCE(paused,false) = false AND (name = $2 OR id::text = $2)
 ORDER BY (name = $2) DESC
 LIMIT 1`, orgID, ref).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("receiver %q not found", ref)
	}
	return id, nil
}

// validateReceivers rejects a rule whose webhook actions target a receiver that does not
// exist for the org (RSP-WEBHOOK-04): the receiver param is validated for presence by
// responserule.Validate; this adds the existence check that needs the DB.
func (h *ResponseRuleDefs) validateReceivers(ctx context.Context, orgID uuid.UUID, rule responserule.ResponseRule) error {
	for _, a := range rule.Actions {
		if a.Type != responserule.ActionWebhook {
			continue
		}
		if _, err := h.resolveReceiverID(ctx, orgID, a.Params["receiver"]); err != nil {
			return err
		}
	}
	return nil
}

// ----------------------------- shared loaders --------------------------------

// loadRules loads an org's response rules ordered by (priority, name). When enabledOnly is
// true only enabled rules are returned (the agent sync + evaluation hot path).
func (h *ResponseRuleDefs) loadRules(ctx context.Context, orgID uuid.UUID, enabledOnly bool) ([]responserule.ResponseRule, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id, name, enabled, priority, event_type, conditions, actions
  FROM response_rules
 WHERE org_id=$1 AND ($2::bool = false OR enabled = true)
 ORDER BY priority, name`, orgID, enabledOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []responserule.ResponseRule{}
	for rows.Next() {
		var rule responserule.ResponseRule
		var conds, acts []byte
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Enabled, &rule.Priority,
			&rule.EventType, &conds, &acts); err != nil {
			return nil, err
		}
		rule.OrgID = orgID
		_ = json.Unmarshal(conds, &rule.Conditions)
		_ = json.Unmarshal(acts, &rule.Actions)
		out = append(out, rule)
	}
	return out, rows.Err()
}

func toDTO(r responserule.ResponseRule) responseRuleDefDTO {
	conds := r.Conditions
	if conds == nil {
		conds = []responserule.Condition{}
	}
	acts := r.Actions
	if acts == nil {
		acts = []responserule.Action{}
	}
	return responseRuleDefDTO{
		ID: r.ID, Name: r.Name, Enabled: r.Enabled, Priority: r.Priority,
		EventType: r.EventType, Conditions: conds, Actions: acts,
	}
}
