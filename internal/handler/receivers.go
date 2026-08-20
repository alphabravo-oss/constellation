package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
)

// Receivers handler implements the integration-receivers CRUD surface
// (POST/PATCH/DELETE /api/v1/integrations/receivers), the test-fire / pause / unpause
// operator controls, and exposes per-receiver delivery history.
//
// Wave N3 hardening: the handler now owns generation of the per-receiver HMAC key
// (returned ONCE at create-time + on rotate), pause/unpause toggles, and the
// /test-fire button that sends a synthetic alert through the full Dispatcher.
type Receivers struct {
	db         *db.DB
	audit      *audit.Logger
	dispatcher *notify.Dispatcher
}

// NewReceivers constructs a Receivers handler. dispatcher may be nil — when nil, the
// test-fire endpoint returns 503 but everything else still works (useful for tests
// that don't stand up the dispatcher).
func NewReceivers(d *db.DB, a *audit.Logger, dispatcher *notify.Dispatcher) *Receivers {
	return &Receivers{db: d, audit: a, dispatcher: dispatcher}
}

type receiverDTO struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Kind            string          `json:"kind"`
	Endpoint        string          `json:"endpoint"`
	SecretRef       string          `json:"secret_ref,omitempty"`
	Owner           string          `json:"owner,omitempty"`
	Environment     string          `json:"environment"`
	Status          string          `json:"status"`
	StatusMessage   string          `json:"status_message,omitempty"`
	SupportedEvents []string        `json:"supported_events"`
	Config          json.RawMessage `json:"config"`
	LastVerifiedAt  string          `json:"last_verified_at,omitempty"`
	CreatedAt       string          `json:"created_at"`
	RatePerMin      int             `json:"rate_per_min"`
	TemplateID      string          `json:"template_id"`
	Paused          bool            `json:"paused"`
}

type receiverDeliveryDTO struct {
	ID             string   `json:"id"`
	ReceiverID     string   `json:"receiver_id"`
	EventType      string   `json:"event_type"`
	Severity       string   `json:"severity"`
	Status         string   `json:"status"`
	Attempts       int      `json:"attempts"`
	LatencyMs      int      `json:"latency_ms"`
	TraceID        string   `json:"trace_id,omitempty"`
	Error          string   `json:"error,omitempty"`
	Artifacts      []string `json:"artifacts"`
	RoutingRuleID  string   `json:"routing_rule_id,omitempty"`
	CreatedAt      string   `json:"created_at"`
	DeliveredAt    string   `json:"delivered_at,omitempty"`
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
	FinalState     string   `json:"final_state,omitempty"`
	NextRetryAt    string   `json:"next_retry_at,omitempty"`
	SignedAt       string   `json:"signed_at,omitempty"`
}

// emailRecipients extracts config.to (array or comma string) from a receiver's config,
// trimming blanks. Mirrors the dispatcher's parse so create-validation and delivery agree.
func emailRecipients(cfg json.RawMessage) []string {
	if len(cfg) == 0 {
		return nil
	}
	var parsed struct {
		To json.RawMessage `json:"to"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil || len(parsed.To) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(parsed.To, &list) != nil {
		var single string
		if json.Unmarshal(parsed.To, &single) != nil {
			return nil
		}
		list = strings.Split(single, ",")
	}
	out := make([]string, 0, len(list))
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// List returns receivers + recent delivery history for the calling org.
func (h *Receivers) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	recvs, err := h.loadReceivers(r, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dels, err := h.loadDeliveries(r, subj.OrgID, uuid.Nil, 100)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"receivers":        recvs,
		"delivery_history": dels,
	})
}

func (h *Receivers) loadReceivers(r *http.Request, orgID uuid.UUID) ([]receiverDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, name, kind, endpoint, COALESCE(secret_ref, ''), COALESCE(owner, ''),
       environment, status, COALESCE(status_message,''), supported_events, config,
       last_verified_at, created_at,
       COALESCE(rate_per_min, 60), COALESCE(template_id, 'default'),
       COALESCE(paused, false)
  FROM receivers WHERE org_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("query receivers: %w", err)
	}
	defer rows.Close()
	out := []receiverDTO{}
	for rows.Next() {
		var (
			id                uuid.UUID
			name, kind        string
			endpoint, sec     string
			owner, env        string
			status, statusMsg string
			eventsJSON        []byte
			cfg               json.RawMessage
			lastVerified      *time.Time
			createdAt         time.Time
			ratePerMin        int
			templateID        string
			paused            bool
		)
		if err := rows.Scan(&id, &name, &kind, &endpoint, &sec, &owner, &env, &status, &statusMsg,
			&eventsJSON, &cfg, &lastVerified, &createdAt, &ratePerMin, &templateID, &paused); err != nil {
			return nil, err
		}
		var events []string
		_ = json.Unmarshal(eventsJSON, &events)
		if events == nil {
			events = []string{}
		}
		if cfg == nil {
			cfg = json.RawMessage(`{}`)
		}
		dto := receiverDTO{
			ID: id.String(), Name: name, Kind: kind, Endpoint: endpoint, SecretRef: sec,
			Owner: owner, Environment: env, Status: status, StatusMessage: statusMsg,
			SupportedEvents: events, Config: cfg, CreatedAt: createdAt.UTC().Format(time.RFC3339),
			RatePerMin: ratePerMin, TemplateID: templateID, Paused: paused,
		}
		if lastVerified != nil {
			dto.LastVerifiedAt = lastVerified.UTC().Format(time.RFC3339)
		}
		out = append(out, dto)
	}
	return out, rows.Err()
}

// loadDeliveries returns delivery rows for the org, optionally filtered to a single
// receiver. limit is clamped to [1, 500].
func (h *Receivers) loadDeliveries(r *http.Request, orgID, receiverID uuid.UUID, limit int) ([]receiverDeliveryDTO, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args := []any{orgID, limit}
	where := "org_id = $1"
	if receiverID != uuid.Nil {
		where += " AND receiver_id = $3"
		args = append(args, receiverID)
	}
	sql := `
SELECT id, receiver_id, event_type, severity, status, attempts, latency_ms,
       COALESCE(trace_id, ''), COALESCE(error, ''), artifacts,
       COALESCE(routing_rule_id, ''), created_at, delivered_at,
       idempotency_key, COALESCE(final_state,''), next_retry_at, signed_at
  FROM receiver_deliveries WHERE ` + where + `
 ORDER BY created_at DESC LIMIT $2`
	rows, err := h.db.Pool().Query(r.Context(), sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query deliveries: %w", err)
	}
	defer rows.Close()
	out := []receiverDeliveryDTO{}
	for rows.Next() {
		var (
			id, rid       uuid.UUID
			et, sev, st   string
			attempts, ms  int
			trace, errMsg string
			artJSON       []byte
			ruleID        string
			createdAt     time.Time
			deliveredAt   *time.Time
			ipk           *uuid.UUID
			finalState    string
			nextRetryAt   *time.Time
			signedAt      *time.Time
		)
		if err := rows.Scan(&id, &rid, &et, &sev, &st, &attempts, &ms, &trace, &errMsg, &artJSON,
			&ruleID, &createdAt, &deliveredAt, &ipk, &finalState, &nextRetryAt, &signedAt); err != nil {
			return nil, err
		}
		var artifacts []string
		_ = json.Unmarshal(artJSON, &artifacts)
		if artifacts == nil {
			artifacts = []string{}
		}
		dto := receiverDeliveryDTO{
			ID: id.String(), ReceiverID: rid.String(), EventType: et, Severity: sev, Status: st,
			Attempts: attempts, LatencyMs: ms, TraceID: trace, Error: errMsg, Artifacts: artifacts,
			RoutingRuleID: ruleID, CreatedAt: createdAt.UTC().Format(time.RFC3339),
			FinalState: finalState,
		}
		if deliveredAt != nil {
			dto.DeliveredAt = deliveredAt.UTC().Format(time.RFC3339)
		}
		if ipk != nil {
			dto.IdempotencyKey = ipk.String()
		}
		if nextRetryAt != nil {
			dto.NextRetryAt = nextRetryAt.UTC().Format(time.RFC3339)
		}
		if signedAt != nil {
			dto.SignedAt = signedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, dto)
	}
	return out, rows.Err()
}

type createReceiverRequest struct {
	Name            string          `json:"name"`
	Kind            string          `json:"kind"`
	Endpoint        string          `json:"endpoint"`
	SecretRef       string          `json:"secret_ref"`
	Owner           string          `json:"owner"`
	Environment     string          `json:"environment"`
	SupportedEvents []string        `json:"supported_events"`
	Config          json.RawMessage `json:"config"`
	TemplateID      string          `json:"template_id"`
	RatePerMin      int             `json:"rate_per_min"`
}

type createReceiverResponse struct {
	ID        string `json:"id"`
	SecretKey string `json:"secret_key"` // returned ONCE at creation
}

// Create inserts a new receiver, generates the HMAC secret_key, and returns it once.
func (h *Receivers) Create(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var req createReceiverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" || req.Kind == "" {
		jsonError(w, http.StatusBadRequest, "name, kind required")
		return
	}
	if req.Kind == "email" {
		// Email is an SMTP send, not an HTTP POST, so the URL/SSRF guard doesn't apply
		// (an internal corporate relay is legitimate). Recipients live in config.to; the
		// endpoint is a human-readable summary of them.
		recips := emailRecipients(req.Config)
		if len(recips) == 0 {
			jsonError(w, http.StatusBadRequest, "email receiver requires config.to (one or more recipient addresses)")
			return
		}
		req.Endpoint = "mailto:" + strings.Join(recips, ",")
	} else {
		if req.Endpoint == "" {
			jsonError(w, http.StatusBadRequest, "endpoint required")
			return
		}
		// SSRF guard (create-time): the dispatcher POSTs alert traffic to this endpoint, so an
		// attacker-controlled internal URL would let a notify rule reach cloud metadata / internal
		// services. Require https + a public host here; the dispatcher additionally re-checks the
		// RESOLVED IP at dial time (defeating DNS rebind).
		if err := notify.PublicURLAllowed(req.Endpoint); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid endpoint: "+err.Error())
			return
		}
	}
	if req.Environment == "" {
		req.Environment = "production"
	}
	if req.SupportedEvents == nil {
		req.SupportedEvents = []string{}
	}
	if len(req.Config) == 0 {
		req.Config = json.RawMessage(`{}`)
	}
	if req.TemplateID == "" {
		req.TemplateID = "default"
	}
	if req.RatePerMin <= 0 {
		req.RatePerMin = 60
	}
	secret, err := notify.GenerateSecretKey()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("secret-gen: %v", err))
		return
	}
	eventsJSON, _ := json.Marshal(req.SupportedEvents)
	id := uuid.New()
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO receivers (id, org_id, name, kind, endpoint, secret_ref, owner, environment,
                       status, supported_events, config, secret_key, rate_per_min, template_id)
VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,''), $8, 'pending', $9::jsonb, $10::jsonb, $11, $12, $13)`,
		id, subj.OrgID, req.Name, req.Kind, req.Endpoint, req.SecretRef, req.Owner, req.Environment,
		eventsJSON, []byte(req.Config), secret, req.RatePerMin, req.TemplateID); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("insert: %v", err))
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "receiver.create",
			TargetKind: "receiver", TargetID: id.String(),
			After: map[string]any{
				"name": req.Name, "kind": req.Kind, "endpoint": req.Endpoint,
				"template_id": req.TemplateID, "rate_per_min": req.RatePerMin,
			},
		})
	}
	writeJSON(w, http.StatusCreated, createReceiverResponse{ID: id.String(), SecretKey: secret})
}

type patchReceiverRequest struct {
	Name            *string         `json:"name,omitempty"`
	Endpoint        *string         `json:"endpoint,omitempty"`
	SecretRef       *string         `json:"secret_ref,omitempty"`
	Owner           *string         `json:"owner,omitempty"`
	Environment     *string         `json:"environment,omitempty"`
	Status          *string         `json:"status,omitempty"`
	SupportedEvents *[]string       `json:"supported_events,omitempty"`
	Config          json.RawMessage `json:"config,omitempty"`
	TemplateID      *string         `json:"template_id,omitempty"`
	RatePerMin      *int            `json:"rate_per_min,omitempty"`
}

// Patch applies a partial update to a receiver.
func (h *Receivers) Patch(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	var req patchReceiverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	// SSRF guard (patch-time): re-validate when the endpoint is being changed so a receiver
	// can't be repointed at an internal/metadata URL after creation. Mirrors Create. An
	// email receiver's endpoint is a mailto: summary (not an HTTP target), so the guard
	// only applies to http(s) endpoints.
	if req.Endpoint != nil && strings.HasPrefix(*req.Endpoint, "http") {
		if err := notify.PublicURLAllowed(*req.Endpoint); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid endpoint: "+err.Error())
			return
		}
	}
	var eventsJSON []byte
	if req.SupportedEvents != nil {
		eventsJSON, _ = json.Marshal(*req.SupportedEvents)
	}
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE receivers SET
  name        = COALESCE($3, name),
  endpoint    = COALESCE($4, endpoint),
  secret_ref  = COALESCE($5, secret_ref),
  owner       = COALESCE($6, owner),
  environment = COALESCE($7, environment),
  status      = COALESCE($8, status),
  supported_events = COALESCE($9::jsonb, supported_events),
  config      = COALESCE($10::jsonb, config),
  template_id = COALESCE($11, template_id),
  rate_per_min = COALESCE($12, rate_per_min),
  updated_at  = NOW()
 WHERE id = $1 AND org_id = $2`,
		id, subj.OrgID, req.Name, req.Endpoint, req.SecretRef, req.Owner, req.Environment, req.Status,
		eventsJSON, []byte(req.Config), req.TemplateID, req.RatePerMin)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "receiver not found")
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "receiver.update",
			TargetKind: "receiver", TargetID: id.String(), After: req,
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Delete removes a receiver.
func (h *Receivers) Delete(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(),
		`DELETE FROM receivers WHERE id = $1 AND org_id = $2`, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "receiver not found")
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "receiver.delete",
			TargetKind: "receiver", TargetID: id.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// TestFire sends a synthetic sample alert through the full delivery path for the
// receiver. The UI uses this to verify end-to-end wiring after a customer plugs in
// Slack / PagerDuty / Jira / ServiceNow / webhook. Returns 200 + delivery_id;
// the caller polls /deliveries to see how it played out.
func (h *Receivers) TestFire(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	if h.dispatcher == nil {
		jsonError(w, http.StatusServiceUnavailable, "dispatcher not configured")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	// Sanity-check ownership before firing.
	var ownerOrg uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT org_id FROM receivers WHERE id = $1`, id).Scan(&ownerOrg); err != nil {
		jsonError(w, http.StatusNotFound, "receiver not found")
		return
	}
	if ownerOrg != subj.OrgID {
		jsonError(w, http.StatusNotFound, "receiver not found")
		return
	}
	ev := notify.Event{
		Kind: "integration.test_fire", OrgID: subj.OrgID, Severity: "info",
		Title:   "Constellation sample alert (test-fire)",
		Body:    "This is a synthetic alert dispatched by an operator to verify the receiver. No action required.",
		Cluster: "test", Workload: "constellation-control-plane",
		URL:            "https://constellation.example/integrations",
		Labels:         map[string]string{"source": "test-fire", "actor": subj.UserID.String()},
		Payload:        map[string]string{"actor": subj.UserID.String()},
		FiredAt:        time.Now().UTC(),
		IdempotencyKey: uuid.New(),
	}
	dlvID, err := h.dispatcher.DispatchTo(r.Context(), id, ev)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "receiver.test_fire",
			TargetKind: "receiver", TargetID: id.String(),
			After: map[string]any{"delivery_id": dlvID.String()},
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"delivery_id":     dlvID.String(),
		"idempotency_key": ev.IdempotencyKey.String(),
	})
}

// Pause flips paused=true on the receiver; the dispatcher won't fan-out to it.
func (h *Receivers) Pause(w http.ResponseWriter, r *http.Request) { h.setPaused(w, r, true) }

// Unpause flips paused=false.
func (h *Receivers) Unpause(w http.ResponseWriter, r *http.Request) { h.setPaused(w, r, false) }

func (h *Receivers) setPaused(w http.ResponseWriter, r *http.Request, paused bool) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(),
		`UPDATE receivers SET paused = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`,
		paused, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "receiver not found")
		return
	}
	action := "receiver.unpause"
	if paused {
		action = "receiver.pause"
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: action,
			TargetKind: "receiver", TargetID: id.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "paused": paused})
}

// RotateSecret regenerates the HMAC secret_key and returns the new one. The old key
// becomes unusable immediately — receivers must update before the next dispatch.
func (h *Receivers) RotateSecret(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	secret, err := notify.GenerateSecretKey()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(),
		`UPDATE receivers SET secret_key = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`,
		secret, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "receiver not found")
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "receiver.rotate_secret",
			TargetKind: "receiver", TargetID: id.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret_key": secret})
}

// ListDeliveries returns the delivery history scoped to a single receiver.
func (h *Receivers) ListDeliveries(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	// Confirm ownership before returning.
	var ownerOrg uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT org_id FROM receivers WHERE id = $1`, id).Scan(&ownerOrg); err != nil {
		jsonError(w, http.StatusNotFound, "receiver not found")
		return
	}
	if ownerOrg != subj.OrgID {
		jsonError(w, http.StatusNotFound, "receiver not found")
		return
	}
	dels, err := h.loadDeliveries(r, subj.OrgID, id, limit)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": dels})
}

// GetRoutingYAML returns the raw Alertmanager-style routing tree (empty string if unset).
func (h *Receivers) GetRoutingYAML(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var yamlStr string
	var revision int
	var updatedAt time.Time
	err := h.db.Pool().QueryRow(r.Context(),
		`SELECT yaml, revision, updated_at FROM routing_configs WHERE org_id = $1`, subj.OrgID).
		Scan(&yamlStr, &revision, &updatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"yaml":       yamlStr,
		"revision":   revision,
		"updated_at": updatedAt.UTC().Format(time.RFC3339),
	})
}

// PutRoutingYAML accepts a raw YAML body and writes the routing tree.
func (h *Receivers) PutRoutingYAML(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO routing_configs (org_id, yaml, revision, updated_by) VALUES ($1, $2, 1, $3)
ON CONFLICT (org_id) DO UPDATE SET yaml = EXCLUDED.yaml,
                                   revision = routing_configs.revision + 1,
                                   updated_at = NOW(),
                                   updated_by = EXCLUDED.updated_by`,
		subj.OrgID, body.YAML, subj.UserID); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "routing.yaml.update",
			TargetKind: "routing_config", TargetID: oid.String(),
			After: map[string]any{"bytes": len(body.YAML)},
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
