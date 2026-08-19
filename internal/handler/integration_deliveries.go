package handler

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
)

type IntegrationDeliveries struct {
	db *db.DB
}

func NewIntegrationDeliveries(database ...*db.DB) *IntegrationDeliveries {
	var d *db.DB
	if len(database) > 0 {
		d = database[0]
	}
	return &IntegrationDeliveries{db: d}
}

type integrationDeliverySummaryDTO struct {
	GeneratedAt                string         `json:"generated_at"`
	IntegrationInstancesTotal  int            `json:"integration_instances_total"`
	IntegrationInstancesByType map[string]int `json:"integration_instances_by_type"`
	HealthyReceivers           int            `json:"healthy_receivers"`
	DegradedReceivers          int            `json:"degraded_receivers"`
	Deliveries24h              int            `json:"deliveries_24h"`
	FailedDeliveries24h        int            `json:"failed_deliveries_24h"`
	DeadLettersOpen            int            `json:"dead_letters_open"`
}

type integrationInstanceDTO struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Status          string   `json:"status"`
	Owner           string   `json:"owner"`
	Environment     string   `json:"environment"`
	Endpoint        string   `json:"endpoint"`
	SecretRef       string   `json:"secret_ref"`
	LastVerifiedAt  string   `json:"last_verified_at"`
	SupportedEvents []string `json:"supported_events"`
}

type integrationRoutingRuleDTO struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Priority        int      `json:"priority"`
	Enabled         bool     `json:"enabled"`
	EventTypes      []string `json:"event_types"`
	Severity        []string `json:"severity"`
	Scope           []string `json:"scope"`
	ReceiverIDs     []string `json:"receiver_ids"`
	Throttle        string   `json:"throttle"`
	DedupeWindow    string   `json:"dedupe_window"`
	EscalationAfter string   `json:"escalation_after,omitempty"`
}

type integrationDeliveryHistoryDTO struct {
	ID            string   `json:"id"`
	EventType     string   `json:"event_type"`
	Severity      string   `json:"severity"`
	Status        string   `json:"status"`
	ReceiverID    string   `json:"receiver_id"`
	RoutingRuleID string   `json:"routing_rule_id"`
	CreatedAt     string   `json:"created_at"`
	DeliveredAt   string   `json:"delivered_at,omitempty"`
	Attempts      int      `json:"attempts"`
	LatencyMs     int      `json:"latency_ms"`
	TraceID       string   `json:"trace_id"`
	Error         string   `json:"error,omitempty"`
	Artifacts     []string `json:"artifacts"`
}

type integrationReceiverHealthDTO struct {
	ReceiverID        string   `json:"receiver_id"`
	Status            string   `json:"status"`
	LastSuccessAt     string   `json:"last_success_at"`
	LastFailureAt     string   `json:"last_failure_at,omitempty"`
	P95LatencyMs      int      `json:"p95_latency_ms"`
	SuccessRate24h    float64  `json:"success_rate_24h"`
	RateLimitResetAt  string   `json:"rate_limit_reset_at,omitempty"`
	RecentErrors      []string `json:"recent_errors"`
	RecommendedAction string   `json:"recommended_action"`
}

type integrationRetryStatsDTO struct {
	ReceiverID         string `json:"receiver_id"`
	QueuedRetries      int    `json:"queued_retries"`
	RetryRate24h       string `json:"retry_rate_24h"`
	MaxAttempts        int    `json:"max_attempts"`
	BackoffPolicy      string `json:"backoff_policy"`
	DeadLettersOpen    int    `json:"dead_letters_open"`
	DeadLetters24h     int    `json:"dead_letters_24h"`
	OldestDeadLetterAt string `json:"oldest_dead_letter_at,omitempty"`
}

type integrationActionDTO struct {
	ID              string   `json:"id"`
	Label           string   `json:"label"`
	IntegrationIDs  []string `json:"integration_ids"`
	ReadOnlyPreview bool     `json:"read_only_preview"`
	RequiresRole    string   `json:"requires_role"`
	GuardrailIDs    []string `json:"guardrail_ids"`
}

type integrationGuardrailDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enforced    bool   `json:"enforced"`
}

type integrationDeliveryOverviewDTO struct {
	Summary              integrationDeliverySummaryDTO   `json:"summary"`
	IntegrationInstances []integrationInstanceDTO        `json:"integration_instances"`
	RoutingRules         []integrationRoutingRuleDTO     `json:"routing_rules"`
	DeliveryHistory      []integrationDeliveryHistoryDTO `json:"delivery_history"`
	ReceiverHealth       []integrationReceiverHealthDTO  `json:"receiver_health"`
	RetryStats           []integrationRetryStatsDTO      `json:"retry_stats"`
	TestableActions      []integrationActionDTO          `json:"testable_actions"`
	Guardrails           []integrationGuardrailDTO       `json:"guardrails"`
}

type integrationTestPreviewDTO struct {
	IntegrationInstance integrationInstanceDTO        `json:"integration_instance"`
	Action              integrationActionDTO          `json:"action"`
	PreviewDelivery     integrationDeliveryHistoryDTO `json:"preview_delivery"`
	ReceiverHealth      integrationReceiverHealthDTO  `json:"receiver_health"`
	Guardrails          []integrationGuardrailDTO     `json:"guardrails"`
	PersistsDelivery    bool                          `json:"persists_delivery"`
	SendsNotification   bool                          `json:"sends_notification"`
	Message             string                        `json:"message"`
}

type integrationDeliveryAggregate struct {
	deliveries24h       int
	failedDeliveries24h int
	deadLettersOpen     int
}

// List returns the read-only integration delivery operations view.
func (h *IntegrationDeliveries) List(w http.ResponseWriter, r *http.Request) {
	if h.db != nil {
		if _, ok := SubjectFrom(r.Context()); !ok {
			jsonError(w, http.StatusUnauthorized, "no subject")
			return
		}
	}
	overview, err := h.overview(r)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

// Overview is an alias for List so routing can expose either collection or console semantics.
func (h *IntegrationDeliveries) Overview(w http.ResponseWriter, r *http.Request) {
	h.List(w, r)
}

// TestPreview returns the delivery envelope a test action would create.
//
// The preview is read-only: it never calls a receiver, persists a delivery row,
// enqueues a retry, or creates a dead-letter record.
func (h *IntegrationDeliveries) TestPreview(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		id = integrationIDFromRequestPath(r)
	}
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "integration id required"})
		return
	}
	if h.db == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "integration not found"})
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	receiverID, err := uuid.Parse(id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "integration id must be a receiver UUID"})
		return
	}

	receiver, err := h.loadReceiver(r, subj.OrgID, receiverID)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "integration not found"})
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	actionID := strings.TrimSpace(r.URL.Query().Get("action"))
	if actionID == "" {
		actionID = "send-test-notification"
	}
	action, ok := integrationPreviewAction(actionID, []string{receiver.ID})
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action not available for integration"})
		return
	}

	now := time.Now().UTC()
	deliveries, err := NewReceivers(h.db, nil, nil).loadDeliveries(r, subj.OrgID, receiverID, 100)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	health := buildReceiverHealth(receiver, deliveries, now)
	preview := integrationDeliveryHistoryDTO{
		ID:            "preview-" + receiver.ID,
		EventType:     "integration.test",
		Severity:      "info",
		Status:        "preview",
		ReceiverID:    receiver.ID,
		RoutingRuleID: "manual-test",
		CreatedAt:     now.Format(time.RFC3339),
		Attempts:      0,
		LatencyMs:     0,
		TraceID:       "",
		Artifacts:     []string{},
	}

	writeJSON(w, http.StatusOK, integrationTestPreviewDTO{
		IntegrationInstance: receiver,
		Action:              action,
		PreviewDelivery:     preview,
		ReceiverHealth:      health,
		Guardrails:          guardrailsByID(action.GuardrailIDs),
		PersistsDelivery:    false,
		SendsNotification:   false,
		Message:             "Test preview is read-only; no receiver call, delivery row, retry, or dead-letter record is created.",
	})
}

func (h *IntegrationDeliveries) overview(r *http.Request) (integrationDeliveryOverviewDTO, error) {
	now := time.Now().UTC()
	if h.db == nil {
		return emptyIntegrationDeliveryOverview(now), nil
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		return integrationDeliveryOverviewDTO{}, fmt.Errorf("no subject")
	}

	receiverHandler := NewReceivers(h.db, nil, nil)
	receivers, err := receiverHandler.loadReceivers(r, subj.OrgID)
	if err != nil {
		return integrationDeliveryOverviewDTO{}, err
	}
	deliveries, err := receiverHandler.loadDeliveries(r, subj.OrgID, uuid.Nil, 500)
	if err != nil {
		return integrationDeliveryOverviewDTO{}, err
	}
	aggregate, err := h.loadDeliveryAggregate(r, subj.OrgID)
	if err != nil {
		return integrationDeliveryOverviewDTO{}, err
	}
	routingRules, err := h.loadRoutingRules(r, subj.OrgID)
	if err != nil {
		return integrationDeliveryOverviewDTO{}, err
	}

	instances := make([]integrationInstanceDTO, 0, len(receivers))
	for _, receiver := range receivers {
		instances = append(instances, receiverToIntegrationInstance(receiver))
	}
	history := make([]integrationDeliveryHistoryDTO, 0, len(deliveries))
	for _, delivery := range deliveries {
		history = append(history, receiverDeliveryToIntegrationHistory(delivery))
	}
	health, retryStats := buildReceiverOperations(receivers, deliveries, now)

	return integrationDeliveryOverviewDTO{
		Summary:              buildIntegrationDeliverySummary(now, instances, health, aggregate),
		IntegrationInstances: instances,
		RoutingRules:         routingRules,
		DeliveryHistory:      history,
		ReceiverHealth:       health,
		RetryStats:           retryStats,
		TestableActions:      integrationTestableActionsFor(instances),
		Guardrails:           integrationGuardrails,
	}, nil
}

func emptyIntegrationDeliveryOverview(now time.Time) integrationDeliveryOverviewDTO {
	return integrationDeliveryOverviewDTO{
		Summary: integrationDeliverySummaryDTO{
			GeneratedAt:                now.Format(time.RFC3339),
			IntegrationInstancesByType: map[string]int{},
		},
		IntegrationInstances: []integrationInstanceDTO{},
		RoutingRules:         []integrationRoutingRuleDTO{},
		DeliveryHistory:      []integrationDeliveryHistoryDTO{},
		ReceiverHealth:       []integrationReceiverHealthDTO{},
		RetryStats:           []integrationRetryStatsDTO{},
		TestableActions:      []integrationActionDTO{},
		Guardrails:           integrationGuardrails,
	}
}

func (h *IntegrationDeliveries) loadReceiver(r *http.Request, orgID, receiverID uuid.UUID) (integrationInstanceDTO, error) {
	var receiver receiverDTO
	rows, err := NewReceivers(h.db, nil, nil).loadReceivers(r, orgID)
	if err != nil {
		return integrationInstanceDTO{}, err
	}
	for _, row := range rows {
		if row.ID == receiverID.String() {
			receiver = row
			return receiverToIntegrationInstance(receiver), nil
		}
	}
	return integrationInstanceDTO{}, pgx.ErrNoRows
}

func (h *IntegrationDeliveries) loadDeliveryAggregate(r *http.Request, orgID uuid.UUID) (integrationDeliveryAggregate, error) {
	var agg integrationDeliveryAggregate
	var deliveries24h, failedDeliveries24h, deadLettersOpen int64
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT
  COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours'),
  COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours' AND status IN ('failed', 'dropped')),
  COUNT(*) FILTER (WHERE status IN ('failed', 'dropped') OR final_state IN ('failed', 'dropped'))
FROM receiver_deliveries
WHERE org_id = $1`, orgID).Scan(&deliveries24h, &failedDeliveries24h, &deadLettersOpen)
	agg.deliveries24h = int(deliveries24h)
	agg.failedDeliveries24h = int(failedDeliveries24h)
	agg.deadLettersOpen = int(deadLettersOpen)
	return agg, err
}

func (h *IntegrationDeliveries) loadRoutingRules(r *http.Request, orgID uuid.UUID) ([]integrationRoutingRuleDTO, error) {
	var yamlStr string
	var revision int
	var updatedAt time.Time
	err := h.db.Pool().QueryRow(r.Context(),
		`SELECT yaml, revision, updated_at FROM routing_configs WHERE org_id = $1`, orgID).
		Scan(&yamlStr, &revision, &updatedAt)
	if err == pgx.ErrNoRows || strings.TrimSpace(yamlStr) == "" {
		return []integrationRoutingRuleDTO{}, nil
	}
	if err != nil {
		return nil, err
	}
	receiverIDs := parseRoutingReceiverReferences(yamlStr)
	name := "Saved notification routing tree"
	if !updatedAt.IsZero() {
		name = fmt.Sprintf("%s (rev %d)", name, revision)
	}
	return []integrationRoutingRuleDTO{{
		ID:           fmt.Sprintf("routing-config-rev-%d", revision),
		Name:         name,
		Priority:     1,
		Enabled:      true,
		EventTypes:   []string{"configured-in-routing-yaml"},
		Severity:     []string{},
		Scope:        []string{},
		ReceiverIDs:  receiverIDs,
		Throttle:     "per-receiver token bucket",
		DedupeWindow: "dispatcher idempotency key",
	}}, nil
}

func buildIntegrationDeliverySummary(now time.Time, instances []integrationInstanceDTO, health []integrationReceiverHealthDTO, aggregate integrationDeliveryAggregate) integrationDeliverySummaryDTO {
	byType := map[string]int{}
	for _, instance := range instances {
		byType[instance.Type]++
	}
	healthyReceivers := 0
	degradedReceivers := 0
	for _, receiver := range health {
		switch receiver.Status {
		case "healthy":
			healthyReceivers++
		case "degraded", "retrying", "paused":
			degradedReceivers++
		}
	}
	return integrationDeliverySummaryDTO{
		GeneratedAt:                now.Format(time.RFC3339),
		IntegrationInstancesTotal:  len(instances),
		IntegrationInstancesByType: byType,
		HealthyReceivers:           healthyReceivers,
		DegradedReceivers:          degradedReceivers,
		Deliveries24h:              aggregate.deliveries24h,
		FailedDeliveries24h:        aggregate.failedDeliveries24h,
		DeadLettersOpen:            aggregate.deadLettersOpen,
	}
}

func integrationIDFromRequestPath(r *http.Request) string {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 2 && parts[len(parts)-1] == "test-preview" {
		return parts[len(parts)-2]
	}
	return ""
}

func receiverToIntegrationInstance(receiver receiverDTO) integrationInstanceDTO {
	return integrationInstanceDTO{
		ID:              receiver.ID,
		Name:            receiver.Name,
		Type:            receiver.Kind,
		Status:          normalizeReceiverStatus(receiver),
		Owner:           receiver.Owner,
		Environment:     receiver.Environment,
		Endpoint:        redactIntegrationEndpoint(receiver.Endpoint),
		SecretRef:       receiver.SecretRef,
		LastVerifiedAt:  receiver.LastVerifiedAt,
		SupportedEvents: receiver.SupportedEvents,
	}
}

func receiverDeliveryToIntegrationHistory(delivery receiverDeliveryDTO) integrationDeliveryHistoryDTO {
	routingRuleID := delivery.RoutingRuleID
	if routingRuleID == "" {
		routingRuleID = "direct-dispatch"
	}
	return integrationDeliveryHistoryDTO{
		ID:            delivery.ID,
		EventType:     delivery.EventType,
		Severity:      delivery.Severity,
		Status:        delivery.Status,
		ReceiverID:    delivery.ReceiverID,
		RoutingRuleID: routingRuleID,
		CreatedAt:     delivery.CreatedAt,
		DeliveredAt:   delivery.DeliveredAt,
		Attempts:      delivery.Attempts,
		LatencyMs:     delivery.LatencyMs,
		TraceID:       delivery.TraceID,
		Error:         delivery.Error,
		Artifacts:     delivery.Artifacts,
	}
}

func normalizeReceiverStatus(receiver receiverDTO) string {
	if receiver.Paused {
		return "paused"
	}
	status := strings.ToLower(strings.TrimSpace(receiver.Status))
	if status == "" {
		return "pending"
	}
	return status
}

func redactIntegrationEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" {
		return "configured"
	}
	if u.Host == "" {
		return u.Scheme + "://..."
	}
	u.User = nil
	u.Path = "/..."
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func buildReceiverOperations(receivers []receiverDTO, deliveries []receiverDeliveryDTO, now time.Time) ([]integrationReceiverHealthDTO, []integrationRetryStatsDTO) {
	deliveriesByReceiver := map[string][]receiverDeliveryDTO{}
	for _, delivery := range deliveries {
		deliveriesByReceiver[delivery.ReceiverID] = append(deliveriesByReceiver[delivery.ReceiverID], delivery)
	}
	health := make([]integrationReceiverHealthDTO, 0, len(receivers))
	retryStats := make([]integrationRetryStatsDTO, 0, len(receivers))
	for _, receiver := range receivers {
		receiverDeliveries := deliveriesByReceiver[receiver.ID]
		health = append(health, buildReceiverHealth(receiverToIntegrationInstance(receiver), receiverDeliveries, now))
		retryStats = append(retryStats, buildReceiverRetryStats(receiver.ID, receiverDeliveries, now))
	}
	return health, retryStats
}

func buildReceiverHealth(receiver integrationInstanceDTO, deliveries []receiverDeliveryDTO, now time.Time) integrationReceiverHealthDTO {
	status := receiver.Status
	var latencies []int
	var recentErrors []string
	var lastSuccessAt, lastFailureAt string
	total24h := 0
	success24h := 0
	for _, delivery := range deliveries {
		createdAt := parseRFC3339(delivery.CreatedAt)
		if !createdAt.IsZero() && createdAt.After(now.Add(-24*time.Hour)) {
			total24h++
			if delivery.Status == "delivered" {
				success24h++
			}
		}
		if delivery.Status == "delivered" {
			if lastSuccessAt == "" {
				if delivery.DeliveredAt != "" {
					lastSuccessAt = delivery.DeliveredAt
				} else {
					lastSuccessAt = delivery.CreatedAt
				}
			}
			if delivery.LatencyMs > 0 {
				latencies = append(latencies, delivery.LatencyMs)
			}
			continue
		}
		if delivery.Status == "failed" || delivery.Status == "retrying" || delivery.Status == "dropped" {
			if status != "paused" && status != "disabled" {
				status = "degraded"
			}
			if lastFailureAt == "" {
				lastFailureAt = delivery.CreatedAt
			}
			if delivery.Error != "" && len(recentErrors) < 3 {
				recentErrors = append(recentErrors, delivery.Error)
			}
		}
	}
	successRate := 0.0
	if total24h > 0 {
		successRate = math.Round((float64(success24h)/float64(total24h))*1000) / 10
	}
	return integrationReceiverHealthDTO{
		ReceiverID:        receiver.ID,
		Status:            status,
		LastSuccessAt:     lastSuccessAt,
		LastFailureAt:     lastFailureAt,
		P95LatencyMs:      percentileLatency(latencies, 0.95),
		SuccessRate24h:    successRate,
		RecentErrors:      recentErrors,
		RecommendedAction: receiverRecommendedAction(receiver.Status, total24h, recentErrors),
	}
}

func buildReceiverRetryStats(receiverID string, deliveries []receiverDeliveryDTO, now time.Time) integrationRetryStatsDTO {
	total24h := 0
	retried24h := 0
	queuedRetries := 0
	deadLettersOpen := 0
	deadLetters24h := 0
	oldestDeadLetterAt := ""
	for _, delivery := range deliveries {
		createdAt := parseRFC3339(delivery.CreatedAt)
		in24h := !createdAt.IsZero() && createdAt.After(now.Add(-24*time.Hour))
		if in24h {
			total24h++
			if delivery.Attempts > 1 || delivery.Status == "retrying" {
				retried24h++
			}
		}
		if delivery.Status == "retrying" || (delivery.NextRetryAt != "" && delivery.FinalState == "") {
			queuedRetries++
		}
		if delivery.Status == "failed" || delivery.Status == "dropped" || delivery.FinalState == "failed" || delivery.FinalState == "dropped" {
			deadLettersOpen++
			if in24h {
				deadLetters24h++
			}
			if oldestDeadLetterAt == "" {
				oldestDeadLetterAt = delivery.CreatedAt
			}
		}
	}
	retryRate := "0.0%"
	if total24h > 0 {
		retryRate = fmt.Sprintf("%.1f%%", (float64(retried24h)/float64(total24h))*100)
	}
	return integrationRetryStatsDTO{
		ReceiverID:         receiverID,
		QueuedRetries:      queuedRetries,
		RetryRate24h:       retryRate,
		MaxAttempts:        4,
		BackoffPolicy:      "dispatcher default: 1s, 5s, 15s with 5m rate-limit watermark",
		DeadLettersOpen:    deadLettersOpen,
		DeadLetters24h:     deadLetters24h,
		OldestDeadLetterAt: oldestDeadLetterAt,
	}
}

func percentileLatency(values []int, percentile float64) int {
	if len(values) == 0 {
		return 0
	}
	sort.Ints(values)
	idx := int(math.Ceil(percentile*float64(len(values)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx]
}

func receiverRecommendedAction(status string, total24h int, recentErrors []string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "paused":
		return "Receiver is paused; unpause before expecting delivery traffic."
	case "disabled":
		return "Receiver is disabled; enable it before expecting delivery traffic."
	case "degraded":
		return "Review recent receiver errors and routing configuration."
	}
	if len(recentErrors) > 0 {
		return "Review recent receiver errors and retry pressure."
	}
	if total24h == 0 {
		return "No delivery telemetry yet; run a receiver test-fire before relying on this route."
	}
	return "No action required."
}

func parseRFC3339(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func parseRoutingReceiverReferences(yamlStr string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, line := range strings.Split(yamlStr, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "receivers:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(trimmed, "receivers:"))
		raw = strings.Trim(raw, "[]")
		for _, item := range strings.Split(raw, ",") {
			item = strings.Trim(strings.TrimSpace(item), `"'`)
			if item == "" {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

func integrationTestableActionsFor(instances []integrationInstanceDTO) []integrationActionDTO {
	if len(instances) == 0 {
		return []integrationActionDTO{}
	}
	ids := make([]string, 0, len(instances))
	for _, instance := range instances {
		ids = append(ids, instance.ID)
	}
	action, _ := integrationPreviewAction("send-test-notification", ids)
	return []integrationActionDTO{action}
}

func integrationPreviewAction(id string, integrationIDs []string) (integrationActionDTO, bool) {
	if id != "send-test-notification" {
		return integrationActionDTO{}, false
	}
	return integrationActionDTO{
		ID:              "send-test-notification",
		Label:           "Preview test notification envelope",
		IntegrationIDs:  integrationIDs,
		ReadOnlyPreview: true,
		RequiresRole:    "org.integration_admin",
		GuardrailIDs:    []string{"read-only-preview", "redact-secrets", "respect-rate-limits"},
	}, true
}

func guardrailsByID(ids []string) []integrationGuardrailDTO {
	guardrails := make([]integrationGuardrailDTO, 0, len(ids))
	for _, id := range ids {
		for _, guardrail := range integrationGuardrails {
			if guardrail.ID == id {
				guardrails = append(guardrails, guardrail)
				break
			}
		}
	}
	return guardrails
}

var integrationGuardrails = []integrationGuardrailDTO{
	{ID: "read-only-preview", Name: "Read-only preview", Description: "Preview handlers must not send receiver traffic, persist delivery rows, enqueue retries, or create dead letters.", Enforced: true},
	{ID: "redact-secrets", Name: "Secret redaction", Description: "Read-only operations views return redacted receiver endpoint shapes and logical secret references only.", Enforced: true},
	{ID: "respect-rate-limits", Name: "Rate-limit awareness", Description: "Preview payloads include receiver health so callers can avoid adding load to limited integrations.", Enforced: true},
}
