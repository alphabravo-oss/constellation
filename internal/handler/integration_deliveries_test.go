package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestIntegrationDeliveries_OverviewWithoutStorageReturnsEmptyLiveState(t *testing.T) {
	w := httptest.NewRecorder()
	NewIntegrationDeliveries().List(w, httptest.NewRequest(http.MethodGet, "/api/v1/integration-deliveries", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}

	var got integrationDeliveryOverviewDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Summary.IntegrationInstancesTotal != 0 || got.Summary.Deliveries24h != 0 || got.Summary.DeadLettersOpen != 0 {
		t.Fatalf("no storage should not return sample integration data: %+v", got.Summary)
	}
	if len(got.IntegrationInstances) != 0 || len(got.DeliveryHistory) != 0 || len(got.ReceiverHealth) != 0 || len(got.RetryStats) != 0 || len(got.TestableActions) != 0 {
		t.Fatalf("no storage should return empty live panels: %+v", got)
	}
	if len(got.Guardrails) == 0 {
		t.Fatalf("guardrails should still describe integration delivery invariants: %+v", got)
	}
}

func TestIntegrationDeliveries_DBOverviewUsesReceiversAndDeliveryRows(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	healthyID := uuid.New()
	degradedID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Integration Delivery Test')`,
		orgID, "integration-delivery-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Integration Admin')`,
		userID, orgID, "integrations-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO receivers (id, org_id, name, kind, endpoint, secret_ref, owner, environment, status,
                       supported_events, config, last_verified_at, rate_per_min, template_id)
VALUES
  ($1, $2, 'SecOps Slack', 'slack', 'https://hooks.slack.com/services/T/B/secret-token?token=leak', 'vault://slack/secops', 'secops', 'production', 'healthy',
   '["finding.created","integration.test"]'::jsonb, '{}'::jsonb, NOW() - INTERVAL '5 minutes', 60, 'default'),
  ($3, $2, 'Security Queue', 'servicenow', 'https://snow.example/api/now/table/incident?token=leak', 'vault://snow/sec', 'secops', 'production', 'healthy',
   '["finding.created","integration.test"]'::jsonb, '{}'::jsonb, NOW() - INTERVAL '10 minutes', 30, 'default')`,
		healthyID, orgID, degradedID); err != nil {
		t.Fatalf("receivers: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO receiver_deliveries (id, org_id, receiver_id, event_type, severity, status, routing_rule_id,
                                 attempts, latency_ms, trace_id, error, artifacts, created_at, delivered_at,
                                 idempotency_key, final_state, next_retry_at, signed_at)
VALUES
  ($1, $2, $3, 'finding.created', 'high', 'delivered', 'rule-slack',
   1, 1800, 'trace-ok', '', '["finding/CVE-2099-0001"]'::jsonb, NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '29 minutes',
   gen_random_uuid(), 'delivered', NULL, NOW() - INTERVAL '30 minutes'),
  ($4, $2, $5, 'finding.created', 'critical', 'retrying', 'rule-snow',
   2, 0, 'trace-retry', '429 rate limited', '["finding/CVE-2099-0002"]'::jsonb, NOW() - INTERVAL '20 minutes', NULL,
   gen_random_uuid(), NULL, NOW() + INTERVAL '5 minutes', NOW() - INTERVAL '20 minutes'),
  ($6, $2, $5, 'finding.created', 'critical', 'failed', 'rule-snow',
   4, 0, 'trace-dead', 'receiver rejected assignment_group', '["finding/CVE-2099-0003"]'::jsonb, NOW() - INTERVAL '10 minutes', NULL,
   gen_random_uuid(), 'failed', NULL, NOW() - INTERVAL '10 minutes')`,
		uuid.New(), orgID, healthyID, uuid.New(), degradedID, uuid.New()); err != nil {
		t.Fatalf("deliveries: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO routing_configs (org_id, yaml, revision, updated_by)
VALUES ($1, 'route:
  receivers: ["SecOps Slack","Security Queue"]', 7, $2)`, orgID, userID); err != nil {
		t.Fatalf("routing: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integration-deliveries", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewIntegrationDeliveries(d).Overview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}

	var got integrationDeliveryOverviewDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Summary.IntegrationInstancesTotal != 2 || got.Summary.Deliveries24h != 3 || got.Summary.FailedDeliveries24h != 1 || got.Summary.DeadLettersOpen != 1 {
		t.Fatalf("unexpected summary: %+v", got.Summary)
	}
	if got.Summary.IntegrationInstancesByType["slack"] != 1 || got.Summary.IntegrationInstancesByType["servicenow"] != 1 {
		t.Fatalf("unexpected type rollup: %+v", got.Summary.IntegrationInstancesByType)
	}
	if len(got.IntegrationInstances) != 2 || len(got.DeliveryHistory) != 3 || len(got.ReceiverHealth) != 2 || len(got.RetryStats) != 2 {
		t.Fatalf("missing live sections: %+v", got)
	}
	for _, instance := range got.IntegrationInstances {
		if strings.Contains(instance.Endpoint, "secret-token") || strings.Contains(instance.Endpoint, "token=leak") {
			t.Fatalf("endpoint was not redacted: %+v", instance)
		}
	}
	if len(got.RoutingRules) != 1 || got.RoutingRules[0].ID != "routing-config-rev-7" || len(got.RoutingRules[0].ReceiverIDs) != 2 {
		t.Fatalf("missing routing summary: %+v", got.RoutingRules)
	}

	healthByReceiver := map[string]integrationReceiverHealthDTO{}
	for _, health := range got.ReceiverHealth {
		healthByReceiver[health.ReceiverID] = health
	}
	if healthByReceiver[healthyID.String()].Status != "healthy" || healthByReceiver[healthyID.String()].SuccessRate24h != 100 {
		t.Fatalf("unexpected healthy receiver health: %+v", healthByReceiver[healthyID.String()])
	}
	if healthByReceiver[degradedID.String()].Status != "degraded" || len(healthByReceiver[degradedID.String()].RecentErrors) == 0 {
		t.Fatalf("unexpected degraded receiver health: %+v", healthByReceiver[degradedID.String()])
	}

	retryByReceiver := map[string]integrationRetryStatsDTO{}
	for _, retry := range got.RetryStats {
		retryByReceiver[retry.ReceiverID] = retry
	}
	if retryByReceiver[degradedID.String()].QueuedRetries != 1 || retryByReceiver[degradedID.String()].DeadLettersOpen != 1 || retryByReceiver[degradedID.String()].RetryRate24h == "0.0%" {
		t.Fatalf("unexpected retry stats: %+v", retryByReceiver[degradedID.String()])
	}
	if len(got.TestableActions) != 1 {
		t.Fatalf("testable actions should be derived from live receivers: %+v", got.TestableActions)
	}
	for _, receiverID := range got.TestableActions[0].IntegrationIDs {
		if _, err := uuid.Parse(receiverID); err != nil {
			t.Fatalf("testable action receiver id should be DB-derived UUID, got %q", receiverID)
		}
	}
}

func TestIntegrationDeliveries_TestPreviewReturnsReadOnlyEnvelopeForDBReceiver(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	receiverID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Integration Preview Test')`,
		orgID, "integration-preview-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Integration Admin')`,
		userID, orgID, "integration-preview-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO receivers (id, org_id, name, kind, endpoint, secret_ref, owner, environment, status,
                       supported_events, config, rate_per_min, template_id)
VALUES ($1, $2, 'SecOps Slack', 'slack', 'https://hooks.slack.com/services/T/B/secret-token', 'vault://slack/secops',
        'secops', 'production', 'healthy', '["integration.test"]'::jsonb, '{}'::jsonb, 60, 'default')`,
		receiverID, orgID); err != nil {
		t.Fatalf("receiver: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/integration-deliveries/test?id="+receiverID.String(), nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewIntegrationDeliveries(d).TestPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}

	var got integrationTestPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.IntegrationInstance.ID != receiverID.String() || strings.Contains(got.IntegrationInstance.Endpoint, "secret-token") {
		t.Fatalf("unexpected integration instance: %+v", got.IntegrationInstance)
	}
	if got.Action.ID != "send-test-notification" || !got.Action.ReadOnlyPreview {
		t.Fatalf("unexpected action: %+v", got.Action)
	}
	if got.PersistsDelivery || got.SendsNotification {
		t.Fatalf("preview should be read-only: %+v", got)
	}
	if got.PreviewDelivery.Status != "preview" || got.PreviewDelivery.ReceiverID != receiverID.String() || got.PreviewDelivery.Attempts != 0 {
		t.Fatalf("unexpected preview delivery: %+v", got.PreviewDelivery)
	}
	if got.ReceiverHealth.ReceiverID != receiverID.String() {
		t.Fatalf("preview did not include matching receiver health: %+v", got.ReceiverHealth)
	}
	if len(got.Guardrails) != len(got.Action.GuardrailIDs) {
		t.Fatalf("preview did not include action guardrails: %+v", got.Guardrails)
	}
}

func TestIntegrationDeliveries_TestPreviewValidation(t *testing.T) {
	w := httptest.NewRecorder()
	NewIntegrationDeliveries().TestPreview(w, httptest.NewRequest(http.MethodPost, "/api/v1/integration-deliveries/test", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing id status: %d", w.Code)
	}

	w = httptest.NewRecorder()
	NewIntegrationDeliveries().TestPreview(w, httptest.NewRequest(http.MethodPost, "/api/v1/integration-deliveries/test?id="+uuid.NewString(), nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no-storage status: %d", w.Code)
	}
}
