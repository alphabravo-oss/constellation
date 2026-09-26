package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReceiverTestFireDeliveryVisibilityAndAudit(t *testing.T) {
	_, server, pool, signer, adminID, _, orgID := newSysConfigTestServer(t)
	ctx := context.Background()
	admin := issueFor(t, signer, adminID, orgID, 0)
	baseURL := server.URL + "/api/v1/integrations/receivers"

	create := func(token, name string) string {
		t.Helper()
		status, body := doJSON(t, http.MethodPost, baseURL, token, map[string]any{
			"name": name, "kind": "email", "config": map[string]any{"to": []string{name + "@example.test"}},
		})
		if status != http.StatusCreated {
			t.Fatalf("create %s: status=%d body=%+v", name, status, body)
		}
		id, _ := body["id"].(string)
		if _, err := uuid.Parse(id); err != nil {
			t.Fatalf("create %s returned invalid id %q: %v", name, id, err)
		}
		return id
	}

	firstID := create(admin, "named-first")
	secondID := create(admin, "named-second")
	firstURL := baseURL + "/" + firstID
	status, fired := doJSON(t, http.MethodPost, firstURL+"/test-fire", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("test-fire: status=%d body=%+v", status, fired)
	}
	deliveryID, _ := fired["delivery_id"].(string)
	if _, err := uuid.Parse(deliveryID); err != nil {
		t.Fatalf("test-fire returned invalid delivery id %q: %v", deliveryID, err)
	}
	if _, err := uuid.Parse(fired["idempotency_key"].(string)); err != nil {
		t.Fatalf("test-fire returned invalid idempotency key: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var delivery map[string]any
	for time.Now().Before(deadline) {
		status, body := doJSON(t, http.MethodGet, firstURL+"/deliveries", admin, nil)
		if status != http.StatusOK {
			t.Fatalf("first receiver deliveries: status=%d body=%+v", status, body)
		}
		rows, ok := body["deliveries"].([]any)
		if !ok || len(rows) != 1 {
			t.Fatalf("first receiver deliveries: %+v", body)
		}
		delivery = rows[0].(map[string]any)
		if delivery["status"] != "pending" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if delivery["id"] != deliveryID || delivery["receiver_id"] != firstID ||
		delivery["event_type"] != "integration.test_fire" || delivery["severity"] != "info" ||
		delivery["idempotency_key"] != fired["idempotency_key"] || delivery["status"] == "pending" {
		t.Fatalf("named delivery receipt not visible or incomplete: %+v", delivery)
	}
	if attempts, _ := delivery["attempts"].(float64); attempts < 1 {
		t.Fatalf("delivery attempt result missing: %+v", delivery)
	}
	status, second := doJSON(t, http.MethodGet, baseURL+"/"+secondID+"/deliveries", admin, nil)
	if status != http.StatusOK || len(second["deliveries"].([]any)) != 0 {
		t.Fatalf("non-target receiver received named event: status=%d body=%+v", status, second)
	}
	status, listing := doJSON(t, http.MethodGet, baseURL, admin, nil)
	if status != http.StatusOK {
		t.Fatalf("receiver list: status=%d body=%+v", status, listing)
	}
	history, ok := listing["delivery_history"].([]any)
	if !ok || len(history) != 1 || history[0].(map[string]any)["id"] != deliveryID {
		t.Fatalf("org delivery history omitted named receipt: %+v", listing)
	}
	status, audit := doJSON(t, http.MethodGet, server.URL+"/api/v1/audit/events?action=receiver.test_fire", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("test-fire audit: status=%d body=%+v", status, audit)
	}
	events, ok := audit["events"].([]any)
	if !ok || len(events) != 1 || events[0].(map[string]any)["target_id"] != firstID ||
		events[0].(map[string]any)["actor_id"] != adminID.String() {
		t.Fatalf("test-fire audit missing or incorrectly scoped: %+v", audit)
	}
	var auditedDelivery string
	if err := pool.QueryRow(ctx, `SELECT after->>'delivery_id' FROM audit_events WHERE org_id=$1 AND action='receiver.test_fire' AND target_id=$2`, orgID, firstID).Scan(&auditedDelivery); err != nil || auditedDelivery != deliveryID {
		t.Fatalf("audit receipt link=%q, err=%v, want=%q", auditedDelivery, err, deliveryID)
	}

	otherOrgID, otherAdminID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Other Receiver Test')`, otherOrgID, "receiver-other-"+otherOrgID.String()); err != nil {
		t.Fatalf("create other org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, otherOrgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name, session_epoch) VALUES ($1, $2, $3, 'Other Admin', 0)`, otherAdminID, otherOrgID, "receiver-other-"+otherAdminID.String()+"@example.test"); err != nil {
		t.Fatalf("create other admin: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'GlobalAdmin', $2)`, otherAdminID, otherOrgID); err != nil {
		t.Fatalf("assign other admin: %v", err)
	}
	otherAdmin := issueFor(t, signer, otherAdminID, otherOrgID, 0)
	for _, path := range []string{firstURL + "/deliveries", firstURL + "/test-fire", firstURL + "/pause"} {
		method := http.MethodPost
		if path == firstURL+"/deliveries" {
			method = http.MethodGet
		}
		if status, body := doJSON(t, method, path, otherAdmin, nil); status != http.StatusNotFound {
			t.Fatalf("cross-org %s %s: status=%d body=%+v", method, path, status, body)
		}
	}
	status, otherList := doJSON(t, http.MethodGet, baseURL, otherAdmin, nil)
	if status != http.StatusOK || len(otherList["delivery_history"].([]any)) != 0 || len(otherList["receivers"].([]any)) != 0 {
		t.Fatalf("cross-org receiver list leaked: status=%d body=%+v", status, otherList)
	}
	status, otherAudit := doJSON(t, http.MethodGet, server.URL+"/api/v1/audit/events?action=receiver.test_fire", otherAdmin, nil)
	if status != http.StatusOK || len(otherAudit["events"].([]any)) != 0 {
		t.Fatalf("cross-org audit leaked: status=%d body=%+v", status, otherAudit)
	}

	if status, body := doJSON(t, http.MethodPost, firstURL+"/pause", admin, nil); status != http.StatusOK || body["paused"] != true {
		t.Fatalf("pause receiver: status=%d body=%+v", status, body)
	}
	if status, body := doJSON(t, http.MethodPost, firstURL+"/test-fire", admin, nil); status != http.StatusConflict || body["error"] != "receiver paused" {
		t.Fatalf("paused receiver test-fire: status=%d body=%+v, want 409", status, body)
	}
	var deliveryCount, auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM receiver_deliveries WHERE org_id=$1 AND receiver_id=$2`, orgID, firstID).Scan(&deliveryCount); err != nil || deliveryCount != 1 {
		t.Fatalf("paused receiver delivery count=%d err=%v", deliveryCount, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='receiver.test_fire' AND target_id=$2`, orgID, firstID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("paused receiver audit count=%d err=%v", auditCount, err)
	}
}
