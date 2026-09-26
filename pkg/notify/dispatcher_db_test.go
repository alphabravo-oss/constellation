package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// openNotifyTestPool connects to the live test DB or skips. Mirrors the convention used by
// the handler tests (CONSTELLATION_TEST_DATABASE_URL with a local default).
func openNotifyTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("skipping: cannot ping test DB (%v)", err)
	}
	return pool
}

func seedReceiver(t *testing.T, pool *pgxpool.Pool) (orgID, receiverID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	receiverID = uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO receivers (id, org_id, name, kind, endpoint, status)
VALUES ($1, $2, $3, 'webhook', 'https://example.com/hook', 'pending')`,
		receiverID, orgID, "notify-test-"+receiverID.String()); err != nil {
		t.Fatalf("insert receiver: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM receivers WHERE id=$1`, receiverID)
	})
	return orgID, receiverID
}

// TestPersistPending_RoundTripsFullPayload covers finding "retried receiver deliveries lose
// the entire alert payload": persistPending must store the full event so a retry can replay
// the identical body. (Migration 113 adds the payload column.)
func TestPersistPending_RoundTripsFullPayload(t *testing.T) {
	pool := openNotifyTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	orgID, receiverID := seedReceiver(t, pool)

	d := &Dispatcher{pool: pool, cfg: DispatcherConfig{
		BackoffSchedule: []time.Duration{time.Second, 5 * time.Second, 15 * time.Second},
		Now:             func() time.Time { return time.Now().UTC() },
	}}
	ev := Event{
		Kind: "runtime.alert.exec", OrgID: orgID, Severity: "critical",
		Title: "lateral movement", Body: "nc spawned a shell", Cluster: "prod-1",
		Workload: "default/api", URL: "https://app/findings/abc",
		Labels: map[string]string{"team": "secops"}, IdempotencyKey: uuid.New(),
		FiredAt: time.Now().UTC().Truncate(time.Second),
	}
	id, err := d.persistPending(ctx, receiverRow{ID: receiverID, OrgID: orgID}, ev)
	if err != nil {
		t.Fatalf("persistPending: %v", err)
	}

	var payload []byte
	if err := pool.QueryRow(ctx, `SELECT payload FROM receiver_deliveries WHERE id=$1`, id).Scan(&payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	var got Event
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("payload not the stored event JSON: %v", err)
	}
	if got.Title != ev.Title || got.Body != ev.Body || got.Cluster != ev.Cluster ||
		got.Workload != ev.Workload || got.URL != ev.URL || got.Labels["team"] != "secops" {
		t.Fatalf("payload did not round-trip the full event: %+v", got)
	}
}

// TestMarkQueueFull_StaysRetryable covers finding "notifications permanently dropped on full
// queue": a queue-full delivery must keep final_state NULL and set next_retry_at so the
// sweeper re-enqueues it.
func TestMarkQueueFull_StaysRetryable(t *testing.T) {
	pool := openNotifyTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	orgID, receiverID := seedReceiver(t, pool)

	d := &Dispatcher{pool: pool, cfg: DispatcherConfig{
		BackoffSchedule: []time.Duration{time.Second, 5 * time.Second, 15 * time.Second},
		Now:             func() time.Time { return time.Now().UTC() },
	}}
	id, err := d.persistPending(ctx, receiverRow{ID: receiverID, OrgID: orgID}, Event{
		Kind: "finding.triage", OrgID: orgID, Severity: "high", IdempotencyKey: uuid.New(),
		FiredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("persistPending: %v", err)
	}

	d.markQueueFull(ctx, id)

	var (
		status      string
		finalState  *string
		nextRetryAt *time.Time
	)
	if err := pool.QueryRow(ctx,
		`SELECT status, final_state, next_retry_at FROM receiver_deliveries WHERE id=$1`, id).
		Scan(&status, &finalState, &nextRetryAt); err != nil {
		t.Fatalf("read delivery: %v", err)
	}
	if status != "retrying" {
		t.Fatalf("status=%q, want retrying", status)
	}
	if finalState != nil {
		t.Fatalf("final_state must stay NULL so the sweeper retries; got %q", *finalState)
	}
	if nextRetryAt == nil {
		t.Fatal("next_retry_at must be set so the sweeper picks the row up")
	}
	// The sweeper selects exactly this shape (final_state IS NULL AND next_retry_at IS NOT NULL).
	var sweepable bool
	if err := pool.QueryRow(ctx,
		`SELECT (final_state IS NULL AND next_retry_at IS NOT NULL) FROM receiver_deliveries WHERE id=$1`, id).
		Scan(&sweepable); err != nil {
		t.Fatalf("sweepable check: %v", err)
	}
	if !sweepable {
		t.Fatal("row is not selectable by the retry sweeper")
	}
}

func processNamedJob(t *testing.T, d *Dispatcher) {
	t.Helper()
	select {
	case j := <-d.queue:
		d.process(context.Background(), j)
	case <-time.After(time.Second):
		t.Fatal("named delivery was not queued")
	}
}

func TestDispatchTo_PausedAfterQueueDoesNotSend(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		priorAttempts int
	}{
		{name: "initial delivery"},
		{name: "queued retry", priorAttempts: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			pool := openNotifyTestPool(t)
			t.Cleanup(pool.Close)
			ctx := context.Background()
			orgID, receiverID := seedReceiver(t, pool)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()
			if _, err := pool.Exec(ctx, `UPDATE receivers SET endpoint=$2 WHERE id=$1`, receiverID, server.URL); err != nil {
				t.Fatal(err)
			}
			d := NewDispatcher(pool, DispatcherConfig{HTTPClient: server.Client(), BackoffSchedule: []time.Duration{time.Millisecond}})
			deliveryID, err := d.DispatchTo(ctx, receiverID, Event{Kind: "response_rule.webhook", OrgID: orgID})
			if err != nil {
				t.Fatal(err)
			}
			if testCase.priorAttempts > 0 {
				processNamedJob(t, d)
				var nextRetryAt time.Time
				if err := pool.QueryRow(ctx, `SELECT next_retry_at FROM receiver_deliveries WHERE id=$1`, deliveryID).Scan(&nextRetryAt); err != nil {
					t.Fatal(err)
				}
				for time.Now().Before(nextRetryAt) {
					time.Sleep(time.Millisecond)
				}
				d.sweepDue(ctx, &deliveryID)
			}
			if _, err := pool.Exec(ctx, `UPDATE receivers SET paused=true WHERE id=$1`, receiverID); err != nil {
				t.Fatal(err)
			}
			processNamedJob(t, d)

			var status, finalState, errorText string
			var attempts int
			var nextRetryAt, deliveredAt, signedAt *time.Time
			if err := pool.QueryRow(ctx, `
SELECT status, final_state, attempts, next_retry_at, delivered_at, signed_at, error
  FROM receiver_deliveries WHERE id=$1`, deliveryID).
				Scan(&status, &finalState, &attempts, &nextRetryAt, &deliveredAt, &signedAt, &errorText); err != nil {
				t.Fatal(err)
			}
			if status != "paused" || finalState != "paused" || attempts != testCase.priorAttempts ||
				nextRetryAt != nil || deliveredAt != nil || signedAt != nil || errorText != "receiver paused" ||
				calls.Load() != int32(testCase.priorAttempts) {
				t.Fatalf("paused receipt: status=%s final=%s attempts=%d retry=%v delivered=%v signed=%v error=%q calls=%d",
					status, finalState, attempts, nextRetryAt, deliveredAt, signedAt, errorText, calls.Load())
			}
		})
	}
}

func TestDispatchTo_NamedReceiverReceipt(t *testing.T) {
	pool := openNotifyTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	orgID, targetID := seedReceiver(t, pool)
	_, otherID := seedReceiver(t, pool)
	var targetCalls, otherCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			targetCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		otherCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for _, receiver := range []struct {
		id       uuid.UUID
		endpoint string
	}{{targetID, server.URL + "/target"}, {otherID, server.URL + "/other"}} {
		if _, err := pool.Exec(ctx, `UPDATE receivers SET endpoint=$2 WHERE id=$1`, receiver.id, receiver.endpoint); err != nil {
			t.Fatal(err)
		}
	}
	d := NewDispatcher(pool, DispatcherConfig{HTTPClient: server.Client()})
	event := Event{Kind: "response_rule.webhook", OrgID: orgID, Title: "named receiver", IdempotencyKey: uuid.New()}
	deliveryID, err := d.DispatchTo(ctx, targetID, event)
	if err != nil {
		t.Fatal(err)
	}
	var pendingStatus string
	var pendingAttempts int
	if err := pool.QueryRow(ctx, `SELECT status, attempts FROM receiver_deliveries WHERE id=$1`, deliveryID).
		Scan(&pendingStatus, &pendingAttempts); err != nil {
		t.Fatal(err)
	}
	if pendingStatus != "pending" || pendingAttempts != 0 {
		t.Fatalf("initial receipt: status=%s attempts=%d", pendingStatus, pendingAttempts)
	}
	processNamedJob(t, d)
	var receiverID uuid.UUID
	var status, finalState string
	var attempts int
	var deliveredAt, signedAt *time.Time
	var nextRetryAt *time.Time
	if err := pool.QueryRow(ctx, `
SELECT receiver_id, status, final_state, attempts, delivered_at, signed_at, next_retry_at
  FROM receiver_deliveries WHERE id=$1`, deliveryID).
		Scan(&receiverID, &status, &finalState, &attempts, &deliveredAt, &signedAt, &nextRetryAt); err != nil {
		t.Fatal(err)
	}
	if receiverID != targetID || status != "delivered" || finalState != "delivered" || attempts != 1 || deliveredAt == nil || signedAt == nil || nextRetryAt != nil {
		t.Fatalf("receipt: receiver=%s status=%s final=%s attempts=%d delivered=%v signed=%v retry=%v", receiverID, status, finalState, attempts, deliveredAt, signedAt, nextRetryAt)
	}
	var otherReceipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM receiver_deliveries WHERE receiver_id=$1 AND idempotency_key=$2`, otherID, event.IdempotencyKey).Scan(&otherReceipts); err != nil {
		t.Fatal(err)
	}
	if targetCalls.Load() != 1 || otherCalls.Load() != 0 || otherReceipts != 0 {
		t.Fatalf("target calls=%d other calls=%d other receipts=%d", targetCalls.Load(), otherCalls.Load(), otherReceipts)
	}
}

func TestDispatchTo_RetryAndTerminalFailure(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		lastStatus int
		finalState string
		recStatus  string
	}{
		{name: "recovers", lastStatus: http.StatusNoContent, finalState: "delivered", recStatus: "healthy"},
		{name: "exhausted", lastStatus: http.StatusServiceUnavailable, finalState: "failed", recStatus: "degraded"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			pool := openNotifyTestPool(t)
			defer pool.Close()
			ctx := context.Background()
			orgID, receiverID := seedReceiver(t, pool)
			var calls atomic.Int32
			type requestRecord struct{ body, key string }
			requests := make(chan requestRecord, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				requests <- requestRecord{body: string(body), key: r.Header.Get("X-Constellation-Idempotency")}
				if calls.Add(1) == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte("temporary outage"))
					return
				}
				w.WriteHeader(testCase.lastStatus)
			}))
			defer server.Close()
			if _, err := pool.Exec(ctx, `UPDATE receivers SET endpoint=$2 WHERE id=$1`, receiverID, server.URL); err != nil {
				t.Fatal(err)
			}
			d := NewDispatcher(pool, DispatcherConfig{HTTPClient: server.Client(), BackoffSchedule: []time.Duration{time.Millisecond}})
			event := Event{Kind: "response_rule.webhook", OrgID: orgID, Severity: "high", Title: "retry payload", IdempotencyKey: uuid.New()}
			deliveryID, err := d.DispatchTo(ctx, receiverID, event)
			if err != nil {
				t.Fatal(err)
			}
			processNamedJob(t, d)
			firstRequest := <-requests
			var status, errorText string
			var finalState *string
			var attempts int
			var nextRetryAt *time.Time
			if err := pool.QueryRow(ctx, `SELECT status, final_state, attempts, next_retry_at, error FROM receiver_deliveries WHERE id=$1`, deliveryID).
				Scan(&status, &finalState, &attempts, &nextRetryAt, &errorText); err != nil {
				t.Fatal(err)
			}
			if status != "retrying" || finalState != nil || attempts != 1 || nextRetryAt == nil || !strings.Contains(errorText, "503") {
				t.Fatalf("retry receipt: status=%s final=%v attempts=%d next=%v error=%q", status, finalState, attempts, nextRetryAt, errorText)
			}
			for time.Now().Before(*nextRetryAt) {
				time.Sleep(time.Millisecond)
			}
			d.sweepDue(ctx, &deliveryID)
			processNamedJob(t, d)
			secondRequest := <-requests
			var receiverStatus string
			var finalError *string
			if err := pool.QueryRow(ctx, `SELECT status, final_state, attempts, next_retry_at, error FROM receiver_deliveries WHERE id=$1`, deliveryID).
				Scan(&status, &finalState, &attempts, &nextRetryAt, &finalError); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, `SELECT status FROM receivers WHERE id=$1`, receiverID).Scan(&receiverStatus); err != nil {
				t.Fatal(err)
			}
			if status != testCase.finalState || finalState == nil || *finalState != testCase.finalState || attempts != 2 || nextRetryAt != nil || receiverStatus != testCase.recStatus || calls.Load() != 2 || !strings.Contains(firstRequest.body, "retry payload") || firstRequest.key != event.IdempotencyKey.String() || secondRequest != firstRequest {
				t.Fatalf("final receipt: status=%s final=%v attempts=%d next=%v receiver=%s calls=%d first=%+v second=%+v", status, finalState, attempts, nextRetryAt, receiverStatus, calls.Load(), firstRequest, secondRequest)
			}
			if testCase.finalState == "delivered" && finalError != nil {
				t.Fatalf("delivered receipt retained retry error: %q", *finalError)
			}
			if testCase.finalState == "failed" && (finalError == nil || !strings.Contains(*finalError, "503")) {
				t.Fatalf("failed receipt missing error: %v", finalError)
			}
		})
	}
}

func TestDispatchTo_RejectsOtherOrgAndPausedReceiver(t *testing.T) {
	for _, name := range []string{"other org", "paused"} {
		t.Run(name, func(t *testing.T) {
			pool := openNotifyTestPool(t)
			defer pool.Close()
			ctx := context.Background()
			orgID, receiverID := seedReceiver(t, pool)
			if name == "paused" {
				if _, err := pool.Exec(ctx, `UPDATE receivers SET paused=true WHERE id=$1`, receiverID); err != nil {
					t.Fatal(err)
				}
			} else {
				orgID = uuid.New()
			}
			d := NewDispatcher(pool, DispatcherConfig{})
			event := Event{Kind: "response_rule.webhook", OrgID: orgID, IdempotencyKey: uuid.New()}
			deliveryID, err := d.DispatchTo(ctx, receiverID, event)
			if err == nil || deliveryID != uuid.Nil {
				t.Fatalf("disallowed dispatch: delivery=%s err=%v", deliveryID, err)
			}
			var receipts int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM receiver_deliveries WHERE receiver_id=$1 AND idempotency_key=$2`, receiverID, event.IdempotencyKey).Scan(&receipts); err != nil {
				t.Fatal(err)
			}
			if receipts != 0 || len(d.queue) != 0 {
				t.Fatalf("disallowed dispatch persisted %d receipts and queued %d jobs", receipts, len(d.queue))
			}
		})
	}
}
