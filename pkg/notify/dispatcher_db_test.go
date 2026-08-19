package notify

import (
	"context"
	"encoding/json"
	"os"
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
