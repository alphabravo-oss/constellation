// Wave N3: fire-and-forget Dispatcher that takes a high-level Event, fans it out to
// the persisted receivers for an org, signs the body with each receiver's HMAC key,
// records a delivery row, and retries with exponential backoff on failure.
//
// The dispatcher is intentionally decoupled from the rest of the API: callers hand it
// an Event over a buffered channel and move on. A worker pool drains the channel; a
// sweeper loop polls the `receiver_deliveries` table for rows whose next_retry_at has
// elapsed and re-fires them.
//
// Rate limit: per-receiver token bucket. When a receiver is throttled we queue the
// delivery in the channel with a high-watermark; if a delivery sits behind the bucket
// for >5min we drop it and mark final_state='rate_limited'.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Event is the high-level happening that fans out to receivers. Kinds follow a
// dotted hierarchy (e.g. "finding.triage", "policy.create", "admission.deny",
// "runtime.alert.exec") so routes can match on prefixes.
type Event struct {
	Kind     string    // finding.triage | policy.create | admission.deny | runtime.alert.exec | ...
	OrgID    uuid.UUID // tenant
	Severity string    // info | low | medium | high | critical
	Title    string    // one-line subject
	Body     string    // optional pre-rendered body (templates fall back to this)
	Cluster  string
	Workload string
	URL      string            // deep-link back into Constellation
	Labels   map[string]string // routing labels
	Payload  any               // structured object for templates (must JSON-marshal)
	FiredAt  time.Time
	// IdempotencyKey, if set, is reused across retries. Generated when empty.
	IdempotencyKey uuid.UUID
}

// DispatcherConfig is the knobs the embedder can override.
type DispatcherConfig struct {
	Workers            int             // worker pool size; default 8
	Buffer             int             // channel buffer depth; default 1024
	BackoffSchedule    []time.Duration // attempt N waits BackoffSchedule[N]; default {1s, 5s, 15s}
	RateLimitWatermark time.Duration   // drop after this much queued time; default 5m
	Logger             *slog.Logger
	HTTPClient         *http.Client
	// Now lets tests pin time.
	Now func() time.Time
	// SyslogTarget, when set, resolves the LIVE syslog/SIEM sender for an org so every
	// dispatched event is also mirrored to syslog (B1 consumer b). It returns (nil,
	// false) when no target is configured. Wired to the runtime-mutable system config:
	// a PATCH of syslog_siem_target switches the destination here without a restart,
	// because the resolver reads the live config each call. Independent of the HTTP
	// receiver fan-out — a syslog failure never blocks receiver delivery.
	SyslogTarget func(ctx context.Context, orgID uuid.UUID) (*Syslog, bool)

	// SMTPServer resolves the LIVE global SMTP server for an org so an "email"
	// receiver can be delivered. Returns (_, false) when no SMTP server is
	// configured (email receivers then fail with a clear message). Wired to the
	// runtime-mutable system config, like SyslogTarget.
	SMTPServer func(ctx context.Context, orgID uuid.UUID) (Email, bool)
}

// Dispatcher is the persisted-receiver dispatcher.
type Dispatcher struct {
	pool *pgxpool.Pool
	cfg  DispatcherConfig

	queue chan *job
	wg    sync.WaitGroup
	stop  chan struct{}

	bucketsMu sync.Mutex
	buckets   map[uuid.UUID]*tokenBucket // keyed by receiver id
}

// NewDispatcher constructs a Dispatcher. Caller must Start() it.
func NewDispatcher(pool *pgxpool.Pool, cfg DispatcherConfig) *Dispatcher {
	if cfg.Workers <= 0 {
		cfg.Workers = 8
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = 1024
	}
	if len(cfg.BackoffSchedule) == 0 {
		cfg.BackoffSchedule = []time.Duration{1 * time.Second, 5 * time.Second, 15 * time.Second}
	}
	if cfg.RateLimitWatermark <= 0 {
		cfg.RateLimitWatermark = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPClient == nil {
		// SSRF hardening: the production default client blocks any dial whose RESOLVED
		// IP is loopback / link-local (incl. 169.254.169.254 cloud metadata) / RFC1918 /
		// ULA / CGNAT / unspecified. The check runs in the dialer Control hook AFTER DNS
		// resolution, so a hostname that rebinds to an internal IP is still rejected.
		// Tests/embedders that inject their own client (e.g. an httptest server on
		// 127.0.0.1) intentionally bypass this guard.
		cfg.HTTPClient = newGuardedHTTPClient(15 * time.Second)
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Dispatcher{
		pool:    pool,
		cfg:     cfg,
		queue:   make(chan *job, cfg.Buffer),
		stop:    make(chan struct{}),
		buckets: make(map[uuid.UUID]*tokenBucket),
	}
}

// Start launches the worker pool + retry sweeper. Idempotent.
func (d *Dispatcher) Start(ctx context.Context) {
	for i := 0; i < d.cfg.Workers; i++ {
		d.wg.Add(1)
		go d.worker(ctx, i)
	}
	d.wg.Add(1)
	go d.sweeper(ctx)
}

// Stop signals workers to exit and waits up to 5s for drain.
func (d *Dispatcher) Stop() {
	close(d.stop)
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// Dispatch is the fire-and-forget entry. It loads matching receivers, persists a
// pending delivery row per receiver, and enqueues each row for the worker pool.
// Returns the delivery ids (caller can poll their state).
func (d *Dispatcher) Dispatch(ctx context.Context, ev Event) ([]uuid.UUID, error) {
	if d == nil || d.pool == nil {
		return nil, nil
	}
	if ev.OrgID == uuid.Nil {
		return nil, errors.New("notify: dispatch missing org_id")
	}
	if ev.Kind == "" {
		return nil, errors.New("notify: dispatch missing kind")
	}
	if ev.FiredAt.IsZero() {
		ev.FiredAt = d.cfg.Now()
	}
	if ev.IdempotencyKey == uuid.Nil {
		ev.IdempotencyKey = uuid.New()
	}
	// B1: mirror the event to the live syslog/SIEM target (if configured) before the
	// HTTP receiver fan-out. Best-effort + non-blocking: syslog is a fire-and-forget
	// log stream, not a tracked receiver delivery.
	d.fireSyslog(ctx, ev)

	recs, err := d.loadReceiversForEvent(ctx, ev)
	if err != nil {
		return nil, fmt.Errorf("notify: load receivers: %w", err)
	}
	ids := make([]uuid.UUID, 0, len(recs))
	for _, rec := range recs {
		dlvID, err := d.persistPending(ctx, rec, ev)
		if err != nil {
			d.cfg.Logger.Warn("notify: persist pending failed",
				slog.String("receiver", rec.Name), slog.String("err", err.Error()))
			continue
		}
		ids = append(ids, dlvID)
		j := &job{
			deliveryID: dlvID,
			receiver:   rec,
			event:      ev,
			enqueuedAt: d.cfg.Now(),
		}
		select {
		case d.queue <- j:
		default:
			// Queue full — DON'T drop the alert. Mark it retrying with next_retry_at set so
			// the sweeper re-enqueues it once the worker pool drains. final_state stays NULL
			// (a full queue during an alert storm is exactly when losing alerts is worst).
			d.markQueueFull(context.Background(), dlvID)
		}
	}
	return ids, nil
}

// DispatchSynchronous is the test/operator hook used by /test-fire: same path as
// Dispatch but waits for the single receiver to actually fire (or fail) and returns
// the resulting delivery id. Honours retries.
func (d *Dispatcher) DispatchTo(ctx context.Context, receiverID uuid.UUID, ev Event) (uuid.UUID, error) {
	rec, err := d.loadReceiver(ctx, receiverID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("notify: load receiver: %w", err)
	}
	if ev.IdempotencyKey == uuid.Nil {
		ev.IdempotencyKey = uuid.New()
	}
	if ev.FiredAt.IsZero() {
		ev.FiredAt = d.cfg.Now()
	}
	dlvID, err := d.persistPending(ctx, rec, ev)
	if err != nil {
		return uuid.Nil, err
	}
	j := &job{deliveryID: dlvID, receiver: rec, event: ev, enqueuedAt: d.cfg.Now()}
	select {
	case d.queue <- j:
	default:
		d.markQueueFull(ctx, dlvID)
	}
	return dlvID, nil
}

// fireSyslog mirrors ev to the org's LIVE syslog/SIEM target when one is configured via
// the SyslogTarget resolver (B1). Best-effort: a resolver miss or a send error is logged
// and swallowed so syslog never blocks or fails the receiver fan-out.
func (d *Dispatcher) fireSyslog(ctx context.Context, ev Event) {
	if d.cfg.SyslogTarget == nil {
		return
	}
	sender, ok := d.cfg.SyslogTarget(ctx, ev.OrgID)
	if !ok || sender == nil {
		return
	}
	alert := Alert{
		ID:       ev.IdempotencyKey.String(),
		OrgID:    ev.OrgID.String(),
		Severity: nonempty(ev.Severity, "info"),
		Kind:     ev.Kind,
		Title:    ev.Title,
		Cluster:  ev.Cluster,
		Workload: ev.Workload,
		Labels:   ev.Labels,
		URL:      ev.URL,
		FiredAt:  ev.FiredAt,
	}
	if err := sender.Send(ctx, []Alert{alert}); err != nil {
		d.cfg.Logger.Warn("notify: syslog mirror failed",
			slog.String("kind", ev.Kind), slog.String("err", err.Error()))
	}
}

// ----------------------------------- internals --------------------------------------

type receiverRow struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	Name       string
	Kind       string
	Endpoint   string
	SecretKey  string
	RatePerMin int
	TemplateID string
	Paused     bool
	Config     []byte
}

type job struct {
	deliveryID uuid.UUID
	receiver   receiverRow
	event      Event
	enqueuedAt time.Time
	attempt    int // 0-based
}

func (d *Dispatcher) loadReceiversForEvent(ctx context.Context, ev Event) ([]receiverRow, error) {
	// At v1 we fan out to every non-paused receiver in the org whose `supported_events`
	// is empty OR contains the event kind. The Alertmanager-style routing tree is layered
	// on top (see Router) but the dispatcher itself uses receiver-level filters so that
	// new receivers with no route still get configured events.
	rows, err := d.pool.Query(ctx, `
SELECT id, org_id, name, kind, endpoint,
       COALESCE(secret_key,''), COALESCE(rate_per_min,60),
       COALESCE(template_id,'default'), COALESCE(paused,false),
       COALESCE(config,'{}'::jsonb)
  FROM receivers
 WHERE org_id = $1
   AND paused = false
   AND (
     supported_events = '[]'::jsonb
     OR supported_events @> $2::jsonb
     OR EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(supported_events) ev
         WHERE $3 LIKE ev || '%'
     )
   )`, ev.OrgID, mustJSON([]string{ev.Kind}), ev.Kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []receiverRow
	for rows.Next() {
		var r receiverRow
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Name, &r.Kind, &r.Endpoint,
			&r.SecretKey, &r.RatePerMin, &r.TemplateID, &r.Paused, &r.Config); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *Dispatcher) loadReceiver(ctx context.Context, id uuid.UUID) (receiverRow, error) {
	var r receiverRow
	err := d.pool.QueryRow(ctx, `
SELECT id, org_id, name, kind, endpoint,
       COALESCE(secret_key,''), COALESCE(rate_per_min,60),
       COALESCE(template_id,'default'), COALESCE(paused,false),
       COALESCE(config,'{}'::jsonb)
  FROM receivers WHERE id = $1`, id).Scan(
		&r.ID, &r.OrgID, &r.Name, &r.Kind, &r.Endpoint,
		&r.SecretKey, &r.RatePerMin, &r.TemplateID, &r.Paused, &r.Config)
	return r, err
}

func (d *Dispatcher) persistPending(ctx context.Context, rec receiverRow, ev Event) (uuid.UUID, error) {
	id := uuid.New()
	// Persist the FULL event as JSONB so a retried delivery replays the exact same body
	// (title/body/cluster/workload/url/labels/payload/fired_at). Without this the sweeper
	// could only rebuild an empty "(retry) <kind>" stub, so retried Slack/PagerDuty/webhook
	// POSTs were content-free and the per-attempt HMAC was computed over the wrong body.
	payload, err := json.Marshal(ev)
	if err != nil {
		return uuid.Nil, fmt.Errorf("notify: marshal payload: %w", err)
	}
	_, err = d.pool.Exec(ctx, `
INSERT INTO receiver_deliveries (id, org_id, receiver_id, event_type, severity,
                                 status, attempts, idempotency_key, payload, created_at)
VALUES ($1, $2, $3, $4, $5, 'pending', 0, $6, $7::jsonb, NOW())`,
		id, rec.OrgID, rec.ID, ev.Kind, nonempty(ev.Severity, "info"), ev.IdempotencyKey, payload)
	return id, err
}

func (d *Dispatcher) worker(ctx context.Context, idx int) {
	defer d.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stop:
			return
		case j, ok := <-d.queue:
			if !ok {
				return
			}
			d.process(ctx, j)
		}
	}
}

func (d *Dispatcher) process(ctx context.Context, j *job) {
	// Rate-limit gate.
	if !d.tryConsume(j.receiver) {
		// Watermark check: if queued for >5min, drop.
		if d.cfg.Now().Sub(j.enqueuedAt) > d.cfg.RateLimitWatermark {
			d.markRateLimited(ctx, j.deliveryID)
			return
		}
		// Re-queue (best-effort) after a short sleep.
		go func() {
			time.Sleep(2 * time.Second)
			select {
			case d.queue <- j:
			default:
				d.markRateLimited(context.Background(), j.deliveryID)
			}
		}()
		return
	}

	// Render the body once (both HTTP and email paths use it).
	body, contentType, err := renderBody(j.receiver, j.event)
	if err != nil {
		d.handleFailure(ctx, j, fmt.Sprintf("render: %v", err))
		return
	}

	// Email is an SMTP send, not an HTTP POST — branch before the HTTP machinery.
	if strings.EqualFold(j.receiver.Kind, "email") {
		d.processEmail(ctx, j, body)
		return
	}

	sig, signedAt := signHMAC(j.receiver.SecretKey, body, d.cfg.Now())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.receiver.Endpoint, bytes.NewReader(body))
	if err != nil {
		d.handleFailure(ctx, j, fmt.Sprintf("build request: %v", err))
		return
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Constellation-Notifier/1.0")
	req.Header.Set("X-Constellation-Idempotency", j.event.IdempotencyKey.String())
	req.Header.Set("X-Constellation-Event", j.event.Kind)
	if sig != "" {
		req.Header.Set("X-Constellation-Signature", sig)
	}

	start := d.cfg.Now()
	resp, err := d.cfg.HTTPClient.Do(req)
	latency := int(d.cfg.Now().Sub(start) / time.Millisecond)
	if err != nil {
		d.handleFailure(ctx, j, fmt.Sprintf("post: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Drain a snippet of body for the error column.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		d.handleFailure(ctx, j, fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet))))
		return
	}

	// Success.
	d.markDelivered(ctx, j, latency, signedAt)
}

// markDelivered records a successful delivery + flips the receiver healthy. Shared
// by the HTTP and email send paths.
func (d *Dispatcher) markDelivered(ctx context.Context, j *job, latencyMs int, signedAt time.Time) {
	_, _ = d.pool.Exec(ctx, `
UPDATE receiver_deliveries
   SET status      = 'delivered',
       final_state = 'delivered',
       attempts    = attempts + 1,
       latency_ms  = $2,
       signed_at   = $3,
       delivered_at = NOW(),
       next_retry_at = NULL
 WHERE id = $1`, j.deliveryID, latencyMs, signedAt)
	_, _ = d.pool.Exec(ctx, `
UPDATE receivers SET last_verified_at = NOW(), status = 'healthy', status_message = NULL
 WHERE id = $1`, j.receiver.ID)
}

// processEmail delivers a rendered body via SMTP. The alert Title is the subject;
// recipients come from the receiver's config ({"to": ["a@x.com", ...]}). Uses the
// same retry/backoff bookkeeping as the HTTP path.
func (d *Dispatcher) processEmail(ctx context.Context, j *job, body []byte) {
	if d.cfg.SMTPServer == nil {
		d.handleFailure(ctx, j, "email: no SMTP server configured")
		return
	}
	server, ok := d.cfg.SMTPServer(ctx, j.receiver.OrgID)
	if !ok {
		d.handleFailure(ctx, j, "email: no SMTP server configured")
		return
	}
	to := parseEmailRecipients(j.receiver.Config)
	if len(to) == 0 {
		d.handleFailure(ctx, j, "email: receiver has no recipients")
		return
	}
	subject := j.event.Title
	if subject == "" {
		subject = "Constellation: " + j.event.Kind
	}
	start := d.cfg.Now()
	if err := server.SendMail(ctx, to, subject, string(body)); err != nil {
		d.handleFailure(ctx, j, err.Error())
		return
	}
	latency := int(d.cfg.Now().Sub(start) / time.Millisecond)
	d.markDelivered(ctx, j, latency, d.cfg.Now())
}

// parseEmailRecipients pulls the recipient list from a receiver's config JSON. It
// accepts {"to": ["a", "b"]} or {"to": "a, b"}.
func parseEmailRecipients(cfg []byte) []string {
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
	if json.Unmarshal(parsed.To, &list) == nil && len(list) > 0 {
		return cleanRecipients(list)
	}
	var single string
	if json.Unmarshal(parsed.To, &single) == nil && single != "" {
		return cleanRecipients(strings.Split(single, ","))
	}
	return nil
}

func cleanRecipients(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (d *Dispatcher) handleFailure(ctx context.Context, j *job, msg string) {
	attempt := j.attempt + 1
	maxAttempts := len(d.cfg.BackoffSchedule) + 1 // initial try + N retries
	if attempt >= maxAttempts {
		d.markFailed(ctx, j.deliveryID, "failed", msg)
		_, _ = d.pool.Exec(ctx, `
UPDATE receivers SET status = 'degraded', status_message = $2 WHERE id = $1`,
			j.receiver.ID, truncate(msg, 240))
		return
	}
	backoff := d.cfg.BackoffSchedule[attempt-1] // attempt=1 -> BackoffSchedule[0]
	next := d.cfg.Now().Add(backoff)
	_, _ = d.pool.Exec(ctx, `
UPDATE receiver_deliveries
   SET status = 'retrying',
       attempts = $2,
       next_retry_at = $3,
       error = $4
 WHERE id = $1`, j.deliveryID, attempt, next, truncate(msg, 1024))
	d.cfg.Logger.Info("notify: scheduling retry",
		slog.String("receiver", j.receiver.Name),
		slog.Int("attempt", attempt),
		slog.Duration("backoff", backoff),
		slog.String("err", msg))
}

func (d *Dispatcher) markFailed(ctx context.Context, id uuid.UUID, state, msg string) {
	_, _ = d.pool.Exec(ctx, `
UPDATE receiver_deliveries
   SET status      = $2,
       final_state = $2,
       attempts    = attempts + 1,
       error       = $3,
       next_retry_at = NULL
 WHERE id = $1`, id, state, truncate(msg, 1024))
}

// markQueueFull is the non-terminal counterpart to markFailed for an over-capacity queue:
// it keeps final_state NULL and sets next_retry_at so the sweeper re-enqueues the delivery
// rather than dropping it forever (the sweeper selects final_state IS NULL AND next_retry_at
// IS NOT NULL). attempts is left untouched so the first real worker pass is still attempt 0.
func (d *Dispatcher) markQueueFull(ctx context.Context, id uuid.UUID) {
	backoff := d.cfg.BackoffSchedule[0]
	next := d.cfg.Now().Add(backoff)
	_, _ = d.pool.Exec(ctx, `
UPDATE receiver_deliveries
   SET status        = 'retrying',
       next_retry_at = $2,
       final_state   = NULL,
       error         = 'dispatch queue saturated; queued for retry'
 WHERE id = $1`, id, next)
}

func (d *Dispatcher) markRateLimited(ctx context.Context, id uuid.UUID) {
	_, _ = d.pool.Exec(ctx, `
UPDATE receiver_deliveries
   SET status      = 'rate_limited',
       final_state = 'rate_limited',
       next_retry_at = NULL,
       error       = 'dropped: rate-limit watermark exceeded'
 WHERE id = $1`, id)
}

// sweeper polls for retry-due deliveries and re-enqueues them.
func (d *Dispatcher) sweeper(ctx context.Context) {
	defer d.wg.Done()
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stop:
			return
		case <-t.C:
			d.sweepOnce(ctx)
		}
	}
}

func (d *Dispatcher) sweepOnce(ctx context.Context) {
	rows, err := d.pool.Query(ctx, `
SELECT d.id, d.receiver_id, d.idempotency_key, d.attempts, d.event_type, d.severity,
       COALESCE(d.payload, '{}'::jsonb),
       r.org_id, r.name, r.kind, r.endpoint,
       COALESCE(r.secret_key,''), COALESCE(r.rate_per_min,60),
       COALESCE(r.template_id,'default'), COALESCE(r.paused,false),
       COALESCE(r.config,'{}'::jsonb)
  FROM receiver_deliveries d
  JOIN receivers r ON r.id = d.receiver_id
 WHERE d.final_state IS NULL
   AND d.next_retry_at IS NOT NULL
   AND d.next_retry_at <= NOW()
 LIMIT 64`)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			d.cfg.Logger.Debug("notify: sweep query", slog.String("err", err.Error()))
		}
		return
	}
	defer rows.Close()
	var toEnqueue []*job
	for rows.Next() {
		var (
			dlvID, rcvID, ipk uuid.UUID
			attempts          int
			eventKind, sev    string
			payload           []byte
			r                 receiverRow
		)
		if err := rows.Scan(&dlvID, &rcvID, &ipk, &attempts, &eventKind, &sev, &payload,
			&r.OrgID, &r.Name, &r.Kind, &r.Endpoint,
			&r.SecretKey, &r.RatePerMin, &r.TemplateID, &r.Paused, &r.Config); err != nil {
			continue
		}
		r.ID = rcvID
		if r.Paused {
			d.markFailed(ctx, dlvID, "paused", "receiver paused")
			continue
		}
		// Replay the exact original event from the persisted payload so the retry body
		// (and therefore the recomputed HMAC) matches the first attempt. Fall back to a
		// minimal reconstruction only for legacy rows written before the payload column.
		ev := Event{
			Kind: eventKind, OrgID: r.OrgID, Severity: sev,
			Title:          "(retry) " + eventKind,
			IdempotencyKey: ipk,
			FiredAt:        d.cfg.Now(),
		}
		var stored Event
		if len(payload) > 0 && json.Unmarshal(payload, &stored) == nil && (stored.Kind != "" || stored.Title != "" || stored.Body != "") {
			ev = stored
			ev.IdempotencyKey = ipk
			if ev.Kind == "" {
				ev.Kind = eventKind
			}
			if ev.OrgID == uuid.Nil {
				ev.OrgID = r.OrgID
			}
			if ev.Severity == "" {
				ev.Severity = sev
			}
			if ev.FiredAt.IsZero() {
				ev.FiredAt = d.cfg.Now()
			}
		}
		toEnqueue = append(toEnqueue, &job{
			deliveryID: dlvID, receiver: r, event: ev,
			enqueuedAt: d.cfg.Now(), attempt: attempts,
		})
	}
	for _, j := range toEnqueue {
		// Clear next_retry_at so we don't double-fire on the next sweep.
		_, _ = d.pool.Exec(ctx, `UPDATE receiver_deliveries SET next_retry_at = NULL WHERE id = $1`, j.deliveryID)
		select {
		case d.queue <- j:
		default:
			// Reset retry-at; next sweep will pick it up again.
			_, _ = d.pool.Exec(ctx, `UPDATE receiver_deliveries SET next_retry_at = NOW() + interval '5 seconds' WHERE id = $1`, j.deliveryID)
		}
	}
}

// ----------------------------------- rate limit -------------------------------------

type tokenBucket struct {
	mu        sync.Mutex
	tokens    float64
	max       float64
	refillPer time.Duration // time per token
	last      time.Time
}

func (d *Dispatcher) tryConsume(rec receiverRow) bool {
	d.bucketsMu.Lock()
	b, ok := d.buckets[rec.ID]
	if !ok || b.max != float64(rec.RatePerMin) {
		b = &tokenBucket{
			tokens:    float64(rec.RatePerMin),
			max:       float64(rec.RatePerMin),
			refillPer: time.Minute / time.Duration(maxInt(rec.RatePerMin, 1)),
			last:      d.cfg.Now(),
		}
		d.buckets[rec.ID] = b
	}
	d.bucketsMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	now := d.cfg.Now()
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		gained := float64(elapsed) / float64(b.refillPer)
		b.tokens += gained
		if b.tokens > b.max {
			b.tokens = b.max
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// ----------------------------------- HMAC + helpers ---------------------------------

// signHMAC returns the X-Constellation-Signature header value of the form
// "t=<unix>,v1=<hex>" and the signed_at time. Empty when no secret key.
func signHMAC(key string, body []byte, now time.Time) (string, time.Time) {
	if key == "" {
		return "", now
	}
	ts := now.Unix()
	mac := hmac.New(sha256.New, []byte(key))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil))), now
}

// VerifyHMAC is the symmetric checker — receivers (or tests) use it to validate the
// signature header. Returns true when the header parses and the v1 hex matches.
func VerifyHMAC(key, header string, body []byte) bool {
	if key == "" || header == "" {
		return false
	}
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "t="):
			ts = part[2:]
		case strings.HasPrefix(part, "v1="):
			sig = part[3:]
		}
	}
	if ts == "" || sig == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	fmt.Fprintf(mac, "%s.", ts)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// GenerateSecretKey returns a fresh 256-bit hex-encoded secret. Used at receiver create
// + rotate time.
func GenerateSecretKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("notify: rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func nonempty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Back off to a rune boundary so the result is always valid UTF-8; a raw
	// byte-slice can split a multi-byte rune and Postgres rejects invalid UTF-8.
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ----------------------------------- SSRF guard -------------------------------------

// newGuardedHTTPClient returns an http.Client whose dialer rejects any connection to a
// non-public RESOLVED IP. The guard lives in the dialer Control hook, which fires after DNS
// resolution and immediately before connect(), so it defeats DNS-rebinding (a hostname that
// first resolves public then re-resolves to 169.254.169.254 / an RFC1918 host is still
// blocked on the actual dial). Transport settings mirror http.DefaultTransport.
func newGuardedHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   ssrfDialControl,
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// ssrfDialControl is the net.Dialer Control hook: address is the post-resolution "ip:port"
// about to be dialed. It blocks any non-public destination.
func ssrfDialControl(network, address string, _ syscall.RawConn) error {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return fmt.Errorf("notify: blocked dial on disallowed network %q", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("notify: blocked dial to malformed address %q", address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Control receives a resolved IP literal; a non-IP here means something is wrong.
		return fmt.Errorf("notify: blocked dial to non-IP address %q", host)
	}
	if isBlockedIP(ip) {
		return fmt.Errorf("notify: blocked dial to non-public address %s", ip)
	}
	return nil
}

// isBlockedIP reports whether ip is a destination notify must never reach: loopback,
// link-local (incl. 169.254.169.254 cloud metadata and IPv6 fe80::/10), RFC1918 / ULA
// private, carrier-grade NAT (100.64.0.0/10), the unspecified address, and multicast.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// Carrier-grade NAT 100.64.0.0/10 (RFC 6598) — not covered by IsPrivate.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 0x40 {
		return true
	}
	return false
}

// PublicURLAllowed reports whether endpoint is an https URL whose host is not an obvious
// non-public destination. It is the create/patch-time guard for receiver endpoints; the
// dialer Control hook above is the authoritative dial-time guard (it also defeats rebind).
// Returns a descriptive error when the endpoint is rejected.
func PublicURLAllowed(endpoint string) error {
	u, err := neturl.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("endpoint must be an https:// URL")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("endpoint must include a host")
	}
	// Literal IP: classify directly. Hostname: best-effort resolve + classify every answer
	// (the dial-time Control hook is the real backstop for DNS that changes later).
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("endpoint host %s is a non-public address", host)
		}
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return errors.New("endpoint host localhost is not allowed")
	}
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if isBlockedIP(ip) {
				return fmt.Errorf("endpoint host %s resolves to a non-public address (%s)", host, ip)
			}
		}
	}
	return nil
}
