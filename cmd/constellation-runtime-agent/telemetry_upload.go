package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alphabravocompany/constellation/internal/telemetryspool"
)

const producerHeader = "X-Constellation-Producer"
const sequenceHeader = "X-Constellation-Sequence"
const ackHeader = "X-Constellation-Ack"

var telemetryQueues sync.Map // stream -> *telemetryspool.Queue; metric labels are fixed

type uploadFailure struct {
	status     int
	retryAfter time.Duration
}

func (e *uploadFailure) Error() string { return fmt.Sprintf("telemetry upload HTTP %d", e.status) }

func openTelemetryQueue(stream, target string) (*telemetryspool.Queue, error) {
	dir := os.Getenv("CONSTELLATION_TELEMETRY_SPOOL_DIR")
	if dir == "" {
		dir = "/var/lib/constellation/telemetry"
	}
	limit := int64(256 << 20)
	if raw := os.Getenv("CONSTELLATION_TELEMETRY_SPOOL_BYTES"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1<<20 || n > 16<<30 {
			return nil, errors.New("spool bytes must be between 1 MiB and 16 GiB per stream")
		}
		limit = n
	}
	queue, err := telemetryspool.Open(filepath.Join(dir, stream), target, limit, 4096)
	if err == nil {
		telemetryQueues.Store(stream, queue)
	}
	return queue, err
}

// durableUploadLoop persists each bounded batch before offering it to the
// network. Exactly one delivery worker preserves producer order. Capture can
// continue during an outage up to the disk limit; drop-new is explicit at full.
func durableUploadLoop[T any](ctx context.Context, logger *slog.Logger, q *telemetryspool.Queue, url, token string, size int, interval time.Duration, in <-chan T, uploaded, dropped *atomic.Uint64) {
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); deliverTelemetry(workerCtx, logger, q, url, token, uploaded) }()
	defer func() { cancel(); <-done; _ = q.Close() }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	batch := make([]T, 0, size)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		persistTelemetryBatch(logger, q, batch, dropped)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			// Drain only records already handed to this lane; do not wait for upstream
			// producers after cancellation. Persist without using the cancelled context.
			for {
				select {
				case row, ok := <-in:
					if !ok {
						flush()
						return
					}
					batch = append(batch, row)
					if len(batch) >= size {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case row, ok := <-in:
			if !ok {
				flush()
				return
			}
			batch = append(batch, row)
			if len(batch) >= size {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Split by encoded bytes as well as count. A single oversized observation is
// reported as dropped rather than blocking every subsequent batch with 413.
func persistTelemetryBatch[T any](logger *slog.Logger, q *telemetryspool.Queue, batch []T, dropped *atomic.Uint64) {
	body, err := json.Marshal(batch)
	if err == nil && len(body) > 900<<10 {
		if len(batch) > 1 {
			mid := len(batch) / 2
			persistTelemetryBatch(logger, q, batch[:mid], dropped)
			persistTelemetryBatch(logger, q, batch[mid:], dropped)
			return
		}
		err = errors.New("single telemetry observation exceeds wire limit")
	}
	if err == nil {
		err = q.Enqueue(body, len(batch))
	}
	if err != nil {
		dropped.Add(uint64(len(batch)))
		logger.Error("telemetry spool rejected batch", slog.Int("records", len(batch)), slog.String("error", err.Error()))
	}
}

func deliverTelemetry(ctx context.Context, logger *slog.Logger, q *telemetryspool.Queue, url, token string, uploaded *atomic.Uint64) {
	backoff := time.Second
	for ctx.Err() == nil {
		batch, records, err := validatedTelemetryBatch(q)
		if err != nil {
			logger.Error("telemetry spool unreadable; retaining queue", slog.String("error", err.Error()))
			if !waitUpload(ctx, 30*time.Second) {
				return
			}
			continue
		}
		if batch == nil {
			if !waitUpload(ctx, 100*time.Millisecond) {
				return
			}
			continue
		}
		err = postTelemetry(ctx, sharedUploadClient, url, token, batch.Body, q.Producer(), batch.Sequence)
		if err == nil {
			if err = q.Ack(batch.Sequence); err != nil {
				logger.Error("telemetry acknowledgement could not be persisted", slog.String("error", err.Error()))
				if !waitUpload(ctx, 30*time.Second) {
					return
				}
				continue
			}
			uploaded.Add(records)
			backoff = time.Second
			continue
		}
		files, bytes := q.Stats()
		logger.Warn("telemetry delivery deferred; batch retained", slog.String("error", err.Error()), slog.Int("pending_batches", files), slog.Int64("pending_bytes", bytes))
		delay := backoff + time.Duration(rand.Int64N(int64(backoff/4)+1)) // jitter is not security-sensitive
		var failure *uploadFailure
		if errors.As(err, &failure) && failure.retryAfter > delay {
			delay = failure.retryAfter
		}
		if !waitUpload(ctx, delay) {
			return
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// Keep the captured count validated alongside the batch until its durable ack.
// Invalid retained data must not be uploaded, discarded, or wrap a counter.
func validatedTelemetryBatch(q *telemetryspool.Queue) (*telemetryspool.Batch, uint64, error) {
	batch, err := q.Peek()
	if err != nil || batch == nil {
		return batch, 0, err
	}
	if batch.Count <= 0 {
		return nil, 0, errors.New("telemetry batch count must be positive")
	}
	return batch, uint64(batch.Count), nil
}

func waitUpload(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func postTelemetry(ctx context.Context, client *http.Client, url, token string, body []byte, producer string, sequence int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if producer != "" {
		req.Header.Set(producerHeader, producer)
		req.Header.Set(sequenceHeader, strconv.FormatInt(sequence, 10))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if producer != "" && resp.Header.Get(ackHeader) != strconv.FormatInt(sequence, 10) {
			return errors.New("server did not acknowledge durable telemetry sequence")
		}
		return nil
	}
	return &uploadFailure{status: resp.StatusCode, retryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now())}
}

func retryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Duration(min(seconds, 86400)) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		return min(max(date.Sub(now), 0), 24*time.Hour)
	}
	return 0
}

// Legacy callers keep a bounded retry budget. Persistent lanes use the worker
// above and retain even permanent failures for operator diagnosis.
func postLegacyBatch(ctx context.Context, client *http.Client, url, token string, batch any) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	var last error
	delay := time.Duration(0)
	for _, base := range []time.Duration{0, 100 * time.Millisecond, 400 * time.Millisecond, 1600 * time.Millisecond} {
		if !waitUpload(ctx, max(base, delay)) {
			return ctx.Err()
		}
		last = postTelemetry(ctx, client, url, token, body, "", 0)
		if last == nil {
			return nil
		}
		var failure *uploadFailure
		if errors.As(last, &failure) {
			if failure.status >= 400 && failure.status < 500 && failure.status != 429 && failure.status != 408 {
				return last
			}
			delay = failure.retryAfter
		}
	}
	return last
}
