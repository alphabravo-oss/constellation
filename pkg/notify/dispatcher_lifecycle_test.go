package notify

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func lifecycleDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	d := NewDispatcher(nil, DispatcherConfig{Workers: 1, Buffer: 1, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	t.Cleanup(d.Stop)
	return d
}

func awaitLifecycleSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatcher lifecycle operation did not finish")
	}
}

func manualRetryTimer() (chan time.Time, <-chan struct{}, func() bool) {
	ticks := make(chan time.Time, 1)
	stopped := make(chan struct{})
	return ticks, stopped, func() bool { close(stopped); return true }
}

func TestRateLimitedRetryPreservesJobAndWatermark(t *testing.T) {
	t.Parallel()
	d := lifecycleDispatcher(t)
	originalTime := time.Now().Add(-4 * time.Minute)
	j := &job{deliveryID: uuid.New(), enqueuedAt: originalTime, attempt: 2, event: Event{Body: "original payload"}}
	ticks, stopped, stop := manualRetryTimer()
	if !d.requeueRateLimitedAfter(t.Context(), j, ticks, stop) {
		t.Fatal("live dispatcher refused delayed retry")
	}
	select {
	case <-d.queue:
		t.Fatal("retry ran before its timer")
	default:
	}
	ticks <- time.Now()
	select {
	case got := <-d.queue:
		if got != j || !got.enqueuedAt.Equal(originalTime) || got.attempt != 2 || got.event.Body != "original payload" {
			t.Fatal("rate-limit retry changed the job, payload, attempt, or original watermark")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ready retry was not queued")
	}
	awaitLifecycleSignal(t, stopped)
}

func TestRateLimitedRetryCancellationStopsTimerAndEnqueue(t *testing.T) {
	for _, cause := range []string{"parent", "dispatcher"} {
		t.Run(cause, func(t *testing.T) {
			d := lifecycleDispatcher(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ticks, stopped, stop := manualRetryTimer()
			if !d.requeueRateLimitedAfter(ctx, &job{}, ticks, stop) {
				t.Fatal("live retry was refused")
			}
			if cause == "parent" {
				cancel()
			} else {
				d.Stop()
			}
			ticks <- time.Now()
			awaitLifecycleSignal(t, stopped)
			select {
			case <-d.queue:
				t.Fatal("canceled retry was queued")
			default:
			}
		})
	}
}

func TestRateLimitedRetryReadyTimerCannotOverrideCanceledParent(t *testing.T) {
	t.Parallel()
	d := lifecycleDispatcher(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticks, stopped, stop := manualRetryTimer()
	if !d.requeueRateLimitedAfter(ctx, &job{}, ticks, stop) {
		t.Fatal("live retry was refused")
	}
	// Hold the final admission gate while both the timer and cancellation become
	// ready. Either select branch must leave the queue untouched.
	d.lifecycleMu.Lock()
	ticks <- time.Now()
	cancel()
	d.lifecycleMu.Unlock()
	awaitLifecycleSignal(t, stopped)
	select {
	case <-d.queue:
		t.Fatal("ready timer overrode canceled parent")
	default:
	}
}

func TestDispatcherStopWaitsForRetryAndRejectsLateRegistration(t *testing.T) {
	t.Parallel()
	d := lifecycleDispatcher(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseRetry := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseRetry)
	stopTimer := func() bool { close(entered); <-release; return true }
	if !d.requeueRateLimitedAfter(t.Context(), &job{}, make(chan time.Time), stopTimer) {
		t.Fatal("live retry was refused")
	}
	finished := make(chan struct{})
	go func() { d.Stop(); close(finished) }()
	awaitLifecycleSignal(t, entered)
	select {
	case <-finished:
		t.Fatal("Stop returned before the registered retry finished")
	default:
	}
	ticks, lateStopped, lateStop := manualRetryTimer()
	ticks <- time.Now()
	if d.requeueRateLimitedAfter(t.Context(), &job{}, ticks, lateStop) {
		t.Fatal("stopping dispatcher admitted a new retry")
	}
	awaitLifecycleSignal(t, lateStopped)
	// Start after Stop must also avoid registering workers after Wait began.
	d.Start(t.Context())
	releaseRetry()
	awaitLifecycleSignal(t, finished)
	d.Stop()
	select {
	case <-d.queue:
		t.Fatal("stopped dispatcher queued a retry")
	default:
	}
}

func TestDispatcherConcurrentStartStopAndRetryRegistration(t *testing.T) {
	t.Parallel()
	for range 50 {
		d := NewDispatcher(nil, DispatcherConfig{Workers: 1, Buffer: 1, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var callers sync.WaitGroup
		callers.Add(3)
		go func() { defer callers.Done(); d.Start(ctx); d.Start(ctx) }()
		go func() { defer callers.Done(); d.Stop(); d.Stop() }()
		go func() {
			defer callers.Done()
			_, _, stop := manualRetryTimer()
			d.requeueRateLimitedAfter(t.Context(), &job{}, make(chan time.Time), stop)
		}()
		callers.Wait()
		d.Stop()
		select {
		case <-d.done:
		default:
			t.Fatal("concurrent lifecycle calls left registered work behind")
		}
	}
}

func TestRateLimitedRetryQueueFailurePreservesExistingJobAndReportsError(t *testing.T) {
	t.Parallel()
	pool, err := pgxpool.New(t.Context(), "postgres://fixture@127.0.0.1:1/unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	// A closed pool fails deterministically without network or a database.
	pool.Close()
	var logs bytes.Buffer
	d := NewDispatcher(pool, DispatcherConfig{Buffer: 1, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	t.Cleanup(d.Stop)
	queued := &job{deliveryID: uuid.New()}
	d.queue <- queued
	j := &job{deliveryID: uuid.New(), enqueuedAt: time.Now().Add(-4 * time.Minute)}
	ticks, stopped, stop := manualRetryTimer()
	if !d.requeueRateLimitedAfter(t.Context(), j, ticks, stop) {
		t.Fatal("live retry was refused")
	}
	ticks <- time.Now()
	awaitLifecycleSignal(t, stopped)
	if <-d.queue != queued {
		t.Fatal("failed retry displaced an existing delivery")
	}
	message := logs.String()
	if !strings.Contains(message, "notify: rate-limit status update failed") || !strings.Contains(message, j.deliveryID.String()) {
		t.Fatal("failed bookkeeping was silently discarded")
	}
	for _, raw := range []string{"closed pool", "127.0.0.1", "postgres://"} {
		if strings.Contains(message, raw) {
			t.Fatal("bookkeeping log exposed raw database diagnostics")
		}
	}
}

type lifecycleContextKey struct{}

func TestRateLimitBookkeepingContextBoundsAndCancellation(t *testing.T) {
	t.Run("deadline ceiling and values", func(t *testing.T) {
		d := lifecycleDispatcher(t)
		parent := context.WithValue(t.Context(), lifecycleContextKey{}, "retained")
		before := time.Now()
		ctx, cancel := d.rateLimitUpdateContext(parent)
		defer cancel()
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(before.Add(5*time.Second+100*time.Millisecond)) || ctx.Value(lifecycleContextKey{}) != "retained" {
			t.Fatal("bookkeeping lost its finite deadline or parent values")
		}
	})
	t.Run("earlier parent deadline", func(t *testing.T) {
		d := lifecycleDispatcher(t)
		parent, parentCancel := context.WithTimeout(t.Context(), time.Second)
		defer parentCancel()
		ctx, cancel := d.rateLimitUpdateContext(parent)
		defer cancel()
		want, _ := parent.Deadline()
		got, ok := ctx.Deadline()
		if !ok || !got.Equal(want) {
			t.Fatal("bookkeeping extended an earlier parent deadline")
		}
	})
	t.Run("parent cancellation", func(t *testing.T) {
		d := lifecycleDispatcher(t)
		parent, parentCancel := context.WithCancel(t.Context())
		ctx, cancel := d.rateLimitUpdateContext(parent)
		defer cancel()
		parentCancel()
		awaitLifecycleSignal(t, ctx.Done())
	})
	t.Run("dispatcher cancellation", func(t *testing.T) {
		d := lifecycleDispatcher(t)
		ctx, cancel := d.rateLimitUpdateContext(t.Context())
		defer cancel()
		d.Stop()
		awaitLifecycleSignal(t, ctx.Done())
	})
	t.Run("already stopped", func(t *testing.T) {
		d := lifecycleDispatcher(t)
		d.Stop()
		ctx, cancel := d.rateLimitUpdateContext(t.Context())
		defer cancel()
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("stopped dispatcher admitted bookkeeping")
		}
	})
}
