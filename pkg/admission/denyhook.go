package admission

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// AsyncDenyHook offloads the DenyHook side-effects (admission.deny audit INSERT,
// uncached response-rule SELECT, quarantine INSERTs) off the admission deny
// path so the verdict returns immediately.
//
// Why this matters: those writes ran SYNCHRONOUSLY before the deny response was
// returned. Only the deny path pays the DB cost, so under DB latency/contention
// (or attacker-amplified deny load) the webhook could exceed the API server's
// ~5s timeout. With the shipped failurePolicy: Ignore, a timed-out webhook is
// treated as "allow" — turning the deny the rule produced into an admit. Fanning
// the writes to a background worker keeps the hot path to a single buffered
// channel send.
//
// Semantics:
//   - FIFO ordering is preserved (a single worker drains the buffer in order).
//   - Best-effort under saturation: if the buffer is full the event is dropped
//     (counted) rather than blocking admission — the deny verdict is never held
//     hostage to a slow database.
//   - No audit loss on graceful shutdown: Close() stops intake and drains every
//     queued event through the inner hook before returning.
//   - The inner hook runs under a detached context, NOT the admission request
//     context (which is canceled the moment the verdict is returned), so the DB
//     writes can still complete after the response is sent.
type AsyncDenyHook struct {
	ch      chan DenyEvent
	inner   DenyHook
	base    context.Context
	timeout time.Duration
	wg      sync.WaitGroup

	closeOnce sync.Once
	dropped   atomic.Int64
}

// NewAsyncDenyHook wraps inner in a buffered single-worker dispatcher and starts
// the worker. base is the detached context the inner hook runs under (use
// context.Background()); buffer is the queue depth (<=0 picks a sane default).
func NewAsyncDenyHook(base context.Context, inner DenyHook, buffer int) *AsyncDenyHook {
	if base == nil {
		base = context.Background()
	}
	if buffer <= 0 {
		buffer = 2048
	}
	a := &AsyncDenyHook{
		ch:      make(chan DenyEvent, buffer),
		inner:   inner,
		base:    base,
		timeout: 30 * time.Second,
	}
	if inner != nil {
		a.wg.Add(1)
		go a.run()
	}
	return a
}

func (a *AsyncDenyHook) run() {
	defer a.wg.Done()
	for ev := range a.ch {
		a.dispatch(ev)
	}
}

func (a *AsyncDenyHook) dispatch(ev DenyEvent) {
	defer func() { _ = recover() }() // a buggy hook must not kill the worker
	ctx := a.base
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(a.base, a.timeout)
		defer cancel()
	}
	a.inner(ctx, ev)
}

// Hook returns the non-blocking DenyHook to install on the engines. It performs
// a single buffered channel send and returns immediately; on a full buffer the
// event is dropped (and counted via Dropped) rather than blocking admission.
func (a *AsyncDenyHook) Hook() DenyHook {
	if a == nil || a.inner == nil {
		return nil
	}
	return func(_ context.Context, ev DenyEvent) {
		select {
		case a.ch <- ev:
		default:
			a.dropped.Add(1)
		}
	}
}

// Dropped reports how many deny events were dropped because the buffer was full.
func (a *AsyncDenyHook) Dropped() int64 { return a.dropped.Load() }

// Close stops accepting new events and blocks until every queued event has been
// processed by the inner hook, or until ctx is done. Call it on shutdown so the
// audit/response-rule writes for in-flight denies are not lost.
func (a *AsyncDenyHook) Close(ctx context.Context) {
	if a == nil || a.inner == nil {
		return
	}
	a.closeOnce.Do(func() { close(a.ch) })
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
