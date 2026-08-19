package admission

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestAsyncDenyHook_DeliversInOrder verifies the wrapped hook is delivered to
// the inner hook FIFO and that the hot-path Hook() returns without waiting on
// the (slow) inner hook.
func TestAsyncDenyHook_DeliversInOrder(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	done := make(chan struct{})
	inner := func(_ context.Context, ev DenyEvent) {
		mu.Lock()
		seen = append(seen, ev.RuleID)
		if len(seen) == 3 {
			close(done)
		}
		mu.Unlock()
	}
	a := NewAsyncDenyHook(context.Background(), inner, 8)
	hook := a.Hook()

	start := time.Now()
	hook(context.Background(), DenyEvent{RuleID: "a"})
	hook(context.Background(), DenyEvent{RuleID: "b"})
	hook(context.Background(), DenyEvent{RuleID: "c"})
	// Enqueue must be fast — it is a buffered channel send, not the inner work.
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("enqueue blocked for %s; hot path must not wait on inner hook", elapsed)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("inner hook never received all events")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || seen[0] != "a" || seen[1] != "b" || seen[2] != "c" {
		t.Fatalf("delivery not FIFO: %v", seen)
	}
}

// TestAsyncDenyHook_DrainsOnClose is the key shutdown guarantee: events queued
// before Close() are still flushed to the inner hook (the audit is not lost),
// and the inner hook runs under a usable (non-cancelled) context even though the
// admission request context is long gone.
func TestAsyncDenyHook_DrainsOnClose(t *testing.T) {
	var mu sync.Mutex
	processed := 0
	ctxOK := true
	inner := func(ctx context.Context, _ DenyEvent) {
		// Simulate a slow DB write so events are still queued at Close time.
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		processed++
		if ctx.Err() != nil {
			ctxOK = false
		}
		mu.Unlock()
	}
	a := NewAsyncDenyHook(context.Background(), inner, 64)
	hook := a.Hook()

	// A request context that is cancelled the instant the verdict returns. The
	// inner hook must NOT inherit it (it would fail the DB write).
	reqCtx, cancel := context.WithCancel(context.Background())
	const n = 10
	for i := 0; i < n; i++ {
		hook(reqCtx, DenyEvent{RuleID: "r"})
	}
	cancel() // verdict returned; request context dead

	closeCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	a.Close(closeCtx)

	mu.Lock()
	defer mu.Unlock()
	if processed != n {
		t.Fatalf("Close dropped queued audits: processed %d of %d", processed, n)
	}
	if !ctxOK {
		t.Fatal("inner hook ran under a cancelled context; DB writes would fail")
	}
}

// TestAsyncDenyHook_DropsWhenSaturated verifies the hot path never blocks when
// the buffer is full: excess events are dropped (counted) rather than holding
// up the admission deny verdict.
func TestAsyncDenyHook_DropsWhenSaturated(t *testing.T) {
	block := make(chan struct{})
	inner := func(_ context.Context, _ DenyEvent) { <-block } // wedge the worker
	a := NewAsyncDenyHook(context.Background(), inner, 1)
	hook := a.Hook()

	start := time.Now()
	for i := 0; i < 1000; i++ {
		hook(context.Background(), DenyEvent{RuleID: "flood"})
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("hot path blocked under saturation for %s", elapsed)
	}
	if a.Dropped() == 0 {
		t.Fatal("expected some events to be dropped under saturation")
	}
	close(block)
	cctx, c := context.WithTimeout(context.Background(), 2*time.Second)
	defer c()
	a.Close(cctx)
}

// TestAsyncDenyHook_NilInner is a safety check: a nil inner hook yields a nil
// Hook() and a no-op Close (audit disabled path).
func TestAsyncDenyHook_NilInner(t *testing.T) {
	a := NewAsyncDenyHook(context.Background(), nil, 4)
	if a.Hook() != nil {
		t.Fatal("nil inner should yield nil Hook")
	}
	a.Close(context.Background()) // must not panic or hang
}
