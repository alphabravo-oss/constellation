package ebpf

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// TestAgentDegraded exercises the userspace channel + Inject path so the rest of the
// runtime pipeline can be tested without root / a Linux kernel.
func TestAgentDegraded(t *testing.T) {
	a, err := New(Options{EventChannelBuffer: 4})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	want := Event{
		Kind: EventKindNetwork,
		At:   time.Unix(1700000000, 0),
		Network: &NetworkEvent{
			PID: 100, Comm: "curl", Direction: "connect", Protocol: "tcp",
			Src: netip.MustParseAddrPort("10.0.0.1:54321"),
			Dst: netip.MustParseAddrPort("10.0.0.2:80"),
		},
	}
	if err := a.Inject(want); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	select {
	case got := <-a.Events():
		if got.Kind != want.Kind || got.Network == nil || got.Network.Dst != want.Network.Dst {
			t.Fatalf("event mismatch: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit")
	}
}

// TestAgentDropsOnBackpressure verifies the dropped counter when the channel is full.
func TestAgentDropsOnBackpressure(t *testing.T) {
	a, err := New(Options{EventChannelBuffer: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	for range 5 {
		_ = a.Inject(Event{Kind: EventKindProcess, Process: &ProcessEvent{PID: 1, Comm: "init"}})
	}
	if got := a.Dropped(); got != 4 {
		t.Fatalf("Dropped() = %d, want 4", got)
	}
}

// TestAgentAlreadyRunning ensures Run is single-shot.
func TestAgentAlreadyRunning(t *testing.T) {
	a, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	// Give the first call a chance to claim runOnce.
	time.Sleep(10 * time.Millisecond)
	if err := a.Run(ctx); err != ErrAlreadyRunning {
		t.Fatalf("second Run = %v, want ErrAlreadyRunning", err)
	}
	cancel()
	<-done
}
