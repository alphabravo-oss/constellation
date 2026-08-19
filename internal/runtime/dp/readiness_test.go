package dp

import (
	"log/slog"
	"testing"
)

// TestSupervisorReadiness asserts the generation/readiness contract: Ready is
// false before any keepalive, true once the current generation's dp answers a
// keepalive, and false again after a restart bumps the generation until the
// fresh instance replies. It wires onReply exactly as Start does.
func TestSupervisorReadiness(t *testing.T) {
	s := &Supervisor{}
	c := newDPClient(slog.Default())
	c.onReply = func() { s.readyGen.Store(s.generation.Load()) }

	// Fresh supervisor: no dp launched yet.
	if s.Generation() != 0 || s.Ready() {
		t.Fatalf("fresh: gen=%d ready=%v; want 0/false", s.Generation(), s.Ready())
	}

	// First dp instance launches (runOnce bumps generation).
	s.generation.Store(1)
	if s.Ready() {
		t.Fatalf("gen1 before reply: Ready()=true; want false")
	}

	// dp answers a keepalive -> onReply fires.
	c.onReply()
	if !s.Ready() || s.Generation() != 1 {
		t.Fatalf("gen1 after reply: ready=%v gen=%d; want true/1", s.Ready(), s.Generation())
	}

	// dp crashes and restarts: generation bumps, readyGen is stale.
	s.generation.Store(2)
	if s.Ready() {
		t.Fatalf("gen2 before fresh reply: Ready()=true; want false")
	}

	// Fresh dp answers -> ready again for the new generation.
	c.onReply()
	if !s.Ready() || s.Generation() != 2 {
		t.Fatalf("gen2 after reply: ready=%v gen=%d; want true/2", s.Ready(), s.Generation())
	}
}
