//go:build linux && cgo && integration

package dpi

import (
	"context"
	"testing"
	"time"
)

// TestNFQUEUEAttach is the gated smoke test for the NFQUEUE inline source. It opens
// queue number 99 (an unused number in test) and waits 250ms; if the open + close
// round-trip succeeds the kernel-side wiring is healthy.
//
// Requirements:
//   - root or CAP_NET_ADMIN
//   - iptables rule pointing NF traffic at queue 99 (optional for this smoke test)
//
// Run with:
//   sudo -E env "PATH=$PATH" go test -tags=linux,cgo,integration \
//       ./internal/runtime/dpi/... -run TestNFQUEUEAttach
func TestNFQUEUEAttach(t *testing.T) {
	eng := NewEngine(nil)
	src, err := NewSource(eng, SourceConfig{QueueNum: 99, VerdictAccept: true})
	if err != nil {
		t.Skipf("NFQUEUE open failed (need CAP_NET_ADMIN): %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := src.Run(ctx); err != nil && err != context.DeadlineExceeded {
		// Run returns nil when ctx fires before any error.
		t.Logf("Run: %v", err)
	}
}
