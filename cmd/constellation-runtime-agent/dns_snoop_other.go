//go:build !linux

package main

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// runDNSSnoop is a no-op off Linux; the AF_PACKET DNS snoop is Linux-only.
func runDNSSnoop(_ context.Context, _ *dp.Supervisor, logger *slog.Logger, _ *atomic.Uint64) {
	if logger != nil {
		logger.Info("dns snoop: unsupported on this platform")
	}
}
