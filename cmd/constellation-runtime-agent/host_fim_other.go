//go:build !linux

package main

import (
	"context"
	"log/slog"
)

// hostFIMLoop is a no-op on non-linux: the host FIM uses fanotify (linux-only).
func hostFIMLoop(ctx context.Context, cfg hostFIMConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.Logger.Info("host-fim: disabled (fanotify is linux-only)")
	<-ctx.Done()
}
