// Wave N6: heartbeat side-car for constellation-discoverer.
//
// We deliberately keep this in a separate file so the reconciler logic in
// main.go is owned by Wave M2. The init() below schedules a goroutine using
// the same os.Signal context the main reconcile loop uses, so the heartbeat
// stops when the discoverer shuts down.
package main

import (
	"context"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/alphabravocompany/constellation/pkg/version"
)

// startHeartbeat must be called from main() AFTER the reconciler has settled
// the cluster_id (so we can include it in every heartbeat). Wired via init()
// is too early — we don't know the cluster yet. Instead, main calls this
// helper once it has resolved the cluster row.
func startHeartbeat(parent context.Context, logger *slog.Logger, clusterID string) {
	apiURL, token := discovererAPIConfig()
	if apiURL == "" || token == "" {
		logger.Info("heartbeat.disabled",
			slog.String("component", "discoverer"),
			slog.String("reason", "CONSTELLATION_API_URL or token missing"))
		return
	}
	version.LogStartup(logger, "discoverer")
	go version.HeartbeatLoop(parent, version.HeartbeatConfig{
		APIBaseURL: apiURL,
		Token:      token,
		Component:  "discoverer",
		ClusterID:  clusterID,
		Logger:     logger,
	})
}

// signalContext returns a context that is canceled on SIGINT/SIGTERM. Used by
// the heartbeat goroutine when main.go hasn't already exposed its own context.
// Currently unused (main.go threads its own ctx), but kept available for tests
// that exercise the heartbeat in isolation.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}
