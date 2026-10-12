// Wave N6: heartbeat side-car for constellation-discoverer.
//
// main calls startHeartbeat after resolving cluster ownership and supplies its
// signal context, so the heartbeat stops when the discoverer shuts down.
package main

import (
	"context"
	"log/slog"

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
