// Wave 9: liveness + readiness HTTP server for the runtime-agent DaemonSet.
//
// Kubelet hits /healthz on every node periodically. We return 200 if main()
// has reached this point — the process is running, sockets exist, signals
// are being handled. A 503 means the process should be restarted.
//
// /readyz requires the current active dp generation to have answered a
// keepalive, or reports ready immediately when dp is disabled. Lifecycle,
// keepalive and tap counters are diagnostic; fresh tap reconciliation and
// enforcement acceptance require their own signals.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// runHealthServer is started as a goroutine from main(). It listens on addr
// (typically :9404) until ctx is canceled. dpSup may be nil; readiness then
// reports "dp disabled" — still 200, because in dp-disabled mode the agent
// is just an exec/file event shipper and is ready as soon as it starts.
//
// metrics may be nil — when nil the /metrics endpoint returns 503 so a
// Prometheus scrape config doesn't break.
func runHealthServer(ctx context.Context, logger *slog.Logger, addr string, dpSup *dp.Supervisor, metrics *metricsSource) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeHealthJSON(w, http.StatusOK, map[string]any{"status": "alive"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		writeReadyJSON(w, dpSup)
	})
	if metrics != nil {
		mux.HandleFunc("/metrics", metricsHandler(metrics))
	} else {
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "metrics not available", http.StatusServiceUnavailable)
		})
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Shut down cleanly when the agent receives SIGTERM. A 5s grace gives
	// in-flight probe requests time to drain.
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutCtx)
	}()

	logger.Info("health server: listening", slog.String("addr", addr))
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		// A bind failure (port already in use) is a real config issue but
		// shouldn't kill the agent — the kubelet probe simply fails over to
		// "unhealthy" and the operator can fix the values.yaml.
		var ne *net.OpError
		if errors.As(err, &ne) {
			logger.Error("health server: listen failed",
				slog.String("addr", addr), slog.String("err", err.Error()))
			return
		}
		logger.Warn("health server: closed", slog.String("err", err.Error()))
	}
}

// writeReadyJSON reports readiness for the current active dp generation.
// Keep the concrete supervisor boundary so a disabled (nil) dp stays ready.
func writeReadyJSON(w http.ResponseWriter, dpSup *dp.Supervisor) {
	if dpSup == nil {
		writeHealthJSON(w, http.StatusOK, map[string]any{"status": "ready", "dp": "disabled"})
		return
	}
	writeDPReadyJSON(w, dpSup)
}

type dpReadinessSource interface {
	Ready() bool
	Stats() (dp.LifecycleStats, dp.Stats, dp.ClientStats, dp.TapStats)
}

// writeDPReadyJSON keeps cumulative counters as diagnostics and gates on the
// supervisor's current active generation, including exits and pending restarts.
func writeDPReadyJSON(w http.ResponseWriter, dpSup dpReadinessSource) {
	body := map[string]any{}
	life, _, ka, taps := dpSup.Stats()
	body["dp_starts"] = life.StartCount
	body["dp_crashes"] = life.CrashCount
	body["dp_ka_replied"] = ka.Replied
	body["dp_ka_errors"] = ka.Errors
	body["dp_taps_added"] = taps.Added
	body["dp_taps_errors"] = taps.Errors
	body["dp_taps_current"] = taps.CurrentTaps

	if !dpSup.Ready() {
		body["status"] = "starting"
		body["reason"] = "current dp generation is not ready"
		if life.StartCount == 0 {
			body["reason"] = "dp not yet started"
		}
		writeHealthJSON(w, http.StatusServiceUnavailable, body)
		return
	}
	body["status"] = "ready"
	writeHealthJSON(w, http.StatusOK, body)
}

func writeHealthJSON(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
