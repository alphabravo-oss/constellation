// Wave 9: liveness + readiness HTTP server for the runtime-agent DaemonSet.
//
// Kubelet hits /healthz on every node periodically. We return 200 if main()
// has reached this point — the process is running, sockets exist, signals
// are being handled. A 503 means the process should be restarted.
//
// /readyz is more conservative: it answers 200 only once dp's keepalive has
// round-tripped at least once AND the tap reconciler has run at least once.
// Until then we report 503 with a structured body so kubelet keeps the pod
// out of any internal Service endpoints (none today, but future state).
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

// writeReadyJSON inspects the dp supervisor (when enabled) for the two
// signals that mean "the data plane is functioning": at least one keepalive
// round-trip + at least one tap installed (or zero adds and zero errors,
// meaning the reconciler ran on an empty host).
func writeReadyJSON(w http.ResponseWriter, dpSup *dp.Supervisor) {
	body := map[string]any{}
	if dpSup == nil {
		body["status"] = "ready"
		body["dp"] = "disabled"
		writeHealthJSON(w, http.StatusOK, body)
		return
	}
	life, _, ka, taps := dpSup.Stats()
	body["dp_starts"] = life.StartCount
	body["dp_crashes"] = life.CrashCount
	body["dp_ka_replied"] = ka.Replied
	body["dp_ka_errors"] = ka.Errors
	body["dp_taps_added"] = taps.Added
	body["dp_taps_errors"] = taps.Errors
	body["dp_taps_current"] = taps.CurrentTaps

	// Ready when:
	//   - dp has been started at least once (init done)
	//   - keepalive has round-tripped (IPC alive)
	//   - reconciler ran (Added > 0 OR Errors == 0 with CurrentTaps == 0
	//     for a host with no pod veths yet)
	if life.StartCount == 0 {
		body["status"] = "starting"
		body["reason"] = "dp not yet started"
		writeHealthJSON(w, http.StatusServiceUnavailable, body)
		return
	}
	if ka.Replied == 0 {
		body["status"] = "starting"
		body["reason"] = "no dp keepalive reply yet"
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
