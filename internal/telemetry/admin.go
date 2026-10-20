package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"time"
)

// AdminOptions configures the admin listener handler.
type AdminOptions struct {
	// Ready reports readiness; nil means always ready.
	Ready func(context.Context) error
	// Healthy reports liveness; nil means always healthy.
	Healthy func(context.Context) error
	// EnablePprof mounts net/http/pprof. The admin port must then never be exposed publicly.
	EnablePprof bool
	// Extra registers additional admin-only routes.
	Extra func(mux *http.ServeMux)
}

// AdminHandler serves /healthz, /readyz and /metrics (plus pprof when enabled). Every
// long-lived binary mounts it on a dedicated admin port that is never on the public ingress.
func (t *Telemetry) AdminHandler(opts AdminOptions) http.Handler {
	mux := http.NewServeMux()
	probe := func(fn func(context.Context) error) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if fn != nil {
				if err := fn(r.Context()); err != nil {
					http.Error(w, err.Error(), http.StatusServiceUnavailable)
					return
				}
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok\n"))
		}
	}
	mux.HandleFunc("GET /healthz", probe(opts.Healthy))
	mux.HandleFunc("GET /readyz", probe(opts.Ready))
	mux.Handle("GET /metrics", t.MetricsHandler())
	if opts.EnablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	if opts.Extra != nil {
		opts.Extra(mux)
	}
	return mux
}

// ServeAdmin runs an admin HTTP server on addr until ctx is cancelled. It blocks.
func ServeAdmin(ctx context.Context, addr string, h http.Handler, logger *slog.Logger) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		if logger != nil {
			logger.Info("admin listener", slog.String("addr", addr))
		}
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// StartAdmin runs ServeAdmin in the background and logs a listener failure. A failed admin
// listener is fatal for probes, so the error is logged at Error level.
func StartAdmin(ctx context.Context, addr string, h http.Handler, logger *slog.Logger) {
	go func() {
		if err := ServeAdmin(ctx, addr, h, logger); err != nil && logger != nil {
			logger.Error("admin listener failed", slog.String("addr", addr), slog.String("err", err.Error()))
		}
	}()
}
