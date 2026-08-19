// Command constellation-github-app runs the Constellation GitHub App webhook
// receiver.
//
// Required environment:
//
//	GITHUB_APP_ID                  numeric App ID
//	GITHUB_APP_PRIVATE_KEY_PATH    path to the App's RSA PEM
//	GITHUB_WEBHOOK_SECRET          shared secret (X-Hub-Signature-256)
//	CONSTELLATION_SERVER           Constellation API base URL
//	CONSTELLATION_TOKEN            API token (scope `ci-runner`)
//
// Optional:
//
//	LISTEN_ADDR                    default ":8088"
//	CONSTELLATIONCTL_BIN           default "constellationctl"
//	WORKDIR                        scratch dir for SARIF/JSON outputs
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alphabravocompany/constellation/deploy/integrations/github-app/webhook"
	"github.com/alphabravocompany/constellation/internal/obslog"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()}))
	slog.SetDefault(log)

	cfg, err := webhook.FromEnv()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	srv, err := webhook.New(cfg, log)
	if err != nil {
		log.Error("init server", "err", err)
		os.Exit(2)
	}

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8088"
	}
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("listening", "addr", addr, "version", version)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}
