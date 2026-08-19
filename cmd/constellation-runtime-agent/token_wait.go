// Token-wait helper: poll a file-mounted Secret until it contains a
// non-empty token, returning it. Used at agent startup to bridge the
// chart's post-install bootstrap-job race window (see main.go).
//
// We poll the file rather than env because env-from-secret is resolved
// once at container start; if the secret didn't exist at that moment
// the env value is permanently empty for the lifetime of the container.
// File-mounted secrets, in contrast, are auto-updated by the kubelet
// when the underlying Secret changes — so polling the file lets a
// long-running pod pick up a Secret that was created after pod start.
package main

import (
	"log/slog"
	"os"
	"strings"
	"time"
)

// waitForToken polls path every pollEvery up to timeout. Returns the
// trimmed file contents when non-empty, or "" if the timeout elapses
// (agent falls back to stdout-only mode in that case).
func waitForToken(path string, pollEvery, timeout time.Duration, logger *slog.Logger) string {
	deadline := time.Now().Add(timeout)
	for {
		if b, err := os.ReadFile(path); err == nil {
			s := strings.TrimSpace(string(b))
			if s != "" {
				logger.Info("runtime-agent: token loaded from file", slog.String("file", path))
				return s
			}
		}
		if time.Now().After(deadline) {
			logger.Warn("runtime-agent: token file never populated; falling back to stdout-only mode",
				slog.String("file", path),
				slog.Duration("waited", timeout),
			)
			return ""
		}
		time.Sleep(pollEvery)
	}
}
