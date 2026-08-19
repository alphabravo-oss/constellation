// Package obslog holds tiny cross-service observability helpers shared by every
// cmd/*/main.go. It intentionally depends only on the stdlib.
package obslog

import (
	"log/slog"
	"os"
	"strings"
)

// Level parses CONSTELLATION_LOG_LEVEL (debug|info|warn|error, case-insensitive)
// into an slog.Level. Anything unset or unrecognized falls back to Info so a
// typo can never accidentally silence or flood the logs.
func Level() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CONSTELLATION_LOG_LEVEL"))) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
