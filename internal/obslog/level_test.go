package obslog

import (
	"log/slog"
	"testing"
)

func TestLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		" warn ":  slog.LevelWarn,
		"error":   slog.LevelError,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo, // unset -> Info
		"verbose": slog.LevelInfo, // unknown -> Info
	}
	for in, want := range cases {
		t.Setenv("CONSTELLATION_LOG_LEVEL", in)
		if got := Level(); got != want {
			t.Fatalf("Level(%q) = %v, want %v", in, got, want)
		}
	}
}
