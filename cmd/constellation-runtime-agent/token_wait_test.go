package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWaitForTokenReadsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  runtime-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := waitForToken(path, time.Millisecond, 50*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got != "runtime-token" {
		t.Fatalf("token=%q want runtime-token", got)
	}
}

func TestWaitForTokenPollsUntilFileIsPopulated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = os.WriteFile(path, []byte("late-token"), 0o600)
	}()
	got := waitForToken(path, time.Millisecond, 200*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got != "late-token" {
		t.Fatalf("token=%q want late-token", got)
	}
}

func TestWaitForTokenTimesOutEmpty(t *testing.T) {
	got := waitForToken(filepath.Join(t.TempDir(), "missing"), time.Millisecond, 5*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got != "" {
		t.Fatalf("token=%q want empty timeout result", got)
	}
}
