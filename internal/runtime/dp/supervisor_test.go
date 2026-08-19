package dp

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSupervisorRunOnceCountsCrashExit(t *testing.T) {
	bin := writeDPTestScript(t, "exit 7\n")
	s := New(Options{
		Binary:         bin,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		RestartBackoff: time.Millisecond,
	})
	if clean := s.runOnce(context.Background()); clean {
		t.Fatal("runOnce returned clean for non-zero exit")
	}
	life, _, _, _ := s.Stats()
	if life.StartCount != 1 || life.ExitCount != 1 || life.CrashCount != 1 {
		t.Fatalf("lifecycle=%+v want start=1 exit=1 crash=1", life)
	}
}

func TestSupervisorRunOnceCountsCleanExit(t *testing.T) {
	bin := writeDPTestScript(t, "exit 0\n")
	s := New(Options{
		Binary:         bin,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		RestartBackoff: time.Millisecond,
	})
	if clean := s.runOnce(context.Background()); !clean {
		t.Fatal("runOnce returned crash for zero exit")
	}
	life, _, _, _ := s.Stats()
	if life.StartCount != 1 || life.ExitCount != 1 || life.CrashCount != 0 {
		t.Fatalf("lifecycle=%+v want start=1 exit=1 crash=0", life)
	}
}

func writeDPTestScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dp-test.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
