package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// exec replaces the fixture shell, so cancellation must stop the actual stalled
// signer rather than merely returning while a child keeps the operation alive.
func stalledCosign(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cosign")
	if err := writeSecurityFixture(bin, []byte("#!/bin/sh\nexec sleep 60\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestCosignBootstrapDeadlineDoesNotPublishKey(t *testing.T) {
	t.Setenv("COSIGN_BIN", stalledCosign(t))
	t.Setenv("COSIGN_KEY", "")
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	signer, err := ensureCosignKey(ctx, dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if signer != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled bootstrap: signer=%v err=%v", signer, err)
	}
	for _, name := range []string{"cosign.key", "cosign.pub"} {
		if _, err := os.Stat(filepath.Join(dir, ".cosign", name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("published %s after deadline: %v", name, err)
		}
	}
}

func TestCosignSigningDeadlineDoesNotProduceSignatureOrChecksumFallback(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	d := daemon{signer: &cosignSigner{bin: stalledCosign(t)}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	signature, err := d.signArtifact(ctx, root, "report.csv", filepath.Join(dir, "report.csv"), []byte("report"))
	if signature != "" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled signing returned signature=%q err=%v", signature, err)
	}
	if _, err := root.Stat("report.csv.sig"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published signature after deadline: %v", err)
	}
}

func TestCosignBootstrapHonorsCancellationBeforeUsingConfiguredKey(t *testing.T) {
	t.Setenv("COSIGN_BIN", stalledCosign(t))
	t.Setenv("COSIGN_KEY", "operator-configured-key")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	signer, err := ensureCosignKey(ctx, t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if signer != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled bootstrap: signer=%v err=%v", signer, err)
	}
}
