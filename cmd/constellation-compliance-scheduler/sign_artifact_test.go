package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/securefiles"
)

func TestArtifactSigningChecksumFallback(t *testing.T) {
	artifact := []byte("fixture compliance evidence")
	d := daemon{}
	signature, err := d.signArtifact(t.Context(), nil, "report.csv", "", artifact)
	expected := sha256.Sum256(artifact)
	if err != nil || signature != "sha256:"+hex.EncodeToString(expected[:]) {
		t.Fatalf("checksum fallback changed: %q %v", signature, err)
	}
}

func TestArtifactSigningPersistsPrivateSignatureAndPropagatesWriteFailure(t *testing.T) {
	dir := t.TempDir()
	root, err := securefiles.OpenPrivateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	bin := filepath.Join(t.TempDir(), "cosign")
	if err := writeSecurityFixture(bin, []byte("#!/bin/sh\nprintf 'fixture-signature'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	d := daemon{signer: &cosignSigner{bin: bin}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	sig, err := d.signArtifact(t.Context(), root, "report.csv", filepath.Join(dir, "report.csv"), []byte("evidence"))
	if err != nil || sig != "fixture-signature" {
		t.Fatalf("signature changed: %q %v", sig, err)
	}
	body, err := root.ReadFile("report.csv.sig")
	if err != nil || string(body) != sig {
		t.Fatalf("signature not retained: %v", err)
	}
	info, err := root.Stat("report.csv.sig")
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("signature permissions: %v", err)
	}
	if err := root.Remove("report.csv.sig"); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "report.csv.sig")); err != nil {
		t.Fatal(err)
	}
	if sig, err := d.signArtifact(t.Context(), root, "report.csv", filepath.Join(dir, "report.csv"), nil); err == nil || sig != "" {
		t.Fatalf("signature publication error was lost: %q %v", sig, err)
	}
	body, err = readSecurityFixture(t, outside)
	if err != nil || string(body) != "unchanged" {
		t.Fatalf("outside signature modified: %v", err)
	}
}

func TestConfiguredArtifactSigningFailureIsAnError(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "cosign")
	if err := writeSecurityFixture(bin, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var logged strings.Builder
	d := daemon{signer: &cosignSigner{bin: bin}, logger: slog.New(slog.NewTextHandler(&logged, nil))}
	sig, err := d.signArtifact(t.Context(), nil, "report.csv", "unused", nil)
	if err == nil || sig != "" || !strings.Contains(logged.String(), "cosign sign") {
		t.Fatalf("configured signing failure was ignored: %q %v", sig, err)
	}
}

func TestConfiguredArtifactSigningRejectsEmptySignature(t *testing.T) {
	for _, output := range []string{"", " \t\n"} {
		t.Run(fmt.Sprintf("bytes-%d", len(output)), func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "cosign")
			if err := writeSecurityFixture(bin, []byte("#!/bin/sh\nprintf '"+output+"'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			d := daemon{signer: &cosignSigner{bin: bin}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			sig, err := d.signArtifact(t.Context(), nil, "report.csv", "unused", nil)
			if err == nil || sig != "" || !strings.Contains(err.Error(), "empty signature") {
				t.Fatalf("empty configured signature accepted: %q %v", sig, err)
			}
		})
	}
}
