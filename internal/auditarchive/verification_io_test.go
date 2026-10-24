package auditarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestCompressedVerificationHonorsCancellation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "archive.gz")
	payload := []byte("compressed fixture")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := verifyCompressedHash(ctx, file, Manifest{ArchiveSHA256: hash, SHA256: hash}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled hash returned %v", err)
	}
}

func TestSignedManifestRejectsAmbiguousMetadata(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	if err := backup.GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	signer := backup.SignerOptions{Mode: backup.SignModeStaticKey, KeyPath: private}
	verifier := backup.VerifierOptions{Mode: backup.SignModeStaticKey, KeyPath: public}
	raw, sig, cert, err := signArchiveManifest(t.Context(), Manifest{FormatVersion: archiveManifestVersion, RecordCount: 1, FirstID: 1, LastID: 1, Stream: "fixture", FirstPrevHash: strings.Repeat("0", 64), SignMode: backup.SignModeStaticKey}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifyManifest(t.Context(), raw, sig, cert, verifier); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{`{"unknown":true,`, `{"stream":"fixture",`} {
		modified := append([]byte(prefix), bytes.TrimSpace(raw)[1:]...)
		signed, _, _, err := backup.Sign(t.Context(), modified, signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = verifyManifest(t.Context(), modified, signed, nil, verifier); err == nil {
			t.Fatal("ambiguous signed metadata accepted")
		}
	}
}
