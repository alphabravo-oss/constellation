package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

const cosignBundleFixture = `#!/bin/sh
set -eu
bundle=""
while [ "$#" -gt 1 ]; do
 if [ "$1" = --bundle ]; then bundle="$2"; shift; fi
 shift
done
digest=$(openssl dgst -sha256 -binary "$1" | openssl base64 -A)
printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","messageSignature":{"signature":"Zml4dHVyZS1zaWduYXR1cmU=","messageDigest":{"algorithm":"SHA2_256","digest":"%s"}}}' "$digest" > "$bundle"
`

func TestCosignBundleRejectsInvalidSignatureAndWrongReport(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "report")
	if err := os.WriteFile(artifact, []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("report"))
	for _, tc := range []struct{ name, signature, digest, media, algorithm string }{
		{"valid", "c2ln", base64.StdEncoding.EncodeToString(sum[:]), "application/vnd.dev.sigstore.bundle.v0.3+json", "SHA2_256"},
		{"empty", "", base64.StdEncoding.EncodeToString(sum[:]), "application/vnd.dev.sigstore.bundle.v0.3+json", "SHA2_256"},
		{"bad-base64", "!", base64.StdEncoding.EncodeToString(sum[:]), "application/vnd.dev.sigstore.bundle.v0.3+json", "SHA2_256"},
		{"wrong-report", "c2ln", "d3Jvbmc=", "application/vnd.dev.sigstore.bundle.v0.3+json", "SHA2_256"},
		{"wrong-format", "c2ln", base64.StdEncoding.EncodeToString(sum[:]), "unknown", "SHA2_256"},
		{"wrong-algorithm", "c2ln", base64.StdEncoding.EncodeToString(sum[:]), "application/vnd.dev.sigstore.bundle.v0.3+json", "SHA1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"mediaType": tc.media, "messageSignature": map[string]any{"signature": tc.signature, "messageDigest": map[string]any{"algorithm": tc.algorithm, "digest": tc.digest}}})
			if err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(dir, "bundle")
			if err := os.WriteFile(bundle, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			signature, err := readCosignSignature(bundle, artifact)
			if tc.name == "valid" {
				if err != nil || signature != tc.signature {
					t.Fatalf("valid bundle: %q %v", signature, err)
				}
			} else if err == nil || signature != "" {
				t.Fatalf("invalid bundle accepted: %q %v", signature, err)
			}
		})
	}
}

// This opt-in test runs inside the pinned scanner/tool image with --network none.
// Verification uses Go crypto directly, independently of Cosign's verifier.
func TestCosignActualToolRoundTrip(t *testing.T) {
	bin := os.Getenv("CONSTELLATION_TEST_COSIGN_BIN")
	if bin == "" {
		t.Skip("requires pinned Cosign container; exercised by compliance signing workflow")
	}
	password := rand.Text()
	t.Setenv("COSIGN_BIN", bin)
	t.Setenv("COSIGN_KEY", "")
	t.Setenv("COSIGN_PASSWORD", password)
	dir := t.TempDir()
	signer, err := ensureCosignKey(t.Context(), dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "report.json")
	body := []byte(`{"framework":"fixture","checks":[{"status":"pass"}]}`)
	if err := os.WriteFile(artifact, body, 0o600); err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(t.Context(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile(filepath.Join(dir, ".cosign", "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(public)
	if block == nil {
		t.Fatal("missing public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected public key %T", parsed)
	}
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if !ecdsa.VerifyASN1(key, sum[:], decoded) {
		t.Fatal("signature did not verify independently")
	}
	tampered := sha256.Sum256(append(body, '!'))
	if ecdsa.VerifyASN1(key, tampered[:], decoded) {
		t.Fatal("tampered report verified")
	}
}
