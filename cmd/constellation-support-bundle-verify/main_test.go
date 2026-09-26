package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signedFixture(t *testing.T) (bundle, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]any{"environment": map[string]any{"api": "healthy"}, "count": json.Number("9007199254740993")}
	encodedSections, err := json.Marshal(sections)
	if err != nil {
		t.Fatal(err)
	}
	sectionsHash := sha256.Sum256(encodedSections)
	keyHash := sha256.Sum256(publicKey)
	fixture := bundle{
		SchemaVersion: schemaVersion,
		BundleID:      "bundle-123",
		GeneratedAt:   time.Date(2026, 9, 26, 8, 34, 56, 123456789, time.FixedZone("EDT", -4*60*60)),
		OrgID:         "org-456",
		Sections:      sections,
		Integrity: integrity{
			Algorithm:          "sha256",
			Scope:              "sections",
			SHA256:             hex.EncodeToString(sectionsHash[:]),
			Signed:             true,
			SignatureAlgorithm: "ed25519",
			PublicKey:          base64.StdEncoding.EncodeToString(publicKey),
			KeyID:              hex.EncodeToString(keyHash[:]),
		},
	}
	payload := "constellation.support_bundle.signature.v1\nconstellation.support_bundle.v1\nbundle-123\n2026-09-26T12:34:56.123456789Z\norg-456\n" + fixture.Integrity.SHA256
	fixture.Integrity.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(payload)))
	return fixture, fixture.Integrity.KeyID
}

func writeBundle(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifySignedBundle(t *testing.T) {
	fixture, pinnedKeyID := signedFixture(t)
	if err := verify(fixture, pinnedKeyID); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"--file", writeBundle(t, encoded), "--key-id", pinnedKeyID}, &output); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "Verified bundle bundle-123 with key "+pinnedKeyID+"\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestVerifyRejectsTamperingAndUntrustedKeys(t *testing.T) {
	fixture, pinnedKeyID := signedFixture(t)
	mutations := map[string]func(*bundle){
		"unsigned":            func(value *bundle) { value.Integrity.Signed = false },
		"sections":            func(value *bundle) { value.Sections["count"] = float64(3) },
		"sections hash":       func(value *bundle) { value.Integrity.SHA256 = strings.Repeat("0", 64) },
		"hash algorithm":      func(value *bundle) { value.Integrity.Algorithm = "other" },
		"hash scope":          func(value *bundle) { value.Integrity.Scope = "other" },
		"missing sections":    func(value *bundle) { value.Sections = nil },
		"schema version":      func(value *bundle) { value.SchemaVersion = "other" },
		"bundle id":           func(value *bundle) { value.BundleID = "other" },
		"generated at":        func(value *bundle) { value.GeneratedAt = value.GeneratedAt.Add(time.Second) },
		"org id":              func(value *bundle) { value.OrgID = "other" },
		"signature algorithm": func(value *bundle) { value.Integrity.SignatureAlgorithm = "other" },
		"signature bytes": func(value *bundle) {
			value.Integrity.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
		"signature encoding": func(value *bundle) { value.Integrity.Signature = "not base64" },
		"signature size":     func(value *bundle) { value.Integrity.Signature = base64.StdEncoding.EncodeToString([]byte("short")) },
		"public key bytes": func(value *bundle) {
			value.Integrity.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
		},
		"public key encoding": func(value *bundle) { value.Integrity.PublicKey = "not base64" },
		"public key size":     func(value *bundle) { value.Integrity.PublicKey = base64.StdEncoding.EncodeToString([]byte("short")) },
		"missing key id":      func(value *bundle) { value.Integrity.KeyID = "" },
		"forged key id":       func(value *bundle) { value.Integrity.KeyID = strings.Repeat("0", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := fixture
			changed.Sections = map[string]any{"environment": fixture.Sections["environment"], "count": json.Number("9007199254740993")}
			mutate(&changed)
			if err := verify(changed, pinnedKeyID); err == nil {
				t.Fatal("modified bundle verified")
			}
		})
	}
	for _, invalidPin := range []string{"", "abc", strings.ToUpper(pinnedKeyID), strings.Repeat("0", 64)} {
		if err := verify(fixture, invalidPin); err == nil {
			t.Fatalf("invalid pinned key %q accepted", invalidPin)
		}
	}
}

func TestRunRejectsInvalidInput(t *testing.T) {
	fixture, pinnedKeyID := signedFixture(t)
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	validPath := writeBundle(t, encoded)
	tooLargePath := writeBundle(t, bytes.Repeat([]byte(" "), maxBundleBytes+1))
	for name, args := range map[string][]string{
		"no file":          {"--key-id", pinnedKeyID},
		"no pin":           {"--file", validPath},
		"uppercase pin":    {"--file", validPath, "--key-id", strings.ToUpper(pinnedKeyID)},
		"wrong pin":        {"--file", validPath, "--key-id", strings.Repeat("0", 64)},
		"extra argument":   {"--file", validPath, "--key-id", pinnedKeyID, "extra"},
		"unknown flag":     {"--unknown"},
		"missing file":     {"--file", filepath.Join(t.TempDir(), "missing.json"), "--key-id", pinnedKeyID},
		"malformed JSON":   {"--file", writeBundle(t, []byte("{")), "--key-id", pinnedKeyID},
		"oversized bundle": {"--file", tooLargePath, "--key-id", pinnedKeyID},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(args, &output); err == nil {
				t.Fatal("invalid input verified")
			}
			if output.Len() != 0 {
				t.Fatalf("success output on failure: %q", output.String())
			}
		})
	}
}
