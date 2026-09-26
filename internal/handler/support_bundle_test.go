package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSupportBundleRedactsSensitiveKeysAndValues(t *testing.T) {
	raw := map[string]any{
		"token":        "cst_raw-token-value",
		"description":  "safe operational detail",
		"database_url": "postgres://alice:hunter2@db.example.test:5432/constellation?sslmode=require",
		"nested": map[string]any{
			"api_key":     "nvd-key-value",
			"last_error":  "scanner failed with bearer token abc123",
			"public_url":  "https://console.example.test/path",
			"private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
		},
		"receivers": []any{
			map[string]any{"webhook_secret": "super-secret-value"},
			map[string]any{"endpoint": "https://hooks.example.test/notify?token=raw-token"},
		},
	}

	got := redactSupportBundleValue(raw, "")
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, forbidden := range []string{
		"cst_raw-token-value",
		"hunter2",
		"alice",
		"nvd-key-value",
		"bearer token abc123",
		"PRIVATE KEY",
		"super-secret-value",
		"raw-token",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("support bundle redaction leaked %q in %s", forbidden, body)
		}
	}
	if !strings.Contains(body, supportBundleRedacted) {
		t.Fatalf("redacted marker missing from %s", body)
	}
	if !strings.Contains(body, "safe operational detail") || !strings.Contains(body, "https://console.example.test/path") {
		t.Fatalf("non-sensitive values were not preserved: %s", body)
	}
}

func TestSupportBundleHashIsStableForRedactedSections(t *testing.T) {
	sections := map[string]any{
		"system_config": map[string]any{"tls_verify": true},
		"scanner_state": map[string]any{"pending": float64(2)},
	}
	first, err := supportBundleHash(sections)
	if err != nil {
		t.Fatal(err)
	}
	second, err := supportBundleHash(sections)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("support bundle hash not stable: %q vs %q", first, second)
	}
}

func TestSupportBundleRedactsStructSections(t *testing.T) {
	sections := map[string]any{
		"component": struct {
			Name     string `json:"name"`
			APIToken string `json:"api_token"`
		}{
			Name:     "scanner",
			APIToken: "raw-token-value",
		},
	}
	redacted, err := redactSupportBundleSections(sections)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(redacted)
	body := string(b)
	if strings.Contains(body, "raw-token-value") {
		t.Fatalf("struct-backed section leaked token: %s", body)
	}
	if !strings.Contains(body, "scanner") || !strings.Contains(body, supportBundleRedacted) {
		t.Fatalf("struct-backed section redaction malformed: %s", body)
	}
}

func testSupportBundle(t *testing.T, sections map[string]any) supportBundleDTO {
	t.Helper()
	sum, err := supportBundleHash(sections)
	if err != nil {
		t.Fatal(err)
	}
	return supportBundleDTO{
		SchemaVersion: supportBundleSchemaVersion,
		BundleID:      "bundle-123",
		GeneratedAt:   time.Date(2026, time.September, 26, 12, 34, 56, 123456789, time.UTC),
		OrgID:         "org-456",
		Sections:      sections,
		Integrity: supportBundleIntegrityDTO{
			Algorithm: "sha256",
			Scope:     "sections",
			SHA256:    sum,
		},
	}
}

func testSupportBundleSigningKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "support-bundle-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(supportBundleSigningKeyEnv, path)
	return publicKey
}

func TestSupportBundleUnsignedIntegrity(t *testing.T) {
	previous, configured := os.LookupEnv(supportBundleSigningKeyEnv)
	if err := os.Unsetenv(supportBundleSigningKeyEnv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if configured {
			_ = os.Setenv(supportBundleSigningKeyEnv, previous)
		} else {
			_ = os.Unsetenv(supportBundleSigningKeyEnv)
		}
	})

	bundle := testSupportBundle(t, map[string]any{"environment": "safe"})
	if err := signSupportBundle(&bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Integrity.Signed || bundle.Integrity.Signature != "" || bundle.Integrity.PublicKey != "" || bundle.Integrity.KeyID != "" {
		t.Fatalf("unsigned bundle has signing metadata: %+v", bundle.Integrity)
	}
	if err := verifySupportBundleIntegrity(bundle); err != nil {
		t.Fatal(err)
	}
	bundle.Sections["environment"] = "changed"
	if err := verifySupportBundleIntegrity(bundle); err == nil {
		t.Fatal("tampered unsigned sections verified")
	}
}

func TestSupportBundleEd25519Signature(t *testing.T) {
	publicKey := testSupportBundleSigningKey(t)
	bundle := testSupportBundle(t, map[string]any{"environment": "safe"})
	if err := signSupportBundle(&bundle); err != nil {
		t.Fatal(err)
	}
	if !bundle.Integrity.Signed || bundle.Integrity.SignatureAlgorithm != "ed25519" {
		t.Fatalf("missing signature metadata: %+v", bundle.Integrity)
	}
	keyHash := sha256.Sum256(publicKey)
	if bundle.Integrity.PublicKey != base64.StdEncoding.EncodeToString(publicKey) || bundle.Integrity.KeyID != hex.EncodeToString(keyHash[:]) {
		t.Fatal("public key identity mismatch")
	}
	expectedPayload := "constellation.support_bundle.signature.v1\nconstellation.support_bundle.v1\nbundle-123\n2026-09-26T12:34:56.123456789Z\norg-456\n" + bundle.Integrity.SHA256
	if string(supportBundleSignaturePayload(bundle)) != expectedPayload {
		t.Fatalf("unexpected signing payload: %q", supportBundleSignaturePayload(bundle))
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Integrity.Signature)
	if err != nil || !ed25519.Verify(publicKey, []byte(expectedPayload), signature) {
		t.Fatal("signature does not cover the specified payload")
	}
	if err := verifySupportBundleIntegrity(bundle); err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*supportBundleDTO){
		"sections":       func(value *supportBundleDTO) { value.Sections["environment"] = "changed" },
		"sections hash":  func(value *supportBundleDTO) { value.Integrity.SHA256 = strings.Repeat("0", 64) },
		"schema version": func(value *supportBundleDTO) { value.SchemaVersion = "other" },
		"bundle id":      func(value *supportBundleDTO) { value.BundleID = "other" },
		"generated at":   func(value *supportBundleDTO) { value.GeneratedAt = value.GeneratedAt.Add(time.Second) },
		"org id":         func(value *supportBundleDTO) { value.OrgID = "other" },
		"signature": func(value *supportBundleDTO) {
			value.Integrity.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
		"public key": func(value *supportBundleDTO) {
			value.Integrity.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
		},
		"key id":              func(value *supportBundleDTO) { value.Integrity.KeyID = strings.Repeat("0", 64) },
		"signature algorithm": func(value *supportBundleDTO) { value.Integrity.SignatureAlgorithm = "other" },
		"signed flag":         func(value *supportBundleDTO) { value.Integrity.Signed = false },
		"hash algorithm":      func(value *supportBundleDTO) { value.Integrity.Algorithm = "other" },
		"hash scope":          func(value *supportBundleDTO) { value.Integrity.Scope = "other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copy := bundle
			copy.Sections = map[string]any{"environment": "safe"}
			mutate(&copy)
			if err := verifySupportBundleIntegrity(copy); err == nil {
				t.Fatal("tampered bundle verified")
			}
		})
	}
}

func TestSupportBundleSigningRejectsInvalidKeys(t *testing.T) {
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		"malformed PEM":  []byte("not a key"),
		"wrong PEM type": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}),
		"invalid PKCS8":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}),
		"wrong key type": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret-key.pem")
			if err := os.WriteFile(path, contents, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(supportBundleSigningKeyEnv, path)
			bundle := testSupportBundle(t, map[string]any{"environment": "safe"})
			if err := signSupportBundle(&bundle); err == nil || strings.Contains(err.Error(), path) {
				t.Fatalf("invalid key error leaked path or was accepted: %v", err)
			}
			if bundle.Integrity.Signed || bundle.Integrity.Signature != "" {
				t.Fatal("invalid key partially signed bundle")
			}
		})
	}
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing-key.pem")} {
		t.Run("unreadable-"+path, func(t *testing.T) {
			t.Setenv(supportBundleSigningKeyEnv, path)
			bundle := testSupportBundle(t, map[string]any{"environment": "safe"})
			if err := signSupportBundle(&bundle); err == nil || strings.Contains(err.Error(), path) && path != "" {
				t.Fatalf("unreadable key error leaked path or was accepted: %v", err)
			}
			if bundle.Integrity.Signed {
				t.Fatal("unreadable key partially signed bundle")
			}
		})
	}
}

func TestSupportBundleRedactsBeforeSigning(t *testing.T) {
	testSupportBundleSigningKey(t)
	bundle, err := newSupportBundle("org-456", time.Now().UTC(), map[string]any{
		"system_config": map[string]any{"api_token": "raw-secret", "enabled": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "raw-secret") || !strings.Contains(string(encoded), supportBundleRedacted) {
		t.Fatalf("redaction before signing failed: %s", encoded)
	}
	if !bundle.Integrity.Signed {
		t.Fatal("bundle was not signed")
	}
	if err := verifySupportBundleIntegrity(bundle); err != nil {
		t.Fatal(err)
	}
}

func TestSupportBundleDownloadFailsClosedOnInvalidSigningKey(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	path := filepath.Join(t.TempDir(), "missing-key.pem")
	t.Setenv(supportBundleSigningKeyEnv, path)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/support/bundle", nil)
	request = request.WithContext(WithSubject(context.Background(), Subject{UserID: uuid.New(), OrgID: uuid.New()}))
	response := httptest.NewRecorder()
	NewSupportBundle(database, nil).Download(response, request)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), path) || strings.Contains(response.Body.String(), "PRIVATE KEY") {
		t.Fatalf("invalid key response: status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Disposition") != "" || strings.Contains(response.Body.String(), `"sections"`) {
		t.Fatal("invalid signing key returned a downloadable bundle")
	}
}
