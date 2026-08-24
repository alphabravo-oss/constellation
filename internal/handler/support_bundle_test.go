package handler

import (
	"encoding/json"
	"strings"
	"testing"
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
