package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseJWTKeysAcceptsBase64AndRawKeys(t *testing.T) {
	rawKey := strings.Repeat("r", 32)
	encodedKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))

	keys, err := parseJWTKeys(encodedKey + "," + rawKey)
	if err != nil {
		t.Fatalf("parseJWTKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if string(keys[0]) != strings.Repeat("b", 32) {
		t.Fatalf("first key did not base64-decode")
	}
	if string(keys[1]) != rawKey {
		t.Fatalf("second key did not preserve raw value")
	}
}

func TestParseJWTKeysRejectsShortKeys(t *testing.T) {
	if _, err := parseJWTKeys("short"); err == nil {
		t.Fatal("expected short JWT key rejection")
	}
}

func TestBuildJWTKeysRequiredRejectsEmpty(t *testing.T) {
	if _, err := buildJWTKeys("", true); err == nil {
		t.Fatal("expected required JWT key rejection")
	}
}

// A5: with no JWT_KEYS and not required, buildJWTKeys returns an empty set so
// server.New falls through to the DB-backed RS256 session keypair — it no longer
// mints an ephemeral HS256 key.
func TestBuildJWTKeysEmptyFallsThroughToDBKeys(t *testing.T) {
	keys, err := buildJWTKeys("", false)
	if err != nil {
		t.Fatalf("buildJWTKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected empty key set, got %d keys", len(keys))
	}
}

func TestAPIHeartbeatURLUsesListenPortAndOverride(t *testing.T) {
	if got := apiHeartbeatURL(":9090"); got != "http://127.0.0.1:9090" {
		t.Fatalf("url = %q", got)
	}
	if got := apiHeartbeatURL("0.0.0.0:9443"); got != "http://127.0.0.1:9443" {
		t.Fatalf("url = %q", got)
	}
	t.Setenv("CONSTELLATION_API_HEARTBEAT_URL", "http://api.internal:8080/")
	if got := apiHeartbeatURL(":9090"); got != "http://api.internal:8080" {
		t.Fatalf("override url = %q", got)
	}
}
