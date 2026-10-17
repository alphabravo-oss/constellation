package registry

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func isolateTokenCache(t *testing.T) {
	t.Helper()
	tokenCacheMu.Lock()
	previous := tokenCache
	tokenCache = map[string]cachedToken{}
	tokenCacheMu.Unlock()
	t.Cleanup(func() {
		tokenCacheMu.Lock()
		tokenCache = previous
		tokenCacheMu.Unlock()
	})
}

func TestCredentialCacheKeyHasUnambiguousPrivateEncoding(t *testing.T) {
	left := tokenCacheKey("a\x00b", "c")
	right := tokenCacheKey("a", "b\x00c")
	if left == right || len(left) != 64 || len(right) != 64 {
		t.Fatal("different credential tuples alias a cache identity")
	}
	cfg := Config{CredentialCacheScope: ownedCredentialScope(t)}
	key := cfg.credentialCacheKey("owned-kind", "owned-secret-sentinel")
	if len(key) != 64 || strings.Contains(key, "owned-secret-sentinel") {
		t.Fatal("cache key exposes credential material")
	}
	if (Config{}).credentialCacheKey("owned-kind", "owned-secret-sentinel") != "" {
		t.Fatal("missing trusted scope established a cache identity")
	}
}

func TestCredentialCacheScopeCannotBeLoadedFromJSON(t *testing.T) {
	var cfg Config
	if err := json.Unmarshal([]byte(`{"CredentialCacheScope":"untrusted-scope","credential_cache_scope":"untrusted-scope"}`), &cfg); err != nil {
		t.Fatal("owned JSON fixture failed")
	}
	if cfg.CredentialCacheScope != "" {
		t.Fatal("untrusted JSON assigned owner cache scope")
	}

}

func TestTokenCacheRejectsUnknownExpiredAndOversizeEntries(t *testing.T) {
	isolateTokenCache(t)
	future := time.Now().Add(time.Hour)
	tokenCachePut("", "owned-value", future)
	tokenCachePut("expired", "owned-value", time.Now().Add(-time.Second))
	tokenCachePut("unknown-expiry", "owned-value", time.Time{})
	tokenCachePut("oversize", strings.Repeat("x", tokenCacheMaxBytes+1), future)
	for _, key := range []string{"", "expired", "unknown-expiry", "oversize"} {
		if _, ok := tokenCacheGet(key); ok {
			t.Fatal("unsafe token entry was retained")
		}
	}
	tokenCacheMu.Lock()
	count := len(tokenCache)
	tokenCacheMu.Unlock()
	if count != 0 {
		t.Fatal("rejected entries consumed global cache capacity")
	}
}

func TestTokenCachePrunesUnreachableExpiredRotationEntries(t *testing.T) {
	isolateTokenCache(t)
	tokenCacheMu.Lock()
	tokenCache["unreachable-old-credential"] = cachedToken{token: "owned-old-value", expiry: time.Now().Add(-time.Second)}
	tokenCacheMu.Unlock()
	tokenCachePut("new-credential", "owned-new-value", time.Now().Add(time.Hour))
	tokenCacheMu.Lock()
	_, retained := tokenCache["unreachable-old-credential"]
	tokenCacheMu.Unlock()
	if retained {
		t.Fatal("insertion did not prune an unreachable expired credential")
	}
	if token, ok := tokenCacheGet("new-credential"); !ok || token != "owned-new-value" {
		t.Fatal("fresh credential was not reusable")
	}
}

func TestTokenCacheRotationHasFiniteEntryAndByteBudgets(t *testing.T) {
	isolateTokenCache(t)
	future := time.Now().Add(time.Hour)
	for n := range tokenCacheMaxItems + 1 {
		tokenCachePut(fmt.Sprintf("owned-rotation-%d", n), "owned-value", future)
	}
	tokenCacheMu.Lock()
	count := len(tokenCache)
	tokenCacheMu.Unlock()
	if count > tokenCacheMaxItems {
		t.Fatal("credential rotation exceeded the entry budget")
	}
	for n := range 3 {
		tokenCachePut(fmt.Sprintf("owned-large-%d", n), strings.Repeat("x", tokenCacheMaxBytes/2), future)
	}
	tokenCacheMu.Lock()
	bytes := 0
	for key, entry := range tokenCache {
		bytes += len(key) + len(entry.token)
	}
	count = len(tokenCache)
	tokenCacheMu.Unlock()
	if bytes > tokenCacheMaxBytes || count > tokenCacheMaxItems {
		t.Fatal("credential rotation exceeded the byte or entry budget")
	}
}
