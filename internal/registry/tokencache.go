package registry

// The shared cloud token cache is bounded and keyed by trusted owner scope plus
// effective credential fingerprints. No raw credential appears in a map key.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"
)

const (
	tokenRefreshLead   = 2 * time.Minute
	tokenCacheMaxItems = 256
	tokenCacheMaxBytes = 8 << 20
)

type cachedToken struct {
	token  string
	expiry time.Time
}

var (
	tokenCacheMu sync.Mutex
	tokenCache   = map[string]cachedToken{}
)

func tokenCacheGet(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	entry, ok := tokenCache[key]
	if !ok {
		return "", false
	}
	if !time.Now().Add(tokenRefreshLead).Before(entry.expiry) {
		delete(tokenCache, key)
		return "", false
	}
	return entry.token, true
}

func tokenCachePut(key, token string, expiry time.Time) {
	cost := len(key) + len(token)
	now := time.Now().Add(tokenRefreshLead)
	if key == "" || cost > tokenCacheMaxBytes || !now.Before(expiry) {
		return
	}
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	bytes := 0
	for existing, entry := range tokenCache {
		if !now.Before(entry.expiry) || existing == key {
			delete(tokenCache, existing)
			continue
		}
		bytes += len(existing) + len(entry.token)
	}
	for len(tokenCache) >= tokenCacheMaxItems || bytes+cost > tokenCacheMaxBytes {
		oldest := oldestTokenCacheKey()
		bytes -= len(oldest) + len(tokenCache[oldest].token)
		delete(tokenCache, oldest)
	}
	tokenCache[key] = cachedToken{token: token, expiry: expiry}
}

// oldestTokenCacheKey requires tokenCacheMu. Ties are deterministic, without
// retaining insertion metadata or exposing credential-derived keys in logs.
func oldestTokenCacheKey() string {
	oldest := ""
	for key, entry := range tokenCache {
		if oldest == "" || entry.expiry.Before(tokenCache[oldest].expiry) ||
			(entry.expiry.Equal(tokenCache[oldest].expiry) && key < oldest) {
			oldest = key
		}
	}
	return oldest
}

func (cfg Config) credentialCacheKey(kind string, parts ...string) string {
	if cfg.CredentialCacheScope == "" {
		return ""
	}
	identity := []string{"registry-credentials-v2", cfg.CredentialCacheScope, kind, cfg.AuthKind}
	return tokenCacheKey(append(identity, parts...)...)
}

// Length-prefix each component: embedded NULs or delimiter-like values cannot
// alias a different credential tuple. Only the SHA256 result leaves this helper.
func tokenCacheKey(parts ...string) string {
	hash := sha256.New()
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
