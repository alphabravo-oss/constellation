package registry

// Small in-process token cache shared by the cloud-native registry connectors
// (GCP / Azure / ECR). Cloud registries hand out short-lived (~1h–12h) tokens, so a
// scheduled scan cadence must re-mint them before they expire. Rather than thread a
// registry id through every connector, entries are keyed by a stable fingerprint of
// the identifying credentials (see tokenCacheKey), so a freshly-built connector for
// the same registry reuses the cached token until it nears expiry.

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// tokenRefreshLead is how long before a token's expiry we treat it as stale and
// re-mint. Cloud clock-skew + request latency make a couple of minutes of headroom
// prudent so an in-flight scan never presents an expired token.
const tokenRefreshLead = 2 * time.Minute

type cachedToken struct {
	token  string
	expiry time.Time
}

var (
	tokenCacheMu sync.Mutex
	tokenCache   = map[string]cachedToken{}
)

// tokenCacheGet returns a cached token when one exists and is not within
// tokenRefreshLead of its expiry.
func tokenCacheGet(key string) (string, bool) {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	ent, ok := tokenCache[key]
	if !ok {
		return "", false
	}
	if !ent.expiry.IsZero() && time.Now().Add(tokenRefreshLead).After(ent.expiry) {
		delete(tokenCache, key)
		return "", false
	}
	return ent.token, true
}

// tokenCachePut stores a freshly-minted token with its absolute expiry time.
func tokenCachePut(key, token string, expiry time.Time) {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	tokenCache[key] = cachedToken{token: token, expiry: expiry}
}

// tokenCacheKey builds a stable, non-reversible cache key from the identifying
// parts of a credential set (never the secret material itself in the clear).
func tokenCacheKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
