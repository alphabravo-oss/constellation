// Package jwks is a minimal JWKS cache for golang-jwt/jwt/v5. Keys are fetched once, refreshed
// in the background when older than MaxAge, and refetched on an unknown kid. All fetches are
// rate-limited by MinGap. A failed refresh keeps the last good keys, so already-issued tokens keep
// validating while the IdP is down.
package jwks

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type Cache struct {
	URL    string
	Client *http.Client
	MaxAge time.Duration // periodic refresh (budget: 15m)
	MinGap time.Duration // minimum time between network fetches

	keys       atomic.Pointer[map[string]crypto.PublicKey]
	fetched    atomic.Int64 // unix nanos of last successful fetch
	refreshing atomic.Bool
	mu         sync.Mutex // serializes fetches
	lastTry    time.Time
	Fetches    atomic.Int64 // successful network fetches (metrics/tests)
}

func New(url string, c *http.Client) *Cache {
	return &Cache{URL: url, Client: c, MaxAge: 15 * time.Minute, MinGap: 10 * time.Second}
}

// Keyfunc resolves the token's kid. Hot path: two atomic loads and a map lookup.
func (c *Cache) Keyfunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if k, ok := c.lookup(kid); ok {
		if time.Since(time.Unix(0, c.fetched.Load())) > c.MaxAge && c.refreshing.CompareAndSwap(false, true) {
			go func() { defer c.refreshing.Store(false); _ = c.Refresh(context.Background()) }()
		}
		return k, nil
	}
	// Rotation never blocks a request on the network. Retry after background refresh.
	if c.refreshing.CompareAndSwap(false, true) {
		go func() { defer c.refreshing.Store(false); _ = c.Refresh(context.Background()) }()
	}
	return nil, fmt.Errorf("jwks: unknown kid %q", kid)
}

func (c *Cache) lookup(kid string) (crypto.PublicKey, bool) {
	if m := c.keys.Load(); m != nil {
		k, ok := (*m)[kid]
		return k, ok
	}
	return nil, false
}

// Refresh fetches the key set unless a fetch happened within MinGap.
func (c *Cache) Refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.lastTry) < c.MinGap {
		return fmt.Errorf("jwks: fetch rate-limited")
	}
	c.lastTry = time.Now()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return err
	}
	res, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: status %d", res.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&set); err != nil {
		return err
	}
	m := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.KeyID != "" && k.Valid() && k.IsPublic() && (k.Use == "" || k.Use == "sig") {
			m[k.KeyID] = k.Key
		}
	}
	if len(m) == 0 {
		return fmt.Errorf("jwks: empty signing key set")
	}
	c.keys.Store(&m)
	c.fetched.Store(time.Now().UnixNano())
	c.Fetches.Add(1)
	return nil
}
