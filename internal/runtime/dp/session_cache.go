// Wave C1: session-cache + periodic poller.
//
// dp's DPMsgConnect aggregates traffic into per-(EPMAC, 5-tuple, policy_id)
// buckets with a SINGLE byte counter (client+server summed). To surface the
// per-direction split the UI wants (client_bytes vs server_bytes), we
// periodically ask dp for its raw per-session table via ctrl_list_session
// and remember the last-observed wing-split for each 5-tuple.
//
// The cache lives on the Supervisor — public via Supervisor.SessionForFlow()
// so cmd/constellation-runtime-agent/dp_flow.go can look up the matching
// session right before emitting the row to /network-flows:bulk.
//
// Cache lifetime: each ctrl_list_session response replaces the cache
// wholesale (one map swap, no merge). Entries are intrinsically time-bound
// by dp's own session-eviction logic; we don't TTL them on our side.
package dp

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// SessionCache stores the most recent DPMsgSession per 5-tuple. Safe for
// concurrent reads (Lookup) while writes (Replace) happen on the polling
// goroutine.
type SessionCache struct {
	mu      sync.RWMutex
	current map[SessionKey]*Session

	updates   atomic.Uint64
	sessions  atomic.Uint64
	lookups   atomic.Uint64
	lookupHit atomic.Uint64
}

// NewSessionCache returns an empty cache.
func NewSessionCache() *SessionCache {
	return &SessionCache{current: map[SessionKey]*Session{}}
}

// Apply merges one batch of sessions (from one DPMsgSession datagram) into
// the cache. A single ctrl_list_session response may span multiple
// datagrams; this is per-datagram, so the cache accretes across them.
//
// Apply never evicts: a 5-tuple that dp has since dropped lingers forever.
// Prefer assembling a full dump with SessionDumpAssembler and calling
// Replace so absent entries are evicted. Apply is retained for back-compat
// with callers that don't (yet) track end-of-dump.
func (c *SessionCache) Apply(sessions []*Session) {
	if len(sessions) == 0 {
		return
	}
	c.mu.Lock()
	for _, s := range sessions {
		c.current[s.Key()] = s
	}
	c.mu.Unlock()
	c.updates.Add(1)
	c.sessions.Add(uint64(len(sessions)))
}

// Replace atomically swaps the cache contents to exactly the provided
// snapshot. Entries absent from `sessions` are evicted — this is the fix
// for the cache accreting stale 5-tuples forever. The caller passes a full
// ctrl_list_session dump (see SessionDumpAssembler) once DPMsgHdr.More has
// gone false; the whole map is rebuilt and swapped in under the lock so
// readers never observe a partial dump.
func (c *SessionCache) Replace(sessions []*Session) {
	next := make(map[SessionKey]*Session, len(sessions))
	for _, s := range sessions {
		next[s.Key()] = s
	}
	c.mu.Lock()
	c.current = next
	c.mu.Unlock()
	c.updates.Add(1)
	c.sessions.Add(uint64(len(sessions)))
}

// SessionDumpAssembler reassembles one complete ctrl_list_session response
// from the sequence of DPMsgSession datagrams dp emits for it. dp sets
// DPMsgHdr.More=1 on every datagram of a dump except the last, which carries
// More=0. Feed each datagram's decoded sessions plus its More flag to Add;
// when Add reports the dump is complete, call Take for the full snapshot and
// hand it to SessionCache.Replace.
//
// Not safe for concurrent use — drive it from a single reader goroutine.
type SessionDumpAssembler struct {
	acc []*Session
}

// Add appends one datagram's sessions to the in-progress dump and reports
// whether the dump is now complete (more == false). `more` is the datagram's
// DPMsgHdr.More flag (hdr.More != 0).
func (a *SessionDumpAssembler) Add(sessions []*Session, more bool) (complete bool) {
	a.acc = append(a.acc, sessions...)
	return !more
}

// Take returns the accumulated dump and resets the assembler for the next
// one. Call it once Add has reported complete.
func (a *SessionDumpAssembler) Take() []*Session {
	out := a.acc
	a.acc = nil
	return out
}

// Lookup returns the most recent session matching the 5-tuple. Returns
// (nil, false) if no match — the caller falls back to the legacy
// "total in client_bytes" behavior.
func (c *SessionCache) Lookup(k SessionKey) (*Session, bool) {
	c.lookups.Add(1)
	c.mu.RLock()
	s, ok := c.current[k]
	c.mu.RUnlock()
	if ok {
		c.lookupHit.Add(1)
	}
	return s, ok
}

// Size returns the current cache count. For metrics.
func (c *SessionCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.current)
}

// SessionCacheStats — for the heartbeat / metrics endpoint.
type SessionCacheStats struct {
	Size       int
	Updates    uint64
	Sessions   uint64
	Lookups    uint64
	LookupHits uint64
}

func (c *SessionCache) Snapshot() SessionCacheStats {
	return SessionCacheStats{
		Size:       c.Size(),
		Updates:    c.updates.Load(),
		Sessions:   c.sessions.Load(),
		Lookups:    c.lookups.Load(),
		LookupHits: c.lookupHit.Load(),
	}
}

// runSessionPoller drives the periodic ctrl_list_session request. Started
// by Supervisor.Start when SessionPollInterval > 0. Default 30s — bumps
// the dp request channel modestly (one JSON write per interval) and the
// notification channel proportional to session count.
//
// The session cache uses Replace semantics: each tick swaps the cache for
// a fresh build assembled from the EventSession events that arrive after
// the request. This requires the poller to know when "all the response
// datagrams have arrived". We use a simple rule: the next tick happens
// after `interval`, and on each tick we replace the cache with whatever
// sessions arrived in the previous interval. Stale entries decay one tick
// later (≤ 30s by default).
func runSessionPoller(ctx context.Context, logger *slog.Logger, client *dpClient, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	// First fire immediately so the cache populates quickly after startup.
	if err := client.ListSessions(); err != nil {
		logger.Debug("dp session poll: initial request failed", slog.String("err", err.Error()))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := client.ListSessions(); err != nil {
				logger.Debug("dp session poll: request failed", slog.String("err", err.Error()))
			}
		}
	}
}
