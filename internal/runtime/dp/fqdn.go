// Task F1b: native datapath FQDN resolver.
//
// Constellation enforces FQDN-anchored egress in its own data-plane (the
// NFQUEUE path), complementary to the Cilium toFQDNs generator (F1a). dp's
// policy engine matches packets by IP, so an FQDN rule is only useful if the
// kernel knows which IPs that name currently resolves to. This resolver is the
// userspace half of that contract:
//
//	DNS responses  ─▶  FqdnResolver.Observe  ─▶  KindIPFqdnStorageUpdate ─▶ dp
//	TTL expiry     ─▶  FqdnResolver.Expire   ─▶  KindIPFqdnStorageRelease ─▶ dp
//
// The DNS responses are snooped in userspace by the L7 engine
// (internal/runtime/dpi/dns.go), which now decodes the answer section. We only
// learn IPs for names that appear in the policy's allow-set (exact or wildcard
// match) — an unrelated lookup never reaches dp's storage table.
//
// Mirrors NeuVector's IP↔FQDN storage notifications (defs.h
// DPMsgIpFqdnStorageUpdateHdr / DPMsgIpFqdnStorageReleaseHdr,
// agent/dp/dp.go dpMsgIpFqdnStorage*), except the snoop/derive happens in Go
// rather than in dp.
package dp

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// fqdnNameMaxLen mirrors DP_POLICY_FQDN_NAME_MAX_LEN (defs.h:220) — the fixed
// width of the Name char[] in the storage-update wire message.
const fqdnNameMaxLen = 256

// defaultMaxFqdnEntries bounds the number of distinct resolved names the
// resolver tracks. A wildcard allow (eg. "*.example.com") matches unboundedly
// many attacker-generated subdomains; without a cap each one would create an
// entry and grow memory without bound (DoS). When the cap is hit the
// soonest-expiring entry is evicted (and its IPs released). Mirrors the bounded
// FQDN IP storage NeuVector keeps.
const defaultMaxFqdnEntries = 4096

// defaultMaxIPsPerName bounds the live IP set for a single name, so a single
// name resolving to a churning/poisoned answer set cannot grow without bound.
const defaultMaxIPsPerName = 64

// ResolvedIP is one A/AAAA answer fed to the resolver: the IP and its TTL.
type ResolvedIP struct {
	IP  net.IP
	TTL uint32 // seconds; 0 → treated as immediately stale on the next Expire
}

// IPFqdnStorageMsg is one emitted IP↔FQDN storage notification. Kind is either
// KindIPFqdnStorageUpdate (learn IP→Fqdn) or KindIPFqdnStorageRelease (forget
// IP). Fqdn is set on updates and empty on releases. Encode renders the dp
// wire form.
type IPFqdnStorageMsg struct {
	Kind uint8
	IP   net.IP
	Fqdn string
}

// Encode renders the message in dp's binary notification format:
//
//	DPMsgHdr{Kind, More=0, Length} ++ body
//
//	update:  IP[16] ++ Name[fqdnNameMaxLen]   (DPMsgIpFqdnStorageUpdateHdr)
//	release: IP[16]                            (DPMsgIpFqdnStorageReleaseHdr)
//
// Length is the total datagram size (header included), big-endian, matching
// decodeHdr's expectation.
func (m IPFqdnStorageMsg) Encode() []byte {
	bodyLen := 16
	if m.Kind == KindIPFqdnStorageUpdate {
		bodyLen += fqdnNameMaxLen
	}
	buf := make([]byte, dpMsgHdrSize+bodyLen)
	buf[0] = m.Kind
	buf[1] = 0 // More
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	copy(buf[dpMsgHdrSize:dpMsgHdrSize+16], to16(m.IP))
	if m.Kind == KindIPFqdnStorageUpdate {
		name := m.Fqdn
		if len(name) >= fqdnNameMaxLen {
			name = name[:fqdnNameMaxLen-1] // leave room for the NUL terminator
		}
		copy(buf[dpMsgHdrSize+16:], name)
	}
	return buf
}

// to16 normalizes an IP into the 16-byte IP field of the storage-update wire
// struct. Mirrors NeuVector's ip4_cpy(fh->IP, ...) (dp/ctrl.c:2963): IPv4 lands
// in the first 4 bytes with the remainder zero-padded; IPv6 fills all 16.
func to16(ip net.IP) []byte {
	out := make([]byte, 16)
	if v4 := ip.To4(); v4 != nil {
		copy(out, v4)
		return out
	}
	if v16 := ip.To16(); v16 != nil {
		copy(out, v16)
	}
	return out
}

// fqdnEntry tracks the live IP set for one resolved name. ips maps the IP's
// canonical string form to its expiry instant.
type fqdnEntry struct {
	ips map[string]ipState
}

// soonestExpiry returns the earliest expiry instant among the entry's IPs, or
// the zero time for an empty entry (treated as immediately evictable).
func (e *fqdnEntry) soonestExpiry() time.Time {
	var out time.Time
	first := true
	for _, st := range e.ips {
		if first || st.expiry.Before(out) {
			out, first = st.expiry, false
		}
	}
	return out
}

type ipState struct {
	ip     net.IP
	expiry time.Time
}

// FqdnResolver maintains the FQDN→IP table for FQDN-anchored datapath rules.
//
// It is pure and concurrency-safe: feed DNS answers via Observe, drive TTL
// eviction via Expire, and consume the returned storage messages. No I/O —
// the caller (the agent's dp wiring) pushes the messages to dp. Tests assert
// on the table (Lookup) and the emitted messages directly.
type FqdnResolver struct {
	mu      sync.Mutex
	allowed []string              // allow-set patterns (exact + wildcard)
	entries map[string]*fqdnEntry // resolved-name → live IP set
	// ipRefs counts, per canonical IP string, how many entries currently hold
	// that IP. An IP is only released to dp when its last holder drops it —
	// two allowed names that share a CDN IP must not release each other's IP.
	ipRefs        map[string]int
	maxEntries    int
	maxIPsPerName int
}

// NewFqdnResolver builds a resolver whose allow-set is `allowed`. Each pattern
// is an exact FQDN ("api.github.com") or a glob containing '*'
// ("*.s3.amazonaws.com"). Names are matched case-insensitively and a trailing
// dot is ignored.
func NewFqdnResolver(allowed ...string) *FqdnResolver {
	r := &FqdnResolver{
		entries:       map[string]*fqdnEntry{},
		ipRefs:        map[string]int{},
		maxEntries:    defaultMaxFqdnEntries,
		maxIPsPerName: defaultMaxIPsPerName,
	}
	r.SetAllowed(allowed)
	return r
}

// SetAllowed replaces the allow-set and returns the release messages for every
// IP that becomes orphaned because its name no longer matches any pattern.
// De-authorizing an FQDN must not leave its learned IPs reachable in dp until
// their TTL elapses, so entries that no longer match are evicted immediately.
func (r *FqdnResolver) SetAllowed(allowed []string) []IPFqdnStorageMsg {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowed = make([]string, 0, len(allowed))
	for _, a := range allowed {
		if a = normalizeFqdn(a); a != "" {
			r.allowed = append(r.allowed, a)
		}
	}
	// Drop any learned entry whose name no longer matches the new allow-set,
	// releasing its IPs (reference-counted).
	var msgs []IPFqdnStorageMsg
	for name, ent := range r.entries {
		if r.allowedLocked(name) {
			continue
		}
		for key, st := range ent.ips {
			if r.releaseIPLocked(key) {
				msgs = append(msgs, IPFqdnStorageMsg{Kind: KindIPFqdnStorageRelease, IP: st.ip})
			}
			delete(ent.ips, key)
		}
		delete(r.entries, name)
	}
	sortMsgs(msgs)
	return msgs
}

// Allowed reports whether `name` matches any allow-set pattern.
func (r *FqdnResolver) Allowed(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allowedLocked(name)
}

func (r *FqdnResolver) allowedLocked(name string) bool {
	name = normalizeFqdn(name)
	for _, pat := range r.allowed {
		if matchFqdn(pat, name) {
			return true
		}
	}
	return false
}

// Observe records the IPs `name` resolved to. It returns one
// KindIPFqdnStorageUpdate per IP when `name` is in the allow-set, so dp learns
// (or refreshes) the IP→FQDN mapping; a non-allowed name yields nil and is
// never stored. Re-observing a known IP refreshes its TTL and re-emits an
// update (an idempotent refresh dp tolerates).
func (r *FqdnResolver) Observe(name string, ips []ResolvedIP, now time.Time) []IPFqdnStorageMsg {
	r.mu.Lock()
	defer r.mu.Unlock()

	name = normalizeFqdn(name)
	if name == "" || !r.allowedLocked(name) {
		return nil
	}
	var msgs []IPFqdnStorageMsg
	ent := r.entries[name]
	if ent == nil {
		// New name: enforce the table cap before inserting so a wildcard zone
		// cannot grow entries without bound.
		msgs = append(msgs, r.evictForCapacityLocked()...)
		ent = &fqdnEntry{ips: map[string]ipState{}}
		r.entries[name] = ent
	}
	for _, ri := range ips {
		if ri.IP == nil {
			continue
		}
		ip := dupIP(ri.IP)
		key := ip.String()
		if _, known := ent.ips[key]; !known {
			// New IP for this name: bound the per-name IP set, then take a
			// reference so cross-name sharing is tracked.
			msgs = append(msgs, r.evictIPForCapacityLocked(ent)...)
			r.ipRefs[key]++
		}
		ent.ips[key] = ipState{ip: ip, expiry: now.Add(time.Duration(ri.TTL) * time.Second)}
		msgs = append(msgs, IPFqdnStorageMsg{Kind: KindIPFqdnStorageUpdate, IP: ip, Fqdn: name})
	}
	sortMsgs(msgs)
	return msgs
}

// evictForCapacityLocked drops the soonest-expiring entry when the table is at
// capacity, returning the releases for any IPs that lose their last holder.
func (r *FqdnResolver) evictForCapacityLocked() []IPFqdnStorageMsg {
	if r.maxEntries <= 0 || len(r.entries) < r.maxEntries {
		return nil
	}
	var victim string
	var victimExpiry time.Time
	for name, ent := range r.entries {
		exp := ent.soonestExpiry()
		if victim == "" || exp.Before(victimExpiry) {
			victim, victimExpiry = name, exp
		}
	}
	if victim == "" {
		return nil
	}
	ent := r.entries[victim]
	var msgs []IPFqdnStorageMsg
	for key, st := range ent.ips {
		if r.releaseIPLocked(key) {
			msgs = append(msgs, IPFqdnStorageMsg{Kind: KindIPFqdnStorageRelease, IP: st.ip})
		}
		delete(ent.ips, key)
	}
	delete(r.entries, victim)
	return msgs
}

// evictIPForCapacityLocked drops the soonest-expiring IP from `ent` when the
// per-name IP cap is reached, returning any release it triggers.
func (r *FqdnResolver) evictIPForCapacityLocked(ent *fqdnEntry) []IPFqdnStorageMsg {
	if r.maxIPsPerName <= 0 || len(ent.ips) < r.maxIPsPerName {
		return nil
	}
	var key string
	var exp time.Time
	for k, st := range ent.ips {
		if key == "" || st.expiry.Before(exp) {
			key, exp = k, st.expiry
		}
	}
	if key == "" {
		return nil
	}
	st := ent.ips[key]
	delete(ent.ips, key)
	if r.releaseIPLocked(key) {
		return []IPFqdnStorageMsg{{Kind: KindIPFqdnStorageRelease, IP: st.ip}}
	}
	return nil
}

// retainIPLocked / releaseIPLocked maintain the cross-name IP refcount.
// releaseIPLocked reports whether the IP's last reference was dropped (caller
// should emit a release to dp).
func (r *FqdnResolver) releaseIPLocked(key string) bool {
	if r.ipRefs[key] <= 1 {
		delete(r.ipRefs, key)
		return true
	}
	r.ipRefs[key]--
	return false
}

// Expire evicts every IP whose TTL has elapsed (expiry <= now) and returns one
// KindIPFqdnStorageRelease per evicted IP so dp forgets the stale mapping.
// Empty entries are dropped. Output is deterministic (sorted by IP).
func (r *FqdnResolver) Expire(now time.Time) []IPFqdnStorageMsg {
	r.mu.Lock()
	defer r.mu.Unlock()

	var msgs []IPFqdnStorageMsg
	for name, ent := range r.entries {
		for key, st := range ent.ips {
			if !st.expiry.After(now) {
				delete(ent.ips, key)
				// Only release when no other allowed name still holds this IP —
				// a shared CDN IP must survive until its last holder expires.
				if r.releaseIPLocked(key) {
					msgs = append(msgs, IPFqdnStorageMsg{Kind: KindIPFqdnStorageRelease, IP: st.ip})
				}
			}
		}
		if len(ent.ips) == 0 {
			delete(r.entries, name)
		}
	}
	sortMsgs(msgs)
	return msgs
}

// Lookup returns the currently-live IPs for `name`, sorted, for inspection and
// tests. Expired-but-not-yet-evicted IPs are still included (call Expire first
// to prune).
func (r *FqdnResolver) Lookup(name string) []net.IP {
	r.mu.Lock()
	defer r.mu.Unlock()
	ent := r.entries[normalizeFqdn(name)]
	if ent == nil {
		return nil
	}
	out := make([]net.IP, 0, len(ent.ips))
	for _, st := range ent.ips {
		out = append(out, st.ip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Snapshot returns a copy of the current name→live-IP table. The dp wiring
// diffs successive snapshots to decide which `ctrl_cfg_set_fqdn` pushes to send
// (NeuVector programs dp with the full IP set per name, not per-IP deltas).
func (r *FqdnResolver) Snapshot() map[string][]net.IP {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][]net.IP, len(r.entries))
	for name, ent := range r.entries {
		ips := make([]net.IP, 0, len(ent.ips))
		for _, st := range ent.ips {
			ips = append(ips, st.ip)
		}
		sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
		out[name] = ips
	}
	return out
}

// Reset drops all learned entries (but keeps the allow-set).
func (r *FqdnResolver) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = map[string]*fqdnEntry{}
	r.ipRefs = map[string]int{}
}

// sortMsgs orders messages by IP then Fqdn for deterministic output.
func sortMsgs(msgs []IPFqdnStorageMsg) {
	sort.Slice(msgs, func(i, j int) bool {
		if a, b := msgs[i].IP.String(), msgs[j].IP.String(); a != b {
			return a < b
		}
		return msgs[i].Fqdn < msgs[j].Fqdn
	})
}

func dupIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

// normalizeFqdn lowercases and strips a single trailing dot. DNS names are
// case-insensitive and the root form may carry a trailing dot.
func normalizeFqdn(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.TrimSuffix(name, ".")
}

// matchFqdn reports whether `name` matches `pattern`. A pattern without '*' is
// an exact match. A pattern with '*' is a glob: '*' matches any run of
// characters. Both inputs are assumed already normalized. The common
// "*.example.com" case requires at least one label before the suffix (the
// leading "*." consumes ≥1 char), matching Cilium toFQDNs matchPattern intent.
func matchFqdn(pattern, name string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	return globMatch(pattern, name)
}

// globMatch is a minimal '*'-only glob: the pattern is split on '*' and each
// literal segment must appear in order, anchored at the ends. A leading "*."
// additionally requires a non-empty prefix so "*.s3.amazonaws.com" does not
// match the bare "s3.amazonaws.com".
func globMatch(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	// Anchor the first segment to the start.
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	pos := len(parts[0])
	// "*.suffix": the wildcard must consume ≥1 char (a real label/prefix).
	if strings.HasPrefix(pattern, "*.") && pos == 0 {
		// First non-empty literal after the leading wildcard is parts[1].
		idx := strings.Index(name, parts[1])
		if idx <= 0 {
			return false
		}
	}
	last := len(parts) - 1
	for i := 1; i < last; i++ {
		seg := parts[i]
		if seg == "" {
			continue
		}
		idx := strings.Index(name[pos:], seg)
		if idx < 0 {
			return false
		}
		pos += idx + len(seg)
	}
	// Anchor the final segment to the end.
	return strings.HasSuffix(name[pos:], parts[last])
}
