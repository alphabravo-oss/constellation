// Package livegraph is the optional in-memory conversation-graph cache (plan
// B5). It layers a hot, per-org aggregation of recent network flows on top of
// the existing Postgres-backed path:
//
//   - The flow-ingest handler calls Store.Publish for every accepted row, so
//     the cache is fed from the same pipeline that writes `network_flows`.
//   - GET /network/conversations can serve from this cache (sub-100ms, no SQL)
//     when CONSTELLATION_LIVEGRAPH is enabled; otherwise the Postgres query is
//     used unchanged. The Postgres path remains the durable source of truth.
//   - GET /network/flows:stream subscribes to Publish events and emits them as
//     Server-Sent Events so the network map can live-update.
//
// Entries are bounded two ways, mirroring NeuVector's bounded in-memory graph:
// a per-org TTL (old observations are evicted on read) and a hard cap on the
// number of distinct edges retained per org.
package livegraph

import (
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/graph"
)

// Flow is one accepted observation handed to the cache by the ingest path. It
// is a deliberately small projection of handler.FlowIngestRow — just what the
// conversation graph and the SSE stream need.
type Flow struct {
	OrgID       uuid.UUID `json:"-"`
	ClusterID   uuid.UUID `json:"cluster_id"`
	SrcWorkload string    `json:"src_workload"`
	DstWorkload string    `json:"dst_workload"`
	Protocol    string    `json:"protocol"`
	Port        int       `json:"port"`
	L7          string    `json:"l7,omitempty"`
	Verdict     string    `json:"verdict,omitempty"`
	Severity    int       `json:"severity,omitempty"`
	Bytes       int64     `json:"bytes,omitempty"`
	Packets     int64     `json:"packets,omitempty"`
	At          time.Time `json:"at"`
}

// Config tunes the eviction bounds. Zero values fall back to defaults.
type Config struct {
	TTL           time.Duration // observations older than now-TTL are dropped on read
	MaxEdgesPer   int           // hard cap on distinct edges retained per org
	SubscriberBuf int           // per-subscriber channel buffer
}

func (c Config) withDefaults() Config {
	if c.TTL <= 0 {
		c.TTL = time.Hour
	}
	if c.MaxEdgesPer <= 0 {
		c.MaxEdgesPer = 20000
	}
	if c.SubscriberBuf <= 0 {
		c.SubscriberBuf = 256
	}
	return c
}

// observation is a retained edge with its accumulated attributes.
type observation struct {
	clusterID uuid.UUID
	src, dst  string
	proto     string
	port      int
	l7        string
	verdict   string
	severity  int
	bytes     int64
	packets   int64
	lastSeen  time.Time
}

type obsKey struct {
	cluster  uuid.UUID
	src, dst string
	proto    string
	port     int
}

// Store holds the per-org hot graph plus the SSE fan-out. Safe for concurrent
// use.
type Store struct {
	cfg Config

	mu   sync.Mutex
	orgs map[uuid.UUID]map[obsKey]*observation

	subMu sync.Mutex
	subs  map[uuid.UUID]map[int]chan Flow
	nextS int
}

// New returns an empty store.
func New(cfg Config) *Store {
	return &Store{
		cfg:  cfg.withDefaults(),
		orgs: map[uuid.UUID]map[obsKey]*observation{},
		subs: map[uuid.UUID]map[int]chan Flow{},
	}
}

// Publish records an accepted flow into the org's hot graph and fans it out to
// any live SSE subscribers. Called from the ingest path; never blocks on a
// slow subscriber (a full channel drops the event for that subscriber only).
func (s *Store) Publish(f Flow) {
	if s == nil || f.OrgID == uuid.Nil {
		return
	}
	if f.At.IsZero() {
		f.At = time.Now().UTC()
	}
	s.record(f)
	s.fanout(f)
}

func (s *Store) record(f Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.orgs[f.OrgID]
	if org == nil {
		org = map[obsKey]*observation{}
		s.orgs[f.OrgID] = org
	}
	k := obsKey{cluster: f.ClusterID, src: f.SrcWorkload, dst: f.DstWorkload, proto: f.Protocol, port: f.Port}
	o, ok := org[k]
	if !ok {
		// Hard cap: when full, evict the oldest entry before inserting so the
		// map stays bounded even if nothing has aged past the TTL yet.
		if len(org) >= s.cfg.MaxEdgesPer {
			s.evictOldestLocked(org)
		}
		o = &observation{clusterID: f.ClusterID, src: f.SrcWorkload, dst: f.DstWorkload, proto: f.Protocol, port: f.Port}
		org[k] = o
	}
	o.bytes += f.Bytes
	o.packets += f.Packets
	if f.Severity > o.severity {
		o.severity = f.Severity
	}
	if worse(f.Verdict, o.verdict) {
		o.verdict = f.Verdict
	}
	if f.At.After(o.lastSeen) {
		o.lastSeen = f.At
		if f.L7 != "" {
			o.l7 = f.L7
		}
	}
}

func (s *Store) evictOldestLocked(org map[obsKey]*observation) {
	var oldestKey obsKey
	var oldest time.Time
	first := true
	for k, o := range org {
		if first || o.lastSeen.Before(oldest) {
			oldest, oldestKey, first = o.lastSeen, k, false
		}
	}
	if !first {
		delete(org, oldestKey)
	}
}

// Snapshot folds the org's live observations into a pkg/graph.Graph, dropping
// anything older than the TTL (and pruning those expired entries from the
// store as a side effect). clusterID, when non-nil, scopes to one cluster.
func (s *Store) Snapshot(orgID uuid.UUID, clusterID *uuid.UUID) *graph.Graph {
	g := graph.New()
	cutoff := time.Now().Add(-s.cfg.TTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.orgs[orgID]
	for k, o := range org {
		if o.lastSeen.Before(cutoff) {
			delete(org, k)
			continue
		}
		if clusterID != nil && o.clusterID != *clusterID {
			continue
		}
		g.AddEdge(o.src, o.dst, graph.Attrs{
			Bytes: o.bytes, Packets: o.packets, Protocol: o.proto, Port: o.port,
			LastSeen: o.lastSeen, L7: o.l7, Verdict: o.verdict, Severity: o.severity,
		})
	}
	if len(org) == 0 {
		delete(s.orgs, orgID)
	}
	return g
}

// Subscribe registers an SSE subscriber for orgID. The returned channel
// receives every subsequent Publish for that org; cancel releases it. The
// channel is buffered and lossy under backpressure (a slow consumer drops
// events, it never stalls ingest).
func (s *Store) Subscribe(orgID uuid.UUID) (<-chan Flow, func()) {
	ch := make(chan Flow, s.cfg.SubscriberBuf)
	s.subMu.Lock()
	id := s.nextS
	s.nextS++
	m := s.subs[orgID]
	if m == nil {
		m = map[int]chan Flow{}
		s.subs[orgID] = m
	}
	m[id] = ch
	s.subMu.Unlock()
	return ch, func() {
		s.subMu.Lock()
		if m := s.subs[orgID]; m != nil {
			if c, ok := m[id]; ok {
				delete(m, id)
				close(c)
			}
			if len(m) == 0 {
				delete(s.subs, orgID)
			}
		}
		s.subMu.Unlock()
	}
}

func (s *Store) fanout(f Flow) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for _, ch := range s.subs[f.OrgID] {
		select {
		case ch <- f:
		default: // drop for this slow subscriber only
		}
	}
}

// worse reports whether candidate is a strictly more severe verdict than have.
func worse(candidate, have string) bool {
	return verdictRank(candidate) > verdictRank(have)
}

func verdictRank(v string) int {
	switch v {
	case "deny", "block":
		return 3
	case "violate", "alert":
		return 2
	case "allow":
		return 1
	}
	return 0
}

// SortFlows orders a flow slice newest-first (used by tests / debug dumps).
func SortFlows(fs []Flow) {
	sort.Slice(fs, func(i, j int) bool { return fs[i].At.After(fs[j].At) })
}
