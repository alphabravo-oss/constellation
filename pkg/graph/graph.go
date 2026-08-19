// Package graph implements a directed multigraph backing the Service Conversation
// Graph view. Each edge carries link attributes (bytes, packets, protocol, last_seen).
//
// Used by GET /api/v1/network/conversations as a higher-level shape than the raw
// /network/map flow rows. Mirrors neuvector/controller/graph/graph.go's role.
package graph

import (
	"sort"
	"sync"
	"time"
)

// Attrs captures aggregate metrics on an edge. The L7/Verdict/Severity fields
// mirror NeuVector's per-conversation application/policyAction/severity so the
// graph carries the same security context as the conversation map.
type Attrs struct {
	Bytes    int64     `json:"bytes"`
	Packets  int64     `json:"packets"`
	Protocol string    `json:"protocol"`
	Port     int       `json:"port"`
	LastSeen time.Time `json:"last_seen"`
	L7       string    `json:"l7,omitempty"`       // L7 application: http, ssl, dns, ...
	Verdict  string    `json:"verdict,omitempty"`  // policy action: allow|deny|violate
	Severity int       `json:"severity,omitempty"` // max threat severity observed
}

// verdictRank orders verdicts by severity so folding keeps the worst.
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

// worseVerdict returns the more severe of two verdicts.
func worseVerdict(a, b string) string {
	if verdictRank(b) > verdictRank(a) {
		return b
	}
	return a
}

// Edge is a directed link between two nodes.
type Edge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Attrs Attrs  `json:"attrs"`
}

// Graph is a thread-safe directed multigraph. Multiple edges can exist between
// the same pair of nodes when distinguished by (Protocol, Port).
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]struct{}
	edges map[edgeKey]*Edge
}

type edgeKey struct {
	from, to, proto string
	port            int
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{nodes: map[string]struct{}{}, edges: map[edgeKey]*Edge{}}
}

// AddNode adds a node (idempotent).
func (g *Graph) AddNode(id string) {
	g.mu.Lock()
	g.nodes[id] = struct{}{}
	g.mu.Unlock()
}

// AddEdge records (or merges) an observation. Bytes/packets accumulate; LastSeen
// advances to the newer timestamp.
func (g *Graph) AddEdge(from, to string, attrs Attrs) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[from] = struct{}{}
	g.nodes[to] = struct{}{}
	k := edgeKey{from: from, to: to, proto: attrs.Protocol, port: attrs.Port}
	if existing, ok := g.edges[k]; ok {
		existing.Attrs.Bytes += attrs.Bytes
		existing.Attrs.Packets += attrs.Packets
		if attrs.Severity > existing.Attrs.Severity {
			existing.Attrs.Severity = attrs.Severity
		}
		existing.Attrs.Verdict = worseVerdict(existing.Attrs.Verdict, attrs.Verdict)
		if attrs.LastSeen.After(existing.Attrs.LastSeen) {
			existing.Attrs.LastSeen = attrs.LastSeen
			if attrs.L7 != "" {
				existing.Attrs.L7 = attrs.L7
			}
		}
		return
	}
	g.edges[k] = &Edge{From: from, To: to, Attrs: attrs}
}

// Nodes returns the sorted node list.
func (g *Graph) Nodes() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, 0, len(g.nodes))
	for n := range g.nodes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Edges returns a copy of the edge set, sorted by (from,to,protocol,port).
func (g *Graph) Edges() []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		if out[i].Attrs.Protocol != out[j].Attrs.Protocol {
			return out[i].Attrs.Protocol < out[j].Attrs.Protocol
		}
		return out[i].Attrs.Port < out[j].Attrs.Port
	})
	return out
}

// Conversations returns the aggregated (from, to) summary, folding all edges
// between the same pair into one row. Useful for the conversation view that
// doesn't care about the per-port breakdown.
func (g *Graph) Conversations() []Conversation {
	g.mu.RLock()
	defer g.mu.RUnlock()
	merged := map[string]*Conversation{}
	for _, e := range g.edges {
		k := e.From + "→" + e.To
		c, ok := merged[k]
		if !ok {
			c = &Conversation{From: e.From, To: e.To}
			merged[k] = c
		}
		c.Bytes += e.Attrs.Bytes
		c.Packets += e.Attrs.Packets
		c.Edges++
		if e.Attrs.LastSeen.After(c.LastSeen) {
			c.LastSeen = e.Attrs.LastSeen
		}
		if e.Attrs.Severity > c.Severity {
			c.Severity = e.Attrs.Severity
		}
		c.Verdict = worseVerdict(c.Verdict, e.Attrs.Verdict)
		if e.Attrs.L7 != "" && !containsStr(c.Apps, e.Attrs.L7) {
			c.Apps = append(c.Apps, e.Attrs.L7)
		}
	}
	for _, c := range merged {
		sort.Strings(c.Apps)
	}
	out := make([]Conversation, 0, len(merged))
	for _, c := range merged {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

// Conversation is the folded shape returned by Conversations.
type Conversation struct {
	From     string    `json:"from"`
	To       string    `json:"to"`
	Bytes    int64     `json:"bytes"`
	Packets  int64     `json:"packets"`
	Edges    int       `json:"edges"`
	LastSeen time.Time `json:"last_seen"`
	Severity int       `json:"severity,omitempty"` // max threat severity across edges
	Verdict  string    `json:"verdict,omitempty"`  // worst policy action across edges
	Apps     []string  `json:"apps,omitempty"`     // distinct L7 applications
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Len returns (nodeCount, edgeCount).
func (g *Graph) Len() (int, int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes), len(g.edges)
}
