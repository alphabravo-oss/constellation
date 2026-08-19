package graph

import (
	"testing"
	"time"
)

func TestGraph_AddAndAggregate(t *testing.T) {
	g := New()
	t1 := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	g.AddEdge("api", "db", Attrs{Bytes: 100, Packets: 1, Protocol: "tcp", Port: 5432, LastSeen: t1})
	g.AddEdge("api", "db", Attrs{Bytes: 200, Packets: 2, Protocol: "tcp", Port: 5432, LastSeen: t1.Add(time.Minute)})
	g.AddEdge("api", "db", Attrs{Bytes: 50, Packets: 1, Protocol: "tcp", Port: 6379, LastSeen: t1})
	g.AddEdge("api", "cache", Attrs{Bytes: 25, Packets: 1, Protocol: "tcp", Port: 6379, LastSeen: t1})

	nodes, edges := g.Len()
	if nodes != 3 {
		t.Fatalf("nodes: want 3, got %d", nodes)
	}
	if edges != 3 {
		t.Fatalf("edges: want 3 (two ports api->db plus api->cache), got %d", edges)
	}
	es := g.Edges()
	// edges are sorted by (from,to,proto,port); find the api->db port 5432 edge.
	var apidb5432 *Edge
	for i := range es {
		if es[i].From == "api" && es[i].To == "db" && es[i].Attrs.Port == 5432 {
			apidb5432 = &es[i]
		}
	}
	if apidb5432 == nil || apidb5432.Attrs.Bytes != 300 || apidb5432.Attrs.Packets != 3 {
		t.Fatalf("merged api->db:5432: want 300 bytes / 3 packets; got %+v", apidb5432)
	}
}

func TestGraph_ConversationSecurityFields(t *testing.T) {
	g := New()
	t1 := time.Now()
	// two edges api→db: an allow http and a later deny ssl with higher severity.
	g.AddEdge("api", "db", Attrs{Bytes: 10, Protocol: "tcp", Port: 443, LastSeen: t1, L7: "http", Verdict: "allow", Severity: 1})
	g.AddEdge("api", "db", Attrs{Bytes: 5, Protocol: "tcp", Port: 5432, LastSeen: t1.Add(time.Minute), L7: "ssl", Verdict: "deny", Severity: 4})
	conv := g.Conversations()
	if len(conv) != 1 {
		t.Fatalf("expected 1 conversation, got %d", len(conv))
	}
	c := conv[0]
	if c.Severity != 4 {
		t.Fatalf("expected max severity 4, got %d", c.Severity)
	}
	if c.Verdict != "deny" {
		t.Fatalf("expected worst verdict deny, got %q", c.Verdict)
	}
	if len(c.Apps) != 2 || c.Apps[0] != "http" || c.Apps[1] != "ssl" {
		t.Fatalf("expected sorted apps [http ssl], got %v", c.Apps)
	}
}

func TestGraph_Conversations(t *testing.T) {
	g := New()
	t1 := time.Now()
	g.AddEdge("api", "db", Attrs{Bytes: 10, Protocol: "tcp", Port: 5432, LastSeen: t1})
	g.AddEdge("api", "db", Attrs{Bytes: 20, Protocol: "tcp", Port: 6379, LastSeen: t1})
	g.AddEdge("api", "cache", Attrs{Bytes: 5, Protocol: "tcp", Port: 6379, LastSeen: t1})
	conv := g.Conversations()
	if len(conv) != 2 {
		t.Fatalf("expected 2 conversations, got %d", len(conv))
	}
	for _, c := range conv {
		if c.From == "api" && c.To == "db" {
			if c.Bytes != 30 || c.Edges != 2 {
				t.Fatalf("api→db conv: %+v", c)
			}
		}
	}
}

func TestGraph_NodesSorted(t *testing.T) {
	g := New()
	g.AddNode("b")
	g.AddNode("a")
	got := g.Nodes()
	if got[0] != "a" || got[1] != "b" {
		t.Fatalf("nodes not sorted: %v", got)
	}
}
