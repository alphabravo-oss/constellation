package livegraph

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSnapshotAggregatesAndScopes(t *testing.T) {
	s := New(Config{TTL: time.Hour})
	org := uuid.New()
	c1, c2 := uuid.New(), uuid.New()
	now := time.Now()

	// Two observations on the same edge in c1 should fold (bytes/packets sum).
	s.Publish(Flow{OrgID: org, ClusterID: c1, SrcWorkload: "ns/a", DstWorkload: "ns/b", Protocol: "tcp", Port: 80, Bytes: 100, Packets: 1, At: now})
	s.Publish(Flow{OrgID: org, ClusterID: c1, SrcWorkload: "ns/a", DstWorkload: "ns/b", Protocol: "tcp", Port: 80, Bytes: 50, Packets: 2, Verdict: "deny", At: now})
	// A different cluster's edge.
	s.Publish(Flow{OrgID: org, ClusterID: c2, SrcWorkload: "ns/x", DstWorkload: "ns/y", Protocol: "tcp", Port: 443, Bytes: 10, Packets: 1, At: now})

	g := s.Snapshot(org, nil)
	nodes, edges := g.Len()
	if nodes != 4 || edges != 2 {
		t.Fatalf("org snapshot: got %d nodes %d edges, want 4/2", nodes, edges)
	}
	convs := g.Conversations()
	var ab bool
	for _, c := range convs {
		if c.From == "ns/a" && c.To == "ns/b" {
			ab = true
			if c.Bytes != 150 || c.Packets != 3 {
				t.Fatalf("folded edge: got bytes=%d packets=%d, want 150/3", c.Bytes, c.Packets)
			}
			if c.Verdict != "deny" {
				t.Fatalf("verdict fold: got %q, want deny", c.Verdict)
			}
		}
	}
	if !ab {
		t.Fatal("missing folded ns/a->ns/b conversation")
	}

	// cluster scoping isolates c1.
	g1 := s.Snapshot(org, &c1)
	if _, e := g1.Len(); e != 1 {
		t.Fatalf("c1 scope: got %d edges, want 1", e)
	}
}

func TestSnapshotEvictsExpired(t *testing.T) {
	s := New(Config{TTL: 10 * time.Millisecond})
	org := uuid.New()
	s.Publish(Flow{OrgID: org, ClusterID: uuid.New(), SrcWorkload: "a", DstWorkload: "b", Protocol: "tcp", At: time.Now().Add(-time.Hour)})
	if _, e := s.Snapshot(org, nil).Len(); e != 0 {
		t.Fatalf("expired observation should be evicted, got %d edges", e)
	}
}

func TestMaxEdgesCapBoundsStore(t *testing.T) {
	s := New(Config{TTL: time.Hour, MaxEdgesPer: 3})
	org := uuid.New()
	cl := uuid.New()
	base := time.Now()
	for i := 0; i < 10; i++ {
		s.Publish(Flow{OrgID: org, ClusterID: cl, SrcWorkload: "a", DstWorkload: "b", Protocol: "tcp", Port: i, At: base.Add(time.Duration(i) * time.Second)})
	}
	if _, e := s.Snapshot(org, nil).Len(); e > 3 {
		t.Fatalf("store exceeded cap: got %d edges, want <=3", e)
	}
}

func TestPublishFanout(t *testing.T) {
	s := New(Config{TTL: time.Hour, SubscriberBuf: 4})
	org := uuid.New()
	ch, cancel := s.Subscribe(org)
	defer cancel()

	s.Publish(Flow{OrgID: org, ClusterID: uuid.New(), SrcWorkload: "a", DstWorkload: "b", Protocol: "tcp", At: time.Now()})
	select {
	case f := <-ch:
		if f.SrcWorkload != "a" || f.DstWorkload != "b" {
			t.Fatalf("fanout wrong flow: %+v", f)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive published flow")
	}

	// other-org publish must not reach this subscriber.
	s.Publish(Flow{OrgID: uuid.New(), ClusterID: uuid.New(), SrcWorkload: "x", DstWorkload: "y", Protocol: "tcp", At: time.Now()})
	select {
	case f := <-ch:
		t.Fatalf("subscriber received cross-org flow: %+v", f)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestNilStorePublishSafe(t *testing.T) {
	var s *Store
	s.Publish(Flow{OrgID: uuid.New()}) // must not panic
}
