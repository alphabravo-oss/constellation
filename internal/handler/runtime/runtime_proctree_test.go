package runtime

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestProcTreeCache_CrossBatchPrivEsc is the RT-4 regression test: a non-root parent exec
// and the root child exec arrive in SEPARATE Bulk calls. The within-batch detector
// (privEscFromBatch) cannot see the parent in the child's batch, so the cross-batch cache
// must flag it. This fails if the cache walk regresses.
func TestProcTreeCache_CrossBatchPrivEsc(t *testing.T) {
	cluster := uuid.New()
	const node = "node-a"
	now := time.Unix(1_700_000_000, 0).UTC()

	c := newProcTreeCache()

	// --- Batch 1: a non-root (uid=1000) parent shell execs, pid 100. ---
	parent := &IngestEvent{Kind: "process_exec", Node: node, PID: 100, PPID: 1, UID: 1000, Comm: "bash"}
	c.put(cluster, node, parent.PID, parent.PPID, parent.UID, parent.Comm, now)

	// In batch 1 the within-batch index only has the parent, so no escalation yet.
	uid1 := buildUIDByPID([]IngestEvent{*parent})
	if c.privEscWithCache(parent, cluster, uid1, now) {
		t.Fatalf("parent exec alone must not be a privilege escalation")
	}

	// --- Batch 2 (a later Bulk call): the root child execs, pid 200, ppid=100. ---
	child := &IngestEvent{Kind: "process_exec", Node: node, PID: 200, PPID: 100, UID: 0, Comm: "id"}
	uid2 := buildUIDByPID([]IngestEvent{*child}) // parent NOT in this batch.

	// Today's within-batch path misses this (parent in a different batch).
	if privEscFromBatch(child, uid2) {
		t.Fatalf("within-batch path unexpectedly saw the parent across batches")
	}
	// The cross-batch cache must catch it.
	if !c.privEscWithCache(child, cluster, uid2, now.Add(time.Second)) {
		t.Fatalf("cross-batch privilege escalation was not flagged")
	}

	// Cross-node isolation: the same PIDs on a different node must not collide.
	childOtherNode := &IngestEvent{Kind: "process_exec", Node: "node-b", PID: 200, PPID: 100, UID: 0, Comm: "id"}
	if c.privEscWithCache(childOtherNode, cluster, uid2, now.Add(time.Second)) {
		t.Fatalf("escalation must not cross node boundaries")
	}

	// Grandparent walk: root parent (pid 100 was non-root above; use a fresh chain).
	// non-root gp (pid 300) -> root parent (pid 400) -> root child (pid 500).
	c.put(cluster, node, 300, 1, 1000, "sh", now)  // non-root grandparent
	c.put(cluster, node, 400, 300, 0, "sudo", now) // root parent
	gchild := &IngestEvent{Kind: "process_exec", Node: node, PID: 500, PPID: 400, UID: 0, Comm: "bash"}
	if !c.privEscWithCache(gchild, cluster, buildUIDByPID([]IngestEvent{*gchild}), now) {
		t.Fatalf("grandparent-non-root escalation was not flagged via ancestor walk")
	}
}

// TestProcTreeCache_TTLEviction asserts an entry past procTreeTTL is ignored (and lazily
// evicted) so a reused PID does not produce a stale escalation.
func TestProcTreeCache_TTLEviction(t *testing.T) {
	cluster := uuid.New()
	const node = "node-a"
	now := time.Unix(1_700_000_000, 0).UTC()

	c := newProcTreeCache()
	c.put(cluster, node, 100, 1, 1000, "bash", now)

	child := &IngestEvent{Kind: "process_exec", Node: node, PID: 200, PPID: 100, UID: 0, Comm: "id"}
	uid := buildUIDByPID([]IngestEvent{*child})

	// Just inside the TTL: still flagged.
	if !c.privEscWithCache(child, cluster, uid, now.Add(procTreeTTL-time.Second)) {
		t.Fatalf("entry within TTL should still flag escalation")
	}
	// Past the TTL: the stale parent entry is ignored.
	if c.privEscWithCache(child, cluster, uid, now.Add(procTreeTTL+time.Second)) {
		t.Fatalf("TTL-expired parent entry must not flag escalation")
	}
	// And the expired entry was evicted by the lookup.
	if got := c.len(); got != 0 {
		t.Fatalf("TTL-expired entry not evicted: cache len = %d, want 0", got)
	}
}

// TestProcTreeCache_SizeEviction asserts the cache stays bounded at procTreeMaxEntries.
func TestProcTreeCache_SizeEviction(t *testing.T) {
	cluster := uuid.New()
	const node = "node-a"
	now := time.Unix(1_700_000_000, 0).UTC()

	c := newProcTreeCache()
	for i := 0; i < procTreeMaxEntries+500; i++ {
		// Stagger seen times so oldest-eviction is well-defined.
		c.put(cluster, node, uint32(i+1), 1, 1000, "bash", now.Add(time.Duration(i)*time.Millisecond))
	}
	if got := c.len(); got > procTreeMaxEntries {
		t.Fatalf("cache exceeded size bound: len = %d, want <= %d", got, procTreeMaxEntries)
	}
}
