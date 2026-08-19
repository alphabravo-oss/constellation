// Cross-batch process-tree cache for runtime privilege-escalation detection (RT-4).
//
// The original within-batch detection (privEscFromBatch / buildUIDByPID in
// runtime_detections.go) can only correlate a root child against its non-root parent
// when BOTH execs land in the same /api/v1/events:bulk call. In practice the parent
// (e.g. a non-root shell) and the child (e.g. a root exec spawned moments later) often
// arrive in different batches a few hundred ms apart, so the escalation is missed today.
//
// procTreeCache is a bounded, TTL'd per-(cluster,node) map of pid -> {uid,ppid,comm}
// that persists across Bulk calls on the server. Combined with the within-batch index it
// lets classifyEvent walk a few ancestors and flag a root-child-of-non-root escalation
// even when the ancestor was seen in an earlier batch. This is the server-side analogue of
// NeuVector's pidProcMap walk in agent/probe/process.go rootEscalationCheck (~865) and the
// short sudo-ancestry walk in isSudoChild (~922, ~10 ancestors).
//
// RT-4-FINISH lifted part of the original ceiling: the agent now emits per-exec /proc
// enrichment (StdioSocket + real uid) on the IngestEvent, so reverse-shell and real-uid
// escalation ARE evaluated server-side — see reverseShell / realUIDEscalation in
// runtime_detections.go, classified in classifyProcessExec. This cache still owns only the
// cross-batch root-child-of-non-root-ANCESTOR walk (pid/ppid/uid correlation).
//
// CEILING (ponytail: process-tree depth + authority walk). What remains unreproducible
// server-side, because it needs the agent's live pidProcMap rather than what per-exec events
// report:
//
//   - Full sudo-ancestry / real-user-vs-effective-user authority checks (NeuVector
//     checkUserGroup: is the real user in adm/root/sudo groups). Our cache only holds what
//     execs report, so we walk a bounded few ancestors by ppid and stop at the cache edge.
//   - userns root-uid offsets (c.userns.root / uidMin). We treat uid 0 as root directly.
//
// The agent-side addition that would lift the remainder: emit per-exec group membership /
// userns mapping so the authority walk could be evaluated server-side.
package runtime

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// procTreeAncestorWalk bounds how many ancestors privEscWithCache walks up the cached tree
// before giving up. Mirrors NeuVector isSudoChild's "look up 10 ancestors" loop.
const procTreeAncestorWalk = 10

// procTreeMaxEntries caps the total number of cached (cluster,node,pid) entries.
// ponytail: fixed-size bound. A 4096-pid LRU-ish cap (oldest-by-insertion eviction once
// exceeded) keeps memory flat under a misbehaving / high-churn node; the real upgrade is a
// proper per-node ring buffer or a TTL sweep goroutine, but a size+TTL bound is enough to
// prevent unbounded growth.
const procTreeMaxEntries = 4096

// procTreeTTL is how long a cached pid entry is trusted. PIDs are reused, so an entry older
// than this is ignored (and lazily evicted) rather than risking a stale ppid->uid mapping.
const procTreeTTL = 5 * time.Minute

// procNode is one cached process: its effective uid, its parent pid, and comm (for the
// payload reason / debugging). seen is the insertion time used for TTL + size eviction.
type procNode struct {
	uid  uint32
	ppid uint32
	comm string
	seen time.Time
}

// procTreeKey scopes a pid to a (cluster,node) so PIDs from different nodes never collide.
type procTreeKey struct {
	cluster uuid.UUID
	node    string
	pid     uint32
}

// procTreeCache is a bounded, TTL'd pid->procNode map shared across Bulk calls. Concurrency:
// Bulk runs one goroutine per request, so the map is guarded by a single mutex; the critical
// sections are short (map writes + a bounded ancestor walk).
type procTreeCache struct {
	mu      sync.Mutex
	entries map[procTreeKey]procNode
}

func newProcTreeCache() *procTreeCache {
	return &procTreeCache{entries: make(map[procTreeKey]procNode)}
}

// put records (or refreshes) a pid's uid/ppid/comm. It performs lazy size eviction: once the
// map exceeds procTreeMaxEntries it drops the single oldest-by-seen entry per insertion, so
// a steady insert rate keeps the map at its cap rather than growing without bound.
func (c *procTreeCache) put(cluster uuid.UUID, node string, pid, ppid, uid uint32, comm string, now time.Time) {
	if c == nil || pid == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[procTreeKey{cluster: cluster, node: node, pid: pid}] = procNode{
		uid:  uid,
		ppid: ppid,
		comm: comm,
		seen: now,
	}
	if len(c.entries) > procTreeMaxEntries {
		c.evictOldestLocked()
	}
}

// evictOldestLocked removes the single entry with the smallest seen time. Caller holds mu.
func (c *procTreeCache) evictOldestLocked() {
	var oldestKey procTreeKey
	var oldest time.Time
	first := true
	for k, v := range c.entries {
		if first || v.seen.Before(oldest) {
			oldestKey, oldest, first = k, v.seen, false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
	}
}

// lookup returns the cached node for a pid if present and not past its TTL. A TTL-expired
// entry is evicted and reported as a miss. Caller holds mu.
func (c *procTreeCache) lookupLocked(cluster uuid.UUID, node string, pid uint32, now time.Time) (procNode, bool) {
	k := procTreeKey{cluster: cluster, node: node, pid: pid}
	n, ok := c.entries[k]
	if !ok {
		return procNode{}, false
	}
	if now.Sub(n.seen) > procTreeTTL {
		delete(c.entries, k)
		return procNode{}, false
	}
	return n, true
}

// len reports the current cache size (test/observability helper).
func (c *procTreeCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// privEscWithCache reports whether ev is a root child whose nearest non-runtime ancestor ran
// as a non-root uid, using the within-batch index FIRST and the cross-batch cache to fill in
// ancestors not present in this batch. It walks up to procTreeAncestorWalk ancestors by ppid.
//
//	ev          the candidate child exec (must already be uid==0 with a non-zero ppid)
//	cluster     scope for the cache key
//	uidByPID    within-batch pid->uid index (buildUIDByPID); takes precedence over the cache
//	now         evaluation time for TTL checks
//
// Returns true iff some ancestor (parent, grandparent, ...) within the walk bound is known to
// have run as a non-root uid. This strictly augments privEscFromBatch: any escalation that the
// within-batch path would flag is also flagged here (the parent is in uidByPID), and it
// additionally catches the cross-batch case where the parent exec arrived earlier.
func (c *procTreeCache) privEscWithCache(ev *IngestEvent, cluster uuid.UUID, uidByPID map[uint32]uint32, now time.Time) bool {
	if ev == nil || ev.Kind != "process_exec" || ev.UID != 0 || ev.PPID == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	ancestorPID := ev.PPID
	for i := 0; i < procTreeAncestorWalk && ancestorPID != 0 && ancestorPID != ev.PID; i++ {
		// Within-batch index wins (freshest, no TTL concern).
		if uid, ok := uidByPID[ancestorPID]; ok {
			if uid != 0 {
				return true
			}
			// Ancestor was root in this batch; keep walking only if the cache knows its
			// parent. The within-batch index does not carry ppid, so consult the cache.
			n, ok := c.lookupLocked(cluster, ev.Node, ancestorPID, now)
			if !ok {
				return false
			}
			ancestorPID = n.ppid
			continue
		}
		// Cross-batch: look the ancestor up in the persisted cache.
		n, ok := c.lookupLocked(cluster, ev.Node, ancestorPID, now)
		if !ok {
			return false
		}
		if n.uid != 0 {
			return true
		}
		ancestorPID = n.ppid
	}
	return false
}
