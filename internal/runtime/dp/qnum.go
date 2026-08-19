// Wave A3: NFQUEUE number allocator.
//
// Each pod veth that's in enforce mode binds to its own kernel NFQUEUE
// (one queue per veth keeps dp's per-queue accounting / threading clean).
// We allocate queue numbers from a configurable base offset (default 4000)
// up to a per-node cap (default 8000) — well above any reasonable pod
// density and well clear of NeuVector's typical 800–1200 range (so a
// belt-and-braces multi-vendor setup doesn't collide).
//
// The allocator is a simple bitmap; reuse-on-release ensures long-running
// agents don't drift the counter forever. Thread-safe.
package dp

import (
	"errors"
	"sync"
)

// QnumAllocator hands out NFQUEUE numbers in [base, base+capacity) and
// reclaims them on Release. Used by enforceManager.
type QnumAllocator struct {
	base     int
	capacity int

	mu       sync.Mutex
	used     []bool // index = qnum-base; true = in use
	nextHint int    // round-robin starting point for the next search
}

// NewQnumAllocator constructs an allocator. base is the lowest queue number
// to hand out; capacity is the total count (so [base, base+capacity)). Zero
// capacity defaults to 4000, base defaults to 4000.
func NewQnumAllocator(base, capacity int) *QnumAllocator {
	if base <= 0 {
		base = 4000
	}
	if capacity <= 0 {
		capacity = 4000
	}
	return &QnumAllocator{
		base:     base,
		capacity: capacity,
		used:     make([]bool, capacity),
	}
}

// Allocate finds the next free queue number and marks it used. Returns
// an error if every slot in [base, base+capacity) is taken — practically
// impossible at default size (4000 slots vs the kube spec's 250-pod max).
func (q *QnumAllocator) Allocate() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	// Search from nextHint forward, wrapping once.
	for i := 0; i < q.capacity; i++ {
		idx := (q.nextHint + i) % q.capacity
		if !q.used[idx] {
			q.used[idx] = true
			q.nextHint = (idx + 1) % q.capacity
			return q.base + idx, nil
		}
	}
	return 0, errors.New("qnum allocator exhausted")
}

// Release marks a queue number free. Idempotent — releasing an already-free
// slot is a no-op (logged at debug elsewhere).
func (q *QnumAllocator) Release(qnum int) {
	idx := qnum - q.base
	if idx < 0 || idx >= q.capacity {
		return
	}
	q.mu.Lock()
	q.used[idx] = false
	q.mu.Unlock()
}

// InUse returns the current count of allocated queues. Useful for the
// /metrics endpoint and for tests.
func (q *QnumAllocator) InUse() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, b := range q.used {
		if b {
			n++
		}
	}
	return n
}
