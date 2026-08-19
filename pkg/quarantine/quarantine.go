// Package quarantine implements the runtime-driven admission deny list.
//
// Architecture:
//
//   - The DB table quarantine_entries (migration 047) is the source of truth.
//   - This package holds an in-memory Snapshot — a cluster-scoped slice of
//     active entries with O(1) match-key lookups. The admission webhook
//     refreshes the Snapshot every N seconds via Source.Refresh().
//   - Snapshot.Match(pod) is called on the admission hot path. It checks
//     namespace, workload, then every container image, and returns the
//     first matching entry (or nil).
//   - A Match() hit is converted to an admission Deny by the engine. The
//     deny carries the entry id in the audit trail so the chain is
//     workload → runtime alert → quarantine entry → admission deny.
//
// Why a snapshot rather than a per-request DB call?
//
//   The admission webhook is on the critical path of every Pod CREATE.
//   A 50ms DB round-trip per request is the difference between "fine" and
//   "the kubelet times out and the node thrashes." We accept up to 5s of
//   staleness (configurable) — quarantine is not an enforcement primitive
//   for already-running pods (use the policy state machine for that), so
//   a short staleness window has no security cost.
package quarantine

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
)

// Scope is one of workload | image | namespace. The semantics live in the
// migration's column comment; this package treats them as opaque strings
// keyed on equal-prefix matching for image, equal-string for workload and
// namespace.
type Scope string

const (
	ScopeWorkload  Scope = "workload"
	ScopeImage     Scope = "image"
	ScopeNamespace Scope = "namespace"
)

// Entry is one quarantine row materialized in memory. Field names match
// the SQL column names for symmetry.
type Entry struct {
	ID         uuid.UUID `json:"id"`
	OrgID      uuid.UUID `json:"org_id"`
	ClusterID  uuid.UUID `json:"cluster_id"`
	Scope      Scope     `json:"scope"`
	MatchKey   string    `json:"match_key"`
	Reason     string    `json:"reason"`
	Origin     string    `json:"origin"`
	SourceKind string    `json:"source_kind,omitempty"`
	SourceID   *uuid.UUID `json:"source_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// Active returns true if the entry is still in force at t. An entry is
// active when it has no expires_at, or expires_at is in the future.
func (e Entry) Active(t time.Time) bool {
	return e.ExpiresAt == nil || e.ExpiresAt.After(t)
}

// Snapshot is the immutable per-refresh view of all active entries for
// one cluster. Lookups are O(1) for namespace and exact-workload, O(n)
// over image-prefix entries (typically <100, so still microseconds).
type Snapshot struct {
	clusterID uuid.UUID
	at        time.Time
	// Indexed views.
	namespaces map[string]Entry        // ns -> first matching entry
	workloads  map[string]Entry        // "ns/name" -> entry
	images     []Entry                 // scope=image; matched by HasPrefix
}

// Hit describes a quarantine match against a candidate pod.
type Hit struct {
	Entry      Entry  // the entry that matched
	MatchKind  string // "namespace" | "workload" | "image"
	MatchValue string // the value that caused the match (image ref / workload name / namespace)
}

// Match checks a pod against the snapshot. Returns the first matching
// entry, or nil if the pod is admissible per current quarantine state.
//
// Match order is from blunt to specific: namespace → workload → image.
// We stop on the first hit because we already have what we need (a
// reason to deny) and the audit event only carries one reference.
func (s *Snapshot) Match(pod *corev1.Pod) *Hit {
	if s == nil || pod == nil {
		return nil
	}
	if e, ok := s.namespaces[pod.Namespace]; ok && e.Active(s.at) {
		return &Hit{Entry: e, MatchKind: "namespace", MatchValue: pod.Namespace}
	}
	if name := workloadKeyForPod(pod); name != "" {
		if e, ok := s.workloads[name]; ok && e.Active(s.at) {
			return &Hit{Entry: e, MatchKind: "workload", MatchValue: name}
		}
	}
	for _, ctr := range allContainers(pod) {
		for _, e := range s.images {
			if !e.Active(s.at) {
				continue
			}
			if strings.HasPrefix(ctr.Image, e.MatchKey) {
				return &Hit{Entry: e, MatchKind: "image", MatchValue: ctr.Image}
			}
		}
	}
	return nil
}

// Stats reports the index size — useful for /metrics and for noticing
// when a cluster's quarantine list has gotten unreasonably large
// (a sign of runaway auto-quarantine).
func (s *Snapshot) Stats() (namespaces, workloads, images int) {
	if s == nil {
		return 0, 0, 0
	}
	return len(s.namespaces), len(s.workloads), len(s.images)
}

// At returns the snapshot's creation time. Used by the webhook's
// /readyz to refuse traffic when staleness exceeds the configured
// threshold.
func (s *Snapshot) At() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.at
}

// BuildSnapshot turns a flat slice of Entries into an indexed Snapshot.
// Exported so the API server can build a snapshot for a synthetic
// "would this pod be quarantined?" preview without touching the webhook.
func BuildSnapshot(clusterID uuid.UUID, at time.Time, entries []Entry) *Snapshot {
	s := &Snapshot{
		clusterID:  clusterID,
		at:         at,
		namespaces: make(map[string]Entry, 8),
		workloads:  make(map[string]Entry, 32),
		images:     make([]Entry, 0, 32),
	}
	for _, e := range entries {
		if !e.Active(at) {
			continue
		}
		switch e.Scope {
		case ScopeNamespace:
			if _, dup := s.namespaces[e.MatchKey]; !dup {
				s.namespaces[e.MatchKey] = e
			}
		case ScopeWorkload:
			if _, dup := s.workloads[e.MatchKey]; !dup {
				s.workloads[e.MatchKey] = e
			}
		case ScopeImage:
			s.images = append(s.images, e)
		}
	}
	return s
}

// Loader is the interface the webhook needs to fetch entries. It exists
// so tests can inject a fake; production uses a *pgxpool.Pool-backed
// implementation in internal/runtime/quarantine.
type Loader interface {
	Load(ctx context.Context, clusterID uuid.UUID) ([]Entry, error)
}

// Source holds the rolling Snapshot for one cluster, refreshed by a
// background goroutine. Construct one per webhook process.
//
// Refresh failures don't tear down the source — we keep serving the
// last good snapshot and bump a counter so the operator can see the
// freshness lag in /metrics.
type Source struct {
	loader    Loader
	clusterID uuid.UUID
	interval  time.Duration

	snap         atomic.Pointer[Snapshot]
	mu           sync.Mutex // serializes manual Refresh calls
	lastErr      atomic.Pointer[error]
	failureCount atomic.Int64
	successCount atomic.Int64
}

// NewSource creates a Source. interval defaults to 5s if <= 0; minimum
// 1s — anything faster is wasted DB traffic. Callers should immediately
// call Refresh(ctx) once before serving admission requests so the first
// pod CREATE isn't denied-on-empty-state.
func NewSource(loader Loader, clusterID uuid.UUID, interval time.Duration) *Source {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}
	s := &Source{
		loader:    loader,
		clusterID: clusterID,
		interval:  interval,
	}
	empty := BuildSnapshot(clusterID, time.Now(), nil)
	s.snap.Store(empty)
	return s
}

// Run blocks, polling the loader on the configured interval until ctx
// is cancelled. Designed to be `go source.Run(ctx)` from main().
func (s *Source) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	// Initial fetch right away so the snapshot isn't empty.
	_ = s.Refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.Refresh(ctx)
		}
	}
}

// Refresh forces an immediate reload. Safe to call concurrently with Run.
func (s *Source) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.loader.Load(ctx, s.clusterID)
	if err != nil {
		s.failureCount.Add(1)
		s.lastErr.Store(&err)
		return err
	}
	snap := BuildSnapshot(s.clusterID, time.Now(), entries)
	s.snap.Store(snap)
	s.successCount.Add(1)
	var ok error
	s.lastErr.Store(&ok)
	return nil
}

// Current returns the most recently loaded snapshot. Never nil after
// NewSource (the constructor seeds an empty one).
func (s *Source) Current() *Snapshot { return s.snap.Load() }

// Health describes the source's freshness for /readyz and /metrics.
type Health struct {
	LastRefresh time.Time `json:"last_refresh"`
	Age         time.Duration `json:"age"`
	Successes   int64     `json:"successes"`
	Failures    int64     `json:"failures"`
	LastError   string    `json:"last_error,omitempty"`
}

// Health returns a fresh snapshot of the source's state.
func (s *Source) Health() Health {
	snap := s.Current()
	h := Health{
		LastRefresh: snap.At(),
		Age:         time.Since(snap.At()),
		Successes:   s.successCount.Load(),
		Failures:    s.failureCount.Load(),
	}
	if errp := s.lastErr.Load(); errp != nil && *errp != nil {
		h.LastError = (*errp).Error()
	}
	return h
}

// workloadKeyForPod attempts to derive a "namespace/workload" string
// from a pod. Pod-creating controllers (Deployment, StatefulSet, DaemonSet,
// Job) set ownerReferences; this function uses the top-level owner kind
// + name when present. Naked pods fall back to "namespace/pod-name".
//
// We deliberately don't synthesize a Deployment name from a ReplicaSet
// suffix — too brittle. Operators authoring quarantine workload keys
// for Deployments should target the Deployment's ReplicaSet name as
// reported by the runtime alert, which is what we record.
func workloadKeyForPod(pod *corev1.Pod) string {
	if pod.Namespace == "" {
		return ""
	}
	for _, o := range pod.OwnerReferences {
		switch o.Kind {
		case "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob":
			return pod.Namespace + "/" + o.Name
		}
	}
	if pod.Name != "" {
		return pod.Namespace + "/" + pod.Name
	}
	return ""
}

func allContainers(pod *corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	out = append(out, pod.Spec.Containers...)
	out = append(out, pod.Spec.InitContainers...)
	return out
}
