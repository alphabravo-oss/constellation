package quarantine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mkPod(ns, name string, owner string, ownerKind string, images ...string) *corev1.Pod {
	ctrs := make([]corev1.Container, 0, len(images))
	for i, img := range images {
		ctrs = append(ctrs, corev1.Container{Name: imgName(i), Image: img})
	}
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{Containers: ctrs},
	}
	if owner != "" {
		p.OwnerReferences = []metav1.OwnerReference{{Kind: ownerKind, Name: owner}}
	}
	return p
}

func imgName(i int) string {
	if i == 0 {
		return "main"
	}
	return "side"
}

func TestSnapshotMatch_Namespace(t *testing.T) {
	cluster := uuid.New()
	now := time.Now()
	entries := []Entry{{
		ID: uuid.New(), OrgID: uuid.New(), ClusterID: cluster,
		Scope: ScopeNamespace, MatchKey: "tainted",
		Reason: "active incident", Origin: "manual", CreatedAt: now,
	}}
	s := BuildSnapshot(cluster, now, entries)

	if hit := s.Match(mkPod("tainted", "pod-1", "", "", "nginx")); hit == nil {
		t.Fatal("namespace-scope quarantine should match pods in that namespace")
	} else if hit.MatchKind != "namespace" || hit.MatchValue != "tainted" {
		t.Errorf("wrong hit shape: %+v", hit)
	}
	if hit := s.Match(mkPod("untainted", "pod-2", "", "", "nginx")); hit != nil {
		t.Errorf("namespace quarantine leaked: %+v", hit)
	}
}

func TestSnapshotMatch_Workload_ReplicaSet(t *testing.T) {
	cluster := uuid.New()
	now := time.Now()
	entries := []Entry{{
		ID: uuid.New(), ClusterID: cluster, Scope: ScopeWorkload,
		MatchKey: "prod/api-server-7f9d", Reason: "exec runtime alert",
		Origin: "auto", CreatedAt: now,
	}}
	s := BuildSnapshot(cluster, now, entries)

	hit := s.Match(mkPod("prod", "api-server-7f9d-abcde", "api-server-7f9d", "ReplicaSet", "ghcr.io/acme/api:1.2.3"))
	if hit == nil {
		t.Fatal("workload-scope quarantine should match a pod owned by the named ReplicaSet")
	}
	if hit.MatchKind != "workload" || hit.MatchValue != "prod/api-server-7f9d" {
		t.Errorf("wrong hit shape: %+v", hit)
	}
}

func TestSnapshotMatch_Workload_DaemonSet(t *testing.T) {
	cluster := uuid.New()
	now := time.Now()
	entries := []Entry{{
		ClusterID: cluster, Scope: ScopeWorkload,
		MatchKey: "kube-system/node-exporter", Reason: "test", Origin: "manual",
		CreatedAt: now,
	}}
	s := BuildSnapshot(cluster, now, entries)

	if hit := s.Match(mkPod("kube-system", "node-exporter-7g8h", "node-exporter", "DaemonSet", "quay.io/prom/node-exporter")); hit == nil {
		t.Error("DaemonSet workload quarantine should match")
	}
}

func TestSnapshotMatch_Image_PrefixSemantics(t *testing.T) {
	cluster := uuid.New()
	now := time.Now()
	entries := []Entry{{
		ClusterID: cluster, Scope: ScopeImage,
		MatchKey: "ghcr.io/acme/api@sha256:badbad", Reason: "compromised digest",
		Origin: "auto", CreatedAt: now,
	}}
	s := BuildSnapshot(cluster, now, entries)

	// Exact-digest pod blocked.
	if s.Match(mkPod("p", "a", "", "", "ghcr.io/acme/api@sha256:badbadabcdef")) == nil {
		t.Error("image quarantine should match prefix")
	}
	// Different digest, same image — should still NOT match the bad-prefix.
	if hit := s.Match(mkPod("p", "b", "", "", "ghcr.io/acme/api@sha256:gooood")); hit != nil {
		t.Errorf("image quarantine should not match a different digest: %+v", hit)
	}
	// Different image entirely — clean.
	if hit := s.Match(mkPod("p", "c", "", "", "ghcr.io/acme/web:1.0.0")); hit != nil {
		t.Errorf("image quarantine should not leak across images: %+v", hit)
	}
}

func TestSnapshotMatch_Image_AnyContainer(t *testing.T) {
	cluster := uuid.New()
	now := time.Now()
	entries := []Entry{{
		ClusterID: cluster, Scope: ScopeImage,
		MatchKey: "evil.example.com/", Reason: "untrusted registry",
		Origin: "manual", CreatedAt: now,
	}}
	s := BuildSnapshot(cluster, now, entries)

	// Match when ANY container has the bad image — not just the first.
	hit := s.Match(mkPod("p", "a", "", "", "nginx", "evil.example.com/payload:latest"))
	if hit == nil {
		t.Fatal("image quarantine should match when a sidecar uses the image")
	}
	if hit.MatchValue != "evil.example.com/payload:latest" {
		t.Errorf("hit value should be the matching image, got %q", hit.MatchValue)
	}
}

func TestSnapshotMatch_ExpiredEntryDoesNotMatch(t *testing.T) {
	cluster := uuid.New()
	now := time.Now()
	past := now.Add(-1 * time.Hour)
	entries := []Entry{{
		ClusterID: cluster, Scope: ScopeNamespace, MatchKey: "stale",
		Reason: "old", Origin: "auto",
		CreatedAt: past.Add(-1 * time.Hour),
		ExpiresAt: &past,
	}}
	s := BuildSnapshot(cluster, now, entries)
	if hit := s.Match(mkPod("stale", "p", "", "", "nginx")); hit != nil {
		t.Errorf("expired entry should not match: %+v", hit)
	}
}

func TestSnapshotMatch_NonExpiringEntry(t *testing.T) {
	cluster := uuid.New()
	now := time.Now()
	entries := []Entry{{
		ClusterID: cluster, Scope: ScopeNamespace, MatchKey: "perm",
		Reason: "permaban", Origin: "manual", CreatedAt: now,
		// ExpiresAt: nil
	}}
	s := BuildSnapshot(cluster, now, entries)
	if s.Match(mkPod("perm", "p", "", "", "nginx")) == nil {
		t.Error("non-expiring entry should match")
	}
}

func TestSnapshotMatch_MatchOrder_NamespaceWinsOverImage(t *testing.T) {
	cluster := uuid.New()
	now := time.Now()
	entries := []Entry{
		{ClusterID: cluster, Scope: ScopeNamespace, MatchKey: "danger", Reason: "ns ban", Origin: "auto", CreatedAt: now},
		{ClusterID: cluster, Scope: ScopeImage, MatchKey: "nginx", Reason: "img ban", Origin: "auto", CreatedAt: now},
	}
	s := BuildSnapshot(cluster, now, entries)
	hit := s.Match(mkPod("danger", "p", "", "", "nginx"))
	if hit == nil || hit.MatchKind != "namespace" {
		t.Errorf("namespace should win match precedence; got %+v", hit)
	}
}

func TestSnapshotMatch_NilSafety(t *testing.T) {
	var s *Snapshot
	if s.Match(mkPod("a", "b", "", "", "c")) != nil {
		t.Error("nil snapshot Match must return nil")
	}
	s = BuildSnapshot(uuid.New(), time.Now(), nil)
	if s.Match(nil) != nil {
		t.Error("Match(nil pod) must return nil")
	}
}

func TestStats_CountsByScope(t *testing.T) {
	cluster := uuid.New()
	now := time.Now()
	entries := []Entry{
		{ClusterID: cluster, Scope: ScopeNamespace, MatchKey: "a", Origin: "auto", CreatedAt: now},
		{ClusterID: cluster, Scope: ScopeNamespace, MatchKey: "b", Origin: "auto", CreatedAt: now},
		{ClusterID: cluster, Scope: ScopeWorkload, MatchKey: "a/x", Origin: "manual", CreatedAt: now},
		{ClusterID: cluster, Scope: ScopeImage, MatchKey: "evil.example.com/", Origin: "auto", CreatedAt: now},
		{ClusterID: cluster, Scope: ScopeImage, MatchKey: "spam.example.com/", Origin: "auto", CreatedAt: now},
	}
	s := BuildSnapshot(cluster, now, entries)
	ns, wl, img := s.Stats()
	if ns != 2 || wl != 1 || img != 2 {
		t.Errorf("wrong stats: ns=%d wl=%d img=%d (want 2/1/2)", ns, wl, img)
	}
}

// ---- Source/Loader plumbing tests ----

type fakeLoader struct {
	calls int
	out   []Entry
	err   error
}

func (f *fakeLoader) Load(_ context.Context, _ uuid.UUID) ([]Entry, error) {
	f.calls++
	return f.out, f.err
}

func TestSource_RefreshUpdatesSnapshot(t *testing.T) {
	loader := &fakeLoader{out: []Entry{{
		ClusterID: uuid.New(), Scope: ScopeNamespace, MatchKey: "x",
		Reason: "test", Origin: "auto", CreatedAt: time.Now(),
	}}}
	src := NewSource(loader, uuid.New(), time.Second)

	// New source ships with an empty snapshot — guards against
	// nil-deref on the first request before Refresh fires.
	if src.Current() == nil {
		t.Fatal("Current() returned nil before any Refresh")
	}

	if err := src.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	ns, _, _ := src.Current().Stats()
	if ns != 1 {
		t.Errorf("snapshot should have 1 namespace entry after refresh, got %d", ns)
	}
	if h := src.Health(); h.Successes != 1 || h.Failures != 0 {
		t.Errorf("unexpected health: %+v", h)
	}
}

func TestSource_RefreshErrorKeepsLastSnapshot(t *testing.T) {
	loader := &fakeLoader{out: []Entry{{
		ClusterID: uuid.New(), Scope: ScopeNamespace, MatchKey: "x",
		Reason: "test", Origin: "auto", CreatedAt: time.Now(),
	}}}
	src := NewSource(loader, uuid.New(), time.Second)
	_ = src.Refresh(context.Background())

	loader.err = errors.New("db down")
	if err := src.Refresh(context.Background()); err == nil {
		t.Fatal("expected error from failing loader")
	}
	// We should still see the previous-good snapshot, not an empty one.
	ns, _, _ := src.Current().Stats()
	if ns != 1 {
		t.Errorf("error refresh should keep prior snapshot intact; got ns=%d", ns)
	}
	if h := src.Health(); h.Failures != 1 || h.LastError == "" {
		t.Errorf("health should record failure: %+v", h)
	}
}

func TestSource_IntervalClampsToOneSecond(t *testing.T) {
	loader := &fakeLoader{}
	src := NewSource(loader, uuid.New(), 1*time.Millisecond)
	if src.interval != time.Second {
		t.Errorf("interval should clamp to 1s minimum, got %v", src.interval)
	}
}

func TestEntry_ActiveAcrossExpiry(t *testing.T) {
	t0 := time.Now()
	future := t0.Add(time.Hour)
	past := t0.Add(-time.Hour)

	if !(Entry{}.Active(t0)) {
		t.Error("zero-value entry (no expiry) must be active")
	}
	if !(Entry{ExpiresAt: &future}.Active(t0)) {
		t.Error("future-expiry entry must be active")
	}
	if (Entry{ExpiresAt: &past}.Active(t0)) {
		t.Error("past-expiry entry must NOT be active")
	}
}
