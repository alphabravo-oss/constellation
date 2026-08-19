package handler

import (
	"testing"
	"time"
)

// Phase A time-bracket resolution: the resolver keys each IP to a slice of
// historical [firstSeen, lastSeen] windows and picks the generation whose
// window (plus grace) brackets the flow's timestamp. These tests exercise the
// pure map-lookup path directly by populating an ipResolver's candidate maps,
// so no database is required.

func newTestResolver(pods map[string][]ipCandidate) *ipResolver {
	if pods == nil {
		pods = map[string][]ipCandidate{}
	}
	return &ipResolver{pods: pods, svcs: map[string][]ipCandidate{}}
}

func TestResolveInWindow(t *testing.T) {
	base := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	r := newTestResolver(map[string][]ipCandidate{
		"10.42.0.5": {{label: "prod/web", firstSeen: base, lastSeen: base.Add(10 * time.Minute)}},
	})

	// A flow inside the window resolves to the pod.
	if got, ok := r.resolve("cluster/10.42.0.5", "10.42.0.5", "", base.Add(5*time.Minute)); !ok || got != "prod/web" {
		t.Fatalf("in-window: got (%q,%v), want (prod/web,true)", got, ok)
	}
	// A flow inside the 5m grace after lastSeen still resolves.
	if got, ok := r.resolve("cluster/10.42.0.5", "10.42.0.5", "", base.Add(13*time.Minute)); !ok || got != "prod/web" {
		t.Fatalf("grace: got (%q,%v), want (prod/web,true)", got, ok)
	}
}

func TestResolveOutOfWindowFallback(t *testing.T) {
	base := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	r := newTestResolver(map[string][]ipCandidate{
		"10.42.0.5": {{label: "prod/web", firstSeen: base, lastSeen: base.Add(10 * time.Minute)}},
	})

	// A flow well after the window (past grace) is out-of-window: best-effort
	// falls back to the only (most-recent) candidate rather than missing.
	got, ok := r.resolve("cluster/10.42.0.5", "10.42.0.5", "", base.Add(2*time.Hour))
	if !ok || got != "prod/web" {
		t.Fatalf("out-of-window fallback: got (%q,%v), want (prod/web,true)", got, ok)
	}

	// A flow before firstSeen is also out-of-window; still falls back.
	if got, ok := r.resolve("cluster/10.42.0.5", "10.42.0.5", "", base.Add(-time.Hour)); !ok || got != "prod/web" {
		t.Fatalf("before-window fallback: got (%q,%v), want (prod/web,true)", got, ok)
	}
}

func TestResolveIPReusePicksGenerationByTime(t *testing.T) {
	base := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	// Same IP, two pod generations that do not overlap: gen1 early, gen2 later.
	r := newTestResolver(map[string][]ipCandidate{
		"10.42.0.5": {
			{label: "prod/web-old", firstSeen: base, lastSeen: base.Add(10 * time.Minute)},
			{label: "prod/web-new", firstSeen: base.Add(30 * time.Minute), lastSeen: base.Add(40 * time.Minute)},
		},
	})

	// A flow during gen1's window attributes to the old pod.
	if got, ok := r.resolve("cluster/10.42.0.5", "10.42.0.5", "", base.Add(5*time.Minute)); !ok || got != "prod/web-old" {
		t.Fatalf("gen1: got (%q,%v), want (prod/web-old,true)", got, ok)
	}
	// A flow during gen2's window attributes to the new pod even though the IP
	// is identical.
	if got, ok := r.resolve("cluster/10.42.0.5", "10.42.0.5", "", base.Add(35*time.Minute)); !ok || got != "prod/web-new" {
		t.Fatalf("gen2: got (%q,%v), want (prod/web-new,true)", got, ok)
	}
	// A flow in the gap between generations misses both windows and falls back
	// to the most-recent lastSeen generation (gen2).
	if got, ok := r.resolve("cluster/10.42.0.5", "10.42.0.5", "", base.Add(20*time.Minute)); !ok || got != "prod/web-new" {
		t.Fatalf("gap fallback: got (%q,%v), want (prod/web-new,true)", got, ok)
	}
}

func TestResolveMiss(t *testing.T) {
	base := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	r := newTestResolver(nil)

	// Unknown IP with no candidates: the label is returned unchanged and ok is
	// false so the caller keeps the original "cluster/<ip>" workload.
	if got, ok := r.resolve("cluster/10.99.0.9", "10.99.0.9", "", base); ok || got != "cluster/10.99.0.9" {
		t.Fatalf("miss: got (%q,%v), want (cluster/10.99.0.9,false)", got, ok)
	}
}

func TestPickCandidateEmpty(t *testing.T) {
	if _, ok := pickCandidate(nil, time.Now()); ok {
		t.Fatalf("pickCandidate(nil) = ok, want miss")
	}
}
