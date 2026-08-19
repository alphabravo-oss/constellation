package runtime

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestThreatDedup_CollapsesFloodWithinWindow is the core P0-5 flood-collapse
// guarantee: thousands of identical SYN-flood threat logs within the dedup
// window must produce exactly ONE alert, and a new alert must fire once the
// window has elapsed (so an ongoing flood keeps surfacing).
func TestThreatDedup_CollapsesFloodWithinWindow(t *testing.T) {
	base := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	now := base
	d := newThreatDedup(60 * time.Second)
	d.now = func() time.Time { return now }

	key := "flood-key"

	// First hit fires.
	if !d.allow(key) {
		t.Fatalf("first hit must fire")
	}
	// A flood of identical hits inside the window is all suppressed.
	fired := 0
	for i := 0; i < 5000; i++ {
		now = now.Add(5 * time.Millisecond) // still well inside 60s
		if d.allow(key) {
			fired++
		}
	}
	if fired != 0 {
		t.Fatalf("flood within window must be fully suppressed, got %d extra alerts", fired)
	}

	// Once the window elapses, the next hit re-fires (re-arms the window).
	now = base.Add(61 * time.Second)
	if !d.allow(key) {
		t.Fatalf("hit after window elapse must re-fire")
	}
	// ...and immediately suppresses again.
	now = now.Add(time.Second)
	if d.allow(key) {
		t.Fatalf("hit right after re-fire must be suppressed")
	}
}

// TestThreatDedup_DistinctTuplesAlertIndependently ensures dedup is per-tuple:
// two different threats (or the same signature from a different source) each get
// their own alert even within the same window.
func TestThreatDedup_DistinctTuplesAlertIndependently(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	d := newThreatDedup(60 * time.Second)
	d.now = func() time.Time { return now }

	if !d.allow("a") {
		t.Fatalf("first tuple must fire")
	}
	if !d.allow("b") {
		t.Fatalf("distinct tuple must fire independently")
	}
	if d.allow("a") {
		t.Fatalf("repeat of tuple a within window must be suppressed")
	}
}

// TestThreatDedup_ZeroWindowDisables verifies dedup can be turned off (every hit
// alerts) via a zero/negative window.
func TestThreatDedup_ZeroWindowDisables(t *testing.T) {
	d := newThreatDedup(0)
	for i := 0; i < 3; i++ {
		if !d.allow("k") {
			t.Fatalf("zero-window dedup must never suppress")
		}
	}
	// A nil dedup is also always-allow (defensive).
	var nilD *threatDedup
	if !nilD.allow("k") {
		t.Fatalf("nil dedup must allow")
	}
}

// TestThreatDedupKey_Identity confirms the flood-collapse identity is exactly
// (org, threat_id, src, dst, dst_port): those four together collapse, and any
// change in one of them is a distinct alert.
func TestThreatDedupKey_Identity(t *testing.T) {
	org := uuid.New()
	other := uuid.New()
	row := &ThreatIngestRow{ThreatID: 1001, SrcIP: "10.0.0.9", DstIP: "10.0.0.1", DstPort: 80, SrcPort: 4444}

	k := threatDedupKey(org, row)

	// Same tuple, different src_port (floods rotate src ports) => same key.
	same := *row
	same.SrcPort = 5555
	if threatDedupKey(org, &same) != k {
		t.Fatalf("src_port must NOT be part of the dedup identity")
	}

	// Any of org / threat_id / src / dst / dst_port changing => distinct key.
	cases := []struct {
		name string
		mut  func(r *ThreatIngestRow, o *uuid.UUID)
	}{
		{"org", func(r *ThreatIngestRow, o *uuid.UUID) { *o = other }},
		{"threat_id", func(r *ThreatIngestRow, o *uuid.UUID) { r.ThreatID = 2022 }},
		{"src_ip", func(r *ThreatIngestRow, o *uuid.UUID) { r.SrcIP = "10.0.0.99" }},
		{"dst_ip", func(r *ThreatIngestRow, o *uuid.UUID) { r.DstIP = "10.0.0.2" }},
		{"dst_port", func(r *ThreatIngestRow, o *uuid.UUID) { r.DstPort = 443 }},
	}
	for _, tc := range cases {
		r := *row
		o := org
		tc.mut(&r, &o)
		if threatDedupKey(o, &r) == k {
			t.Fatalf("%s change must produce a distinct dedup key", tc.name)
		}
	}
}

// TestThreatSeverityLabel_MapsNeuVectorScale pins the NeuVector THRT_SEVERITY_*
// (1..5) -> string mapping used by the notify/response fan-out, and that the
// default alert threshold (HIGH) gates as expected.
func TestThreatSeverityLabel_MapsNeuVectorScale(t *testing.T) {
	want := map[uint8]string{0: "info", 1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}
	for sev, label := range want {
		if got := threatSeverityLabel(sev); got != label {
			t.Fatalf("severity %d: want %q got %q", sev, label, got)
		}
	}
	if defaultThreatAlertSeverityMin != 4 {
		t.Fatalf("default alert threshold must be HIGH(4), got %d", defaultThreatAlertSeverityMin)
	}
}
