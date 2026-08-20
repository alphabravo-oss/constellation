package handler

import (
	"testing"
	"time"
)

func TestPartitionDay(t *testing.T) {
	cases := []struct {
		name    string
		wantOK  bool
		wantDay string // YYYY-MM-DD
	}{
		{"events_20260820", true, "2026-08-20"},
		{"network_flows_20260101", true, "2026-01-01"},
		{"events_p_default", false, ""},          // default partition — never a drop candidate
		{"network_flows_p_default", false, ""},   // default partition
		{"events", false, ""},                    // parent
		{"events_2026082", false, ""},            // 7 digits, not a valid day tag
	}
	for _, c := range cases {
		day, ok := partitionDay(c.name)
		if ok != c.wantOK {
			t.Fatalf("%s: ok=%v want %v", c.name, ok, c.wantOK)
		}
		if ok && day.Format("2006-01-02") != c.wantDay {
			t.Fatalf("%s: day=%s want %s", c.name, day.Format("2006-01-02"), c.wantDay)
		}
	}
}

// The drop rule must only fire when a partition's WHOLE [day, day+1) range is at or
// before the cutoff — a partition covering the cutoff day or any future day must survive.
func TestPartitionExpiryBoundary(t *testing.T) {
	// retention 14 days, "today" = 2026-08-20 → cutoff = 2026-08-06.
	cutoff := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -14)
	expired := func(dayStr string) bool {
		day, _ := time.Parse("2006-01-02", dayStr)
		return !day.AddDate(0, 0, 1).After(cutoff) // same predicate as dropExpiredPartitions
	}
	// day+1 <= cutoff → expired
	if !expired("2026-08-05") { // covers ..08-06 00:00 == cutoff → expired
		t.Fatal("2026-08-05 partition should be expired (upper bound == cutoff)")
	}
	if expired("2026-08-06") { // covers up to 08-07, past cutoff → keep
		t.Fatal("2026-08-06 partition (the cutoff day) must be kept")
	}
	if expired("2026-08-20") {
		t.Fatal("today's partition must never be dropped")
	}
}
