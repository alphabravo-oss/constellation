package compliance

import (
	"testing"
	"time"
)

func TestNextRunFromCron_Valid(t *testing.T) {
	from := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	next, err := NextRunFromCron("0 0 * * *", "UTC", from)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.After(from) {
		t.Fatalf("expected next %v to be after %v", next, from)
	}
}

func TestNextRunFromCron_ImpossibleSpec(t *testing.T) {
	// "0 0 30 2 *" parses fine but never occurs (Feb 30). robfig/cron returns
	// the zero time, which must be rejected rather than persisted as year 0001.
	from := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	if _, err := NextRunFromCron("0 0 30 2 *", "UTC", from); err == nil {
		t.Fatal("expected error for impossible cron spec, got nil")
	}
}
