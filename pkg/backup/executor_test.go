package backup

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func tp(t time.Time) *time.Time { return &t }

func TestIsDue(t *testing.T) {
	now := time.Date(2026, 6, 30, 3, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		s    schedule
		want bool
	}{
		{"disabled never due", schedule{Enabled: false, NextRunAt: tp(now.Add(-time.Hour))}, false},
		{"nil next not due (bootstrap)", schedule{Enabled: true, NextRunAt: nil}, false},
		{"future not due", schedule{Enabled: true, NextRunAt: tp(now.Add(time.Minute))}, false},
		{"exactly now is due", schedule{Enabled: true, NextRunAt: tp(now)}, true},
		{"past is due", schedule{Enabled: true, NextRunAt: tp(now.Add(-time.Minute))}, true},
	}
	for _, c := range cases {
		if got := isDue(c.s, now); got != c.want {
			t.Errorf("%s: isDue=%v want %v", c.name, got, c.want)
		}
	}
}

func TestRetentionVictims(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	mk := func(daysAgo int) backupRecord {
		return backupRecord{ID: uuid.New(), StartedAt: now.Add(-time.Duration(daysAgo) * 24 * time.Hour)}
	}
	// Newest..oldest: 0,1,2,3,4 days ago (deliberately unsorted input).
	recs := []backupRecord{mk(2), mk(0), mk(4), mk(1), mk(3)}

	t.Run("both disabled keeps everything", func(t *testing.T) {
		if v := retentionVictims(recs, 0, 0, now); v != nil {
			t.Fatalf("want nil victims, got %d", len(v))
		}
	})

	t.Run("keep last 2 prunes 3 oldest", func(t *testing.T) {
		v := retentionVictims(recs, 2, 0, now)
		if len(v) != 3 {
			t.Fatalf("want 3 victims, got %d", len(v))
		}
		// Victims must be the 2,3,4-day-old records; the 0 and 1 day survive.
		for _, r := range v {
			age := now.Sub(r.StartedAt).Hours() / 24
			if age < 2 {
				t.Fatalf("pruned a too-recent record aged %.0f days", age)
			}
		}
	})

	t.Run("max age 2 days prunes older than cutoff", func(t *testing.T) {
		v := retentionVictims(recs, 0, 2, now)
		// records strictly older than 2 days: 3 and 4 day-old => 2 victims.
		if len(v) != 2 {
			t.Fatalf("want 2 victims, got %d", len(v))
		}
	})

	t.Run("count and age union", func(t *testing.T) {
		// keepLast=4 alone would prune only the oldest (4d). maxAge=2 also prunes 3d & 4d.
		// Union => {3d, 4d} = 2 victims.
		v := retentionVictims(recs, 4, 2, now)
		if len(v) != 2 {
			t.Fatalf("want 2 victims, got %d", len(v))
		}
	})
}

func TestNextBackupRun(t *testing.T) {
	from := time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC)
	next, err := NextBackupRun("0 3 * * *", from)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := time.Date(2026, 6, 30, 3, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("next=%v want %v", next, want)
	}
	if _, err := NextBackupRun("not a cron", from); err == nil {
		t.Fatal("expected error for invalid cron")
	}
}
