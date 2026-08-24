package registry

import (
	"testing"
	"time"
)

func TestResolveScheduleCustomDuration(t *testing.T) {
	s := ResolveSchedule("12h")
	if s.Mode != SchedulePeriodic || s.Interval != 12*time.Hour {
		t.Fatalf("schedule=%+v, want 12h periodic", s)
	}

	last := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	if !s.IsDue(&last, last.Add(12*time.Hour), time.Minute) {
		t.Fatal("custom duration should be due at interval boundary")
	}
	if s.IsDue(&last, last.Add(11*time.Hour), time.Minute) {
		t.Fatal("custom duration should not be due before interval boundary")
	}
}

func TestResolveScheduleCron(t *testing.T) {
	s := ResolveSchedule("cron:0 2 * * *")
	if s.Mode != ScheduleCron || s.CronExpr != "0 2 * * *" {
		t.Fatalf("schedule=%+v, want cron at 02:00", s)
	}

	last := time.Date(2026, 8, 23, 1, 0, 0, 0, time.UTC)
	if !s.IsDue(&last, time.Date(2026, 8, 23, 2, 0, 0, 0, time.UTC), time.Minute) {
		t.Fatal("cron schedule should be due at next occurrence")
	}
	if s.IsDue(&last, time.Date(2026, 8, 23, 1, 59, 0, 0, time.UTC), time.Minute) {
		t.Fatal("cron schedule should not be due before next occurrence")
	}
}

func TestResolveScheduleInvalidCronFailsClosed(t *testing.T) {
	if got := ResolveSchedule("cron:not valid"); got.Mode != ScheduleManual {
		t.Fatalf("invalid cron resolved to %+v, want manual", got)
	}
}
