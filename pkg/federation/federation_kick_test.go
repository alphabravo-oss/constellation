package federation

import (
	"testing"
	"time"
)

func TestKick(t *testing.T) {
	got, err := Kick(MemberStatusActive)
	if err != nil {
		t.Fatalf("kick active: %v", err)
	}
	if got != MemberStatusKicked {
		t.Fatalf("want %q, got %q", MemberStatusKicked, got)
	}
	if _, err := Kick(MemberStatusKicked); err == nil {
		t.Fatal("kicking an already-kicked member should error")
	}
}

func TestDeriveStatus(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	interval := time.Minute
	cases := []struct {
		name     string
		stored   string
		lastSync time.Time
		want     string
	}{
		{"never synced stays pending", MemberStatusPending, time.Time{}, MemberStatusPending},
		{"fresh poll is active", MemberStatusActive, now.Add(-30 * time.Second), MemberStatusActive},
		{"past one interval is stale", MemberStatusActive, now.Add(-90 * time.Second), MemberStatusStale},
		{"past three intervals is offline", MemberStatusActive, now.Add(-10 * time.Minute), MemberStatusOffline},
		{"kicked is terminal", MemberStatusKicked, now.Add(-1 * time.Second), MemberStatusKicked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveStatus(tc.stored, tc.lastSync, now, interval); got != tc.want {
				t.Fatalf("DeriveStatus(%q,%v) = %q, want %q", tc.stored, tc.lastSync, got, tc.want)
			}
		})
	}
}
