package netpolicy

import (
	"testing"
	"time"
)

func ptime(t time.Time) *time.Time { return &t }

func TestRuleMatchStat_IsDead(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	window := 14 * 24 * time.Hour

	cases := []struct {
		name string
		stat RuleMatchStat
		want bool
	}{
		{"never matched", RuleMatchStat{RuleID: 1, LastMatchedAt: nil}, true},
		{"matched inside window", RuleMatchStat{RuleID: 2, MatchCount: 5, LastMatchedAt: ptime(now.Add(-2 * time.Hour))}, false},
		{"matched just before cutoff", RuleMatchStat{RuleID: 3, MatchCount: 5, LastMatchedAt: ptime(now.Add(-window - time.Minute))}, true},
		{"matched exactly at cutoff is alive", RuleMatchStat{RuleID: 4, LastMatchedAt: ptime(now.Add(-window))}, false},
		{"high count but all before window", RuleMatchStat{RuleID: 5, MatchCount: 9999, LastMatchedAt: ptime(now.Add(-30 * 24 * time.Hour))}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.stat.IsDead(now, window); got != c.want {
				t.Errorf("IsDead = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRuleMatchStat_IsDead_DefaultWindow(t *testing.T) {
	now := time.Now().UTC()
	// A non-positive window falls back to DefaultDeadRuleWindow.
	fresh := RuleMatchStat{RuleID: 1, LastMatchedAt: ptime(now.Add(-1 * time.Hour))}
	if fresh.IsDead(now, 0) {
		t.Error("fresh rule should not be dead with default window")
	}
	stale := RuleMatchStat{RuleID: 2, LastMatchedAt: ptime(now.Add(-DefaultDeadRuleWindow - time.Hour))}
	if !stale.IsDead(now, -1) {
		t.Error("stale rule should be dead with default window")
	}
}

func TestDeadRules(t *testing.T) {
	now := time.Now().UTC()
	stats := []RuleMatchStat{
		{RuleID: 1, LastMatchedAt: ptime(now.Add(-1 * time.Hour))},          // alive
		{RuleID: 2, LastMatchedAt: nil},                                     // dead (never)
		{RuleID: 3, LastMatchedAt: ptime(now.Add(-100 * 24 * time.Hour))},   // dead (stale)
	}
	dead := DeadRules(stats, now, DefaultDeadRuleWindow)
	if len(dead) != 2 {
		t.Fatalf("expected 2 dead rules, got %d", len(dead))
	}
	if dead[0].RuleID != 2 || dead[1].RuleID != 3 {
		t.Errorf("unexpected dead rule ids: %+v", dead)
	}
}
