// A7: per-rule match telemetry + dead-rule detection.
//
// Pure logic + a thin store over the network_rule_match_stats table
// (migration 127). Models NeuVector RESTPolicyRule.MatchCntr / LastMatchTS
// (controller/api/apis.go): every flow the datapath attributes to a rule
// bumps that rule's cumulative counter and last-match timestamp, and a rule
// that has gone silent over a window is surfaced as "dead".
package netpolicy

import "time"

// DefaultDeadRuleWindow is the lookback used to decide a rule is dead when the
// caller does not specify one. A rule with no match inside this window is
// flagged. 14 days mirrors a fortnightly review cadence — long enough that a
// weekly batch job does not read as dead, short enough to catch genuinely
// retired rules.
const DefaultDeadRuleWindow = 14 * 24 * time.Hour

// RuleMatchStat is one row of network_rule_match_stats: the cumulative match
// telemetry for a single matched rule (RuleID == network_flows.policy_id, the
// NeuVector matched-rule id).
type RuleMatchStat struct {
	RuleID         int64      `json:"rule_id"`
	MatchCount     int64      `json:"match_count"`
	FirstMatchedAt *time.Time `json:"first_matched_at,omitempty"`
	LastMatchedAt  *time.Time `json:"last_matched_at,omitempty"`
}

// IsDead reports whether the rule has had zero matches within the window ending
// at `now`. A rule that has never matched (nil LastMatchedAt) is dead; a rule
// whose most recent match predates now-window is dead. A non-positive window
// falls back to DefaultDeadRuleWindow.
//
// Note this is a "no matches *in the window*" signal: a rule may have a large
// cumulative MatchCount yet still be dead if all of it landed before the window
// opened. That is the intended NeuVector-style "is this rule still earning its
// keep?" question, not "was it ever used?".
func (s RuleMatchStat) IsDead(now time.Time, window time.Duration) bool {
	if window <= 0 {
		window = DefaultDeadRuleWindow
	}
	if s.LastMatchedAt == nil {
		return true
	}
	return s.LastMatchedAt.Before(now.Add(-window))
}

// DeadRules returns the subset of stats that are dead over the window ending at
// `now`, preserving input order. Convenience wrapper around IsDead for the
// lifecycle/list API's dead-rule section.
func DeadRules(stats []RuleMatchStat, now time.Time, window time.Duration) []RuleMatchStat {
	out := make([]RuleMatchStat, 0)
	for _, s := range stats {
		if s.IsDead(now, window) {
			out = append(out, s)
		}
	}
	return out
}
