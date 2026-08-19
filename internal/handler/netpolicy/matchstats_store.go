// A7: persistence for per-rule match telemetry (network_rule_match_stats,
// migration 127). The flow-ingest path calls RecordMatches to bump counters;
// the lifecycle/list API calls List / DeadRules to surface the dead-rule
// signal. Pure decision logic lives in pkg/netpolicy/matchstats.go.
package netpolicy

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	netpolicy "github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// MatchStatsStore records and reads per-rule match telemetry.
type MatchStatsStore struct {
	db *db.DB
}

// NewMatchStatsStore constructs the store.
func NewMatchStatsStore(d *db.DB) *MatchStatsStore { return &MatchStatsStore{db: d} }

// ruleHit is one (rule_id -> match increment) accumulated within an ingest
// batch, so a batch of N flows for the same rule costs one UPSERT, not N.
type ruleHit struct {
	count int64
	last  time.Time
}

// RecordMatches upserts cumulative match counters for a batch of rule hits,
// keyed by rule id (== network_flows.policy_id). Best-effort telemetry: it
// runs its own statements (not the caller's flow-insert tx) so a stats write
// never rolls back accepted flows, and callers ignore the error beyond
// logging. `at` timestamps advance first_matched_at (only when unset) and
// last_matched_at (monotonically forward).
func (s *MatchStatsStore) RecordMatches(ctx context.Context, orgID, clusterID uuid.UUID, hits map[int64]ruleHit) error {
	if s == nil || s.db == nil || len(hits) == 0 {
		return nil
	}
	const q = `
INSERT INTO network_rule_match_stats
  (org_id, cluster_id, rule_id, match_count, first_matched_at, last_matched_at)
VALUES ($1,$2,$3,$4,$5,$5)
ON CONFLICT (org_id, cluster_id, rule_id) DO UPDATE
   SET match_count     = network_rule_match_stats.match_count + EXCLUDED.match_count,
       first_matched_at = LEAST(network_rule_match_stats.first_matched_at, EXCLUDED.first_matched_at),
       last_matched_at  = GREATEST(network_rule_match_stats.last_matched_at, EXCLUDED.last_matched_at)`
	for ruleID, h := range hits {
		if ruleID == 0 {
			continue // 0 = "no rule attributed" (default-action / unmatched); nothing to count
		}
		at := h.last
		if at.IsZero() {
			at = time.Now().UTC()
		}
		if _, err := s.db.Pool().Exec(ctx, q, orgID, clusterID, ruleID, h.count, at.UTC()); err != nil {
			return err
		}
	}
	return nil
}

// List returns all recorded rule stats for a cluster, newest-match first.
func (s *MatchStatsStore) List(ctx context.Context, orgID, clusterID uuid.UUID) ([]netpolicy.RuleMatchStat, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Pool().Query(ctx, `
SELECT rule_id, match_count, first_matched_at, last_matched_at
  FROM network_rule_match_stats
 WHERE org_id = $1 AND cluster_id = $2
 ORDER BY last_matched_at DESC NULLS LAST`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []netpolicy.RuleMatchStat{}
	for rows.Next() {
		var st netpolicy.RuleMatchStat
		if err := rows.Scan(&st.RuleID, &st.MatchCount, &st.FirstMatchedAt, &st.LastMatchedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// DeadRules returns the rules that have gone silent over `window` ending now.
// Thin DB-side prefilter (last_matched_at < cutoff) whose result matches the
// pure netpolicy.DeadRules predicate; NULL last_matched_at rows (never matched)
// are dead too but are not stored — see TODO(matrix) in matchstats.go.
func (s *MatchStatsStore) DeadRules(ctx context.Context, orgID, clusterID uuid.UUID, now time.Time, window time.Duration) ([]netpolicy.RuleMatchStat, error) {
	if window <= 0 {
		window = netpolicy.DefaultDeadRuleWindow
	}
	all, err := s.List(ctx, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	return netpolicy.DeadRules(all, now, window), nil
}
