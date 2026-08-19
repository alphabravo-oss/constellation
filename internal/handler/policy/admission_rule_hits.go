package policy

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// admissionRuleHitCounts returns, per admission rule id, how many times that rule
// has matched admission for the org. The count is derived from the durable audit
// trail (audit_events rows with action='admission.deny' for enforce denies OR
// action='admission.monitor' for monitor-mode matches, whose after->>'rule_id'
// records the rule), which is where the webhook records every admission decision —
// so no separate counter table is needed and the numbers can never drift from the
// recorded decisions. Including 'admission.monitor' is what makes monitor-mode
// rules show real hit counts, so operators can tune them before switching to
// enforce. A rule id absent from the result (count 0) is dead: it exists but has
// never been hit.
func admissionRuleHitCounts(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) (map[string]int, error) {
	rows, err := pool.Query(ctx, `
SELECT after->>'rule_id' AS rule_id, COUNT(*)
  FROM audit_events
 WHERE org_id = $1
   AND action IN ('admission.deny', 'admission.monitor')
   AND after->>'rule_id' IS NOT NULL
 GROUP BY after->>'rule_id'`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var ruleID string
		var n int
		if err := rows.Scan(&ruleID, &n); err != nil {
			return nil, err
		}
		counts[ruleID] = n
	}
	return counts, rows.Err()
}
