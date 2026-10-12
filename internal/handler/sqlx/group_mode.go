package sqlx

import "fmt"

// GroupModeRank validates the public strongest configured policy-mode filter.
// It describes cached membership, not applied/enforced policy health.
func GroupModeRank(mode string) (int, error) {
	switch mode {
	case "":
		return 0, nil
	case "discover":
		return 1, nil
	case "monitor":
		return 2, nil
	case "protect":
		return 3, nil
	default:
		return 0, fmt.Errorf("invalid group_mode")
	}
}

// GroupModesSQL emits one strongest mode per tenant, cluster and workload. Inputs
// are trusted SQL expressions/placeholders, never request values. Keeping cluster
// in the grouping key prevents same-named workloads in sibling clusters mixing.
func GroupModesSQL(org, cluster string) string {
	return `SELECT g.org_id, g.cluster_id, member.workload_id,
 MAX(CASE g.policy_mode WHEN 'protect' THEN 3 WHEN 'monitor' THEN 2 ELSE 1 END) AS rank
 FROM groups g
 CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(g.members)='array' THEN g.members ELSE '[]'::jsonb END) member(workload_id)
 WHERE g.org_id=` + org + ` AND (` + cluster + `::uuid IS NULL OR g.cluster_id=` + cluster + `)
 GROUP BY g.org_id,g.cluster_id,member.workload_id`
}
