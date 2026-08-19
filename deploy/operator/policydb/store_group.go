// store_group.go extends the operator policy store (store.go) with the P0-08 "policy-groups"
// domain: NeuVector-style workload groups (groups table) and group→group network segmentation
// edges (group_rule_edges table) — the NvSecurityRule/NvGroupDefinition GitOps parity surface.
//
// OWNERSHIP GUARD.
//
// store.go guards the policies/response_rules upserts on source='declarative' (migrations
// 027/108). The groups / group_rule_edges tables predate that column and — per the operator-crds
// subsystem's "no app migration" scope — are not altered, so the operator keys ownership on
// created_by/cfg_type instead. The operator has no user identity, so it writes created_by=NULL.
//
//   - groups: created_by IS NULL is NOT sufficient on its own — the learned-group synthesizer
//     (internal/handler/runtime/learnedgroups.go, cfg_type='learned') and federation sync
//     (internal/handler/fed_sync.go, cfg_type='fed') ALSO insert with created_by NULL. So the
//     operator ownership guard is created_by IS NULL AND cfg_type='user' (REST authors stamp
//     created_by=user; the operator forces cfg_type='user'). This keeps the operator from
//     clobbering, deleting, or GitOps-exporting a machine-learned or federated group that merely
//     shares a name — a learned/fed name collision affects zero rows and, for upserts, returns
//     ErrImperativeConflict.
//   - group_rule_edges: created_by IS NULL alone is a valid marker — its only non-operator writer
//     is runtime_groups.go, which stamps created_by, and there is no learned/fed edge path.
//
// SERVER-COMPUTED STATE. groups.members is a derived cache and group_rule_edges expansion produces
// runtime_policies rows; the operator writes NEITHER. It writes only the authored columns; the
// existing GroupMembershipReconciler (internal/handler/runtime) recomputes members against current
// deployments and re-expands edges downstream — so "applies to future members" is honoured exactly
// as for REST-authored groups/edges.
//
// TODO(matrix): a dedicated source column on these tables would be the more robust long-term
// ownership marker (created_by can in theory be NULLed on an imperative groups row via
// ON DELETE SET NULL when its author is deleted). Deferred to keep this subsystem migration-free.
package policydb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/group"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// operatorGroupCfgType is the groups.cfg_type stamped on every operator-authored group. It is the
// "user" (ground-truth, human-authored) provenance — as opposed to "learned"/"fed".
const operatorGroupCfgType = "user"

// ------------------------------- groups -------------------------------

// GroupRow is the mapped, org-scoped representation of a ConstellationGroup spec ready to upsert
// into a groups row. Members are intentionally omitted — they are server-computed (see file doc).
type GroupRow struct {
	OrgID       uuid.UUID
	Name        string
	Kind        string // learned | ground | federated
	Comment     string
	Criteria    []group.Criterion
	PolicyMode  string // discover | monitor | protect
	ProfileMode string // discover | monitor | protect
}

// UpsertGroup idempotently writes the group into the groups table keyed by UNIQUE(org_id, name).
// cluster_id is left NULL — operator groups are org-wide. cfg_type is forced to 'user' and
// created_by to NULL (the declarative marker). The CR is the source of truth: on conflict with a
// row the operator owns (created_by IS NULL) the authored columns are overwritten, correcting drift;
// members and cfg_type are never rewritten (members stays a server-computed cache). When the
// (org_id, name) identity is owned by an imperative (created_by non-NULL) row the upsert affects
// zero rows and returns ErrImperativeConflict.
func (s *Store) UpsertGroup(ctx context.Context, row GroupRow) error {
	criteria, err := json.Marshal(row.Criteria)
	if err != nil {
		return fmt.Errorf("marshal group criteria: %w", err)
	}
	tag, err := s.db.Exec(ctx, `
INSERT INTO groups (org_id, cluster_id, name, kind, comment, criteria, cfg_type, policy_mode, profile_mode, created_by)
VALUES ($1, NULL, $2, $3, $4, $5::jsonb, $6, $7, $8, NULL)
ON CONFLICT (org_id, name) DO UPDATE SET
    kind         = EXCLUDED.kind,
    comment      = EXCLUDED.comment,
    criteria     = EXCLUDED.criteria,
    policy_mode  = EXCLUDED.policy_mode,
    profile_mode = EXCLUDED.profile_mode,
    updated_at   = NOW()
WHERE groups.created_by IS NULL AND groups.cfg_type = 'user'`,
		row.OrgID, row.Name, row.Kind, row.Comment, string(criteria),
		operatorGroupCfgType, row.PolicyMode, row.ProfileMode)
	if err != nil {
		return fmt.Errorf("upsert group %q: %w", row.Name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("upsert group %q: %w", row.Name, ErrImperativeConflict)
	}
	return nil
}

// DeleteGroup removes the operator-managed groups row for (orgID, name). Only rows the operator
// owns (created_by IS NULL) are deleted, so a finalizer never orphans nor clobbers a REST-authored
// group that shares the name. It reports whether a row was deleted.
func (s *Store) DeleteGroup(ctx context.Context, orgID uuid.UUID, name string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`DELETE FROM groups WHERE org_id=$1 AND name=$2 AND created_by IS NULL AND cfg_type = 'user'`,
		orgID, name)
	if err != nil {
		return false, fmt.Errorf("delete group %q: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListGroups reads the operator-owned (created_by IS NULL) groups for orgID as upsert-shaped rows,
// ordered by name. It backs the GitOps export path: each row maps 1:1 to a ConstellationGroup CR
// (see GroupCR) that, re-applied, upserts the identical row.
func (s *Store) ListGroups(ctx context.Context, orgID uuid.UUID) ([]GroupRow, error) {
	rows, err := s.db.Query(ctx, `
SELECT name, kind, comment, COALESCE(criteria,'[]'::jsonb), policy_mode, profile_mode
FROM groups
WHERE org_id=$1 AND created_by IS NULL AND cfg_type = 'user'
ORDER BY name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var out []GroupRow
	for rows.Next() {
		r := GroupRow{OrgID: orgID}
		var criteria []byte
		if err := rows.Scan(&r.Name, &r.Kind, &r.Comment, &criteria, &r.PolicyMode, &r.ProfileMode); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		if err := json.Unmarshal(criteria, &r.Criteria); err != nil {
			return nil, fmt.Errorf("unmarshal criteria for %q: %w", r.Name, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate groups: %w", err)
	}
	return out, nil
}

// --------------------------- group_rule_edges ---------------------------

// NetworkRuleRow is the mapped, org+cluster-scoped representation of a ConstellationNetworkRule
// spec ready to upsert into a group_rule_edges row.
type NetworkRuleRow struct {
	OrgID     uuid.UUID
	ClusterID uuid.UUID
	FromGroup string
	ToGroup   string
	Ports     []netpolicy.PortSpec
	Mode      string // discover | monitor | protect
	Comment   string
}

// UpsertNetworkRule idempotently writes the group→group edge into group_rule_edges keyed by
// UNIQUE(org_id, cluster_id, from_group, to_group). created_by/updated_by are NULL (the declarative
// marker). The CR is the source of truth: on conflict with a row the operator owns
// (created_by IS NULL) the authored columns are overwritten, correcting drift. When the identity is
// owned by an imperative (created_by non-NULL) row the upsert affects zero rows and returns
// ErrImperativeConflict. Edge expansion to per-member runtime_policies is performed downstream by
// the GroupMembershipReconciler, not here.
func (s *Store) UpsertNetworkRule(ctx context.Context, row NetworkRuleRow) error {
	ports, err := json.Marshal(row.Ports)
	if err != nil {
		return fmt.Errorf("marshal edge ports: %w", err)
	}
	tag, err := s.db.Exec(ctx, `
INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group, ports, mode, comment, created_by, updated_by)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, NULL, NULL)
ON CONFLICT (org_id, cluster_id, from_group, to_group) DO UPDATE SET
    ports      = EXCLUDED.ports,
    mode       = EXCLUDED.mode,
    comment    = EXCLUDED.comment,
    updated_at = NOW()
WHERE group_rule_edges.created_by IS NULL`,
		row.OrgID, row.ClusterID, row.FromGroup, row.ToGroup, string(ports), row.Mode, row.Comment)
	if err != nil {
		return fmt.Errorf("upsert network rule %s->%s: %w", row.FromGroup, row.ToGroup, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("upsert network rule %s->%s: %w", row.FromGroup, row.ToGroup, ErrImperativeConflict)
	}
	return nil
}

// DeleteNetworkRule removes the operator-managed group_rule_edges row for the edge's natural key.
// Only rows the operator owns (created_by IS NULL) are deleted. It reports whether a row was deleted.
func (s *Store) DeleteNetworkRule(ctx context.Context, orgID, clusterID uuid.UUID, fromGroup, toGroup string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`DELETE FROM group_rule_edges
		 WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3 AND to_group=$4 AND created_by IS NULL`,
		orgID, clusterID, fromGroup, toGroup)
	if err != nil {
		return false, fmt.Errorf("delete network rule %s->%s: %w", fromGroup, toGroup, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListNetworkRules reads the operator-owned (created_by IS NULL) group→group edges for orgID as
// upsert-shaped rows, ordered by (cluster, from, to). It backs the GitOps export path: each row maps
// 1:1 to a ConstellationNetworkRule CR (see NetworkRuleCR) that, re-applied, upserts the identical row.
func (s *Store) ListNetworkRules(ctx context.Context, orgID uuid.UUID) ([]NetworkRuleRow, error) {
	rows, err := s.db.Query(ctx, `
SELECT cluster_id, from_group, to_group, COALESCE(ports,'[]'::jsonb), mode, comment
FROM group_rule_edges
WHERE org_id=$1 AND created_by IS NULL
ORDER BY cluster_id, from_group, to_group`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list network rules: %w", err)
	}
	defer rows.Close()

	var out []NetworkRuleRow
	for rows.Next() {
		r := NetworkRuleRow{OrgID: orgID}
		var ports []byte
		if err := rows.Scan(&r.ClusterID, &r.FromGroup, &r.ToGroup, &ports, &r.Mode, &r.Comment); err != nil {
			return nil, fmt.Errorf("scan network rule: %w", err)
		}
		if err := json.Unmarshal(ports, &r.Ports); err != nil {
			return nil, fmt.Errorf("unmarshal ports for %s->%s: %w", r.FromGroup, r.ToGroup, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network rules: %w", err)
	}
	return out, nil
}
