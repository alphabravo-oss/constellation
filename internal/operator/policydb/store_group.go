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
// runtime_policies rows; the operator writes NEITHER. Referenced group changes and expanded-edge
// changes/deletes are refused until an explicit atomic policy transition is available. The live
// membership reconciler likewise cannot safely refresh referenced groups yet.
//
// TODO(matrix): a dedicated source column on these tables would be the more robust long-term
// ownership marker (created_by can in theory be NULLed on an imperative groups row via
// ON DELETE SET NULL when its author is deleted). Deferred to keep this subsystem migration-free.
package policydb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/pkg/group"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// operatorGroupCfgType is the groups.cfg_type stamped on every operator-authored group. It is the
// "user" (ground-truth, human-authored) provenance — as opposed to "learned"/"fed".
const operatorGroupCfgType = "user"

var ErrGroupReferenced = errors.New("group or edge has policy references")
var ErrGroupScope = errors.New("group or cluster is outside the requested org and cluster scope")

type groupTransactionBeginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

func (s *Store) beginGroupMutation(ctx context.Context, orgID uuid.UUID) (pgx.Tx, error) {
	return s.beginOperatorMutation(ctx, orgID, `LOCK TABLE group_rule_edges, group_dpi_sensor_bindings, response_rules_v2, policies IN SHARE MODE NOWAIT`)
}

func (s *Store) beginOperatorMutation(ctx context.Context, orgID uuid.UUID, tableLock string) (pgx.Tx, error) {
	beginner, ok := s.db.(groupTransactionBeginner)
	if !ok {
		return nil, errors.New("group mutations require a transactional database")
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		tx, err := beginner.Begin(ctx)
		if err != nil {
			return nil, err
		}
		var lockedOrg uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE NOWAIT`, orgID).Scan(&lockedOrg)
		if err == nil {
			_, err = tx.Exec(ctx, tableLock)
		}
		if err == nil {
			return tx, nil
		}
		_ = tx.Rollback(ctx)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || time.Now().After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func groupHasReferences(ctx context.Context, tx pgx.Tx, orgID, groupID uuid.UUID, name string) (bool, error) {
	var count int
	err := tx.QueryRow(ctx, `
SELECT (SELECT count(*) FROM group_rule_edges WHERE org_id=$1 AND (from_group=$3 OR to_group=$3))
     + (SELECT count(*) FROM group_dpi_sensor_bindings WHERE org_id=$1 AND group_id=$2)
     + (SELECT count(*) FROM response_rules_v2 WHERE org_id=$1 AND (workload_match->>'group'=$3 OR workload_match->>'group'=$4))`,
		orgID, groupID, name, groupID.String()).Scan(&count)
	if err != nil || count > 0 {
		return count > 0, err
	}
	rows, err := tx.Query(ctx, `SELECT spec_yaml FROM policies WHERE org_id=$1 AND engine='constellation-admission'`, orgID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var spec string
		if err := rows.Scan(&spec); err != nil {
			return false, err
		}
		var rule struct {
			Spec struct {
				Match struct {
					Groups []string `yaml:"groups"`
				} `yaml:"match"`
			} `yaml:"spec"`
		}
		if yaml.Unmarshal([]byte(spec), &rule) != nil {
			continue
		}
		for _, selector := range rule.Spec.Match.Groups {
			selector = strings.TrimSpace(selector)
			if selector == groupID.String() || strings.EqualFold(selector, name) {
				return true, nil
			}
		}
	}
	return false, rows.Err()
}

func edgeHasPolicies(ctx context.Context, tx pgx.Tx, orgID, clusterID, edgeID uuid.UUID, fromGroup, toGroup string) (bool, error) {
	var exists bool
	legacyName := "edge-" + sanitizeGroupName(fromGroup) + "-to-" + sanitizeGroupName(toGroup)
	err := tx.QueryRow(ctx, `SELECT EXISTS (
SELECT 1 FROM runtime_policies WHERE org_id=$1 AND cluster_id=$2
  AND (name=$3 OR name=$4 OR rules @> $5::jsonb))`,
		orgID, clusterID, legacyName, legacyName+"-"+edgeID.String(),
		`[{"edge_id":"`+edgeID.String()+`"}]`).Scan(&exists)
	return exists, err
}

func sanitizeGroupName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "/", "-")
	return strings.ReplaceAll(value, " ", "-")
}

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
// created_by to NULL (the declarative marker). Referenced policy-sensitive changes are refused;
// comment-only drift can still be corrected. Members and cfg_type are never rewritten.
func (s *Store) UpsertGroup(ctx context.Context, row GroupRow) error {
	criteria, err := json.Marshal(row.Criteria)
	if err != nil {
		return fmt.Errorf("marshal group criteria: %w", err)
	}
	tx, err := s.beginGroupMutation(ctx, row.OrgID)
	if err != nil {
		return fmt.Errorf("begin group upsert: %w", err)
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	var currentKind, currentPolicyMode, currentProfileMode string
	var currentCriteria []byte
	var currentCluster *uuid.UUID
	var createdBy *uuid.UUID
	var cfgType string
	err = tx.QueryRow(ctx, `SELECT id, cluster_id, created_by, cfg_type, kind, criteria, policy_mode, profile_mode
FROM groups WHERE org_id=$1 AND name=$2 FOR UPDATE`, row.OrgID, row.Name).
		Scan(&id, &currentCluster, &createdBy, &cfgType, &currentKind, &currentCriteria, &currentPolicyMode, &currentProfileMode)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read group %q: %w", row.Name, err)
	}
	if err == nil {
		if createdBy != nil || cfgType != operatorGroupCfgType {
			return fmt.Errorf("upsert group %q: %w", row.Name, ErrImperativeConflict)
		}
		if currentCluster != nil {
			return fmt.Errorf("upsert group %q: %w", row.Name, ErrGroupScope)
		}
		var current, next any
		if json.Unmarshal(currentCriteria, &current) != nil || json.Unmarshal(criteria, &next) != nil {
			return fmt.Errorf("upsert group %q: invalid stored criteria", row.Name)
		}
		if currentKind != row.Kind || currentPolicyMode != row.PolicyMode || currentProfileMode != row.ProfileMode || !reflect.DeepEqual(current, next) {
			referenced, err := groupHasReferences(ctx, tx, row.OrgID, id, row.Name)
			if err != nil {
				return fmt.Errorf("check group %q references: %w", row.Name, err)
			}
			if referenced {
				return fmt.Errorf("upsert group %q: %w", row.Name, ErrGroupReferenced)
			}
		}
	} else {
		referenced, err := groupHasReferences(ctx, tx, row.OrgID, uuid.Nil, row.Name)
		if err != nil {
			return fmt.Errorf("check group %q references: %w", row.Name, err)
		}
		if referenced {
			return fmt.Errorf("upsert group %q: %w", row.Name, ErrGroupReferenced)
		}
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO groups (org_id, cluster_id, name, kind, comment, criteria, cfg_type, policy_mode, profile_mode, created_by)
VALUES ($1, NULL, $2, $3, $4, $5::jsonb, $6, $7, $8, NULL)
ON CONFLICT (org_id, name) DO UPDATE SET
    kind         = EXCLUDED.kind,
    comment      = EXCLUDED.comment,
    criteria     = EXCLUDED.criteria,
    policy_mode  = EXCLUDED.policy_mode,
    profile_mode = EXCLUDED.profile_mode,
    updated_at   = NOW()
WHERE groups.created_by IS NULL AND groups.cfg_type = 'user' AND groups.cluster_id IS NULL`,
		row.OrgID, row.Name, row.Kind, row.Comment, string(criteria),
		operatorGroupCfgType, row.PolicyMode, row.ProfileMode)
	if err != nil {
		return fmt.Errorf("upsert group %q: %w", row.Name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("upsert group %q: %w", row.Name, ErrImperativeConflict)
	}
	return tx.Commit(ctx)
}

// DeleteGroup removes the operator-managed groups row for (orgID, name) only when unreferenced.
// It reports whether a row was deleted.
func (s *Store) DeleteGroup(ctx context.Context, orgID uuid.UUID, name string) (bool, error) {
	tx, err := s.beginGroupMutation(ctx, orgID)
	if err != nil {
		return false, fmt.Errorf("begin group delete: %w", err)
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM groups WHERE org_id=$1 AND name=$2 AND cluster_id IS NULL
AND created_by IS NULL AND cfg_type='user' FOR UPDATE`, orgID, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read group %q: %w", name, err)
	}
	referenced, err := groupHasReferences(ctx, tx, orgID, id, name)
	if err != nil {
		return false, fmt.Errorf("check group %q references: %w", name, err)
	}
	if referenced {
		return false, fmt.Errorf("delete group %q: %w", name, ErrGroupReferenced)
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM groups WHERE id=$1 AND org_id=$2 AND cluster_id IS NULL AND created_by IS NULL AND cfg_type='user'`, id, orgID)
	if err != nil {
		return false, fmt.Errorf("delete group %q: %w", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
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
// ErrImperativeConflict. Existing expanded policies block mode/port changes until a safe
// transition can re-expand them; this writer never expands policies itself.
func (s *Store) UpsertNetworkRule(ctx context.Context, row NetworkRuleRow) error {
	ports, err := json.Marshal(row.Ports)
	if err != nil {
		return fmt.Errorf("marshal edge ports: %w", err)
	}
	tx, err := s.beginOperatorMutation(ctx, row.OrgID, `LOCK TABLE group_rule_edges IN ROW EXCLUSIVE MODE NOWAIT`)
	if err != nil {
		return fmt.Errorf("begin network rule upsert: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := lockNetworkRuleScope(ctx, tx, row.OrgID, row.ClusterID, row.FromGroup, row.ToGroup); err != nil {
		return fmt.Errorf("network rule %s->%s: %w", row.FromGroup, row.ToGroup, err)
	}
	var id uuid.UUID
	var createdBy *uuid.UUID
	var currentPorts []byte
	var currentMode string
	err = tx.QueryRow(ctx, `SELECT id, created_by, ports, mode FROM group_rule_edges
WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3 AND to_group=$4 FOR UPDATE`,
		row.OrgID, row.ClusterID, row.FromGroup, row.ToGroup).Scan(&id, &createdBy, &currentPorts, &currentMode)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read network rule: %w", err)
	}
	if err == nil {
		if createdBy != nil {
			return fmt.Errorf("upsert network rule %s->%s: %w", row.FromGroup, row.ToGroup, ErrImperativeConflict)
		}
		var current, next any
		if json.Unmarshal(currentPorts, &current) != nil || json.Unmarshal(ports, &next) != nil {
			return errors.New("invalid stored network rule ports")
		}
		if currentMode != row.Mode || !reflect.DeepEqual(current, next) {
			referenced, err := edgeHasPolicies(ctx, tx, row.OrgID, row.ClusterID, id, row.FromGroup, row.ToGroup)
			if err != nil {
				return fmt.Errorf("check network rule policies: %w", err)
			}
			if referenced {
				return fmt.Errorf("upsert network rule %s->%s: %w", row.FromGroup, row.ToGroup, ErrGroupReferenced)
			}
		}
	}
	tag, err := tx.Exec(ctx, `
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
	return tx.Commit(ctx)
}

// DeleteNetworkRule removes the operator-managed group_rule_edges row for the edge's natural key.
// Only unexpanded rows the operator owns (created_by IS NULL) are deleted. It reports whether a row was deleted.
func (s *Store) DeleteNetworkRule(ctx context.Context, orgID, clusterID uuid.UUID, fromGroup, toGroup string) (bool, error) {
	tx, err := s.beginOperatorMutation(ctx, orgID, `LOCK TABLE group_rule_edges IN ROW EXCLUSIVE MODE NOWAIT`)
	if err != nil {
		return false, fmt.Errorf("begin network rule delete: %w", err)
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM group_rule_edges WHERE org_id=$1 AND cluster_id=$2
AND from_group=$3 AND to_group=$4 AND created_by IS NULL FOR UPDATE`,
		orgID, clusterID, fromGroup, toGroup).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read network rule: %w", err)
	}
	referenced, err := edgeHasPolicies(ctx, tx, orgID, clusterID, id, fromGroup, toGroup)
	if err != nil {
		return false, fmt.Errorf("check network rule policies: %w", err)
	}
	if referenced {
		return false, fmt.Errorf("delete network rule %s->%s: %w", fromGroup, toGroup, ErrGroupReferenced)
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM group_rule_edges
		 WHERE id=$1 AND org_id=$2 AND created_by IS NULL`, id, orgID)
	if err != nil {
		return false, fmt.Errorf("delete network rule %s->%s: %w", fromGroup, toGroup, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func lockNetworkRuleScope(ctx context.Context, tx pgx.Tx, orgID, clusterID uuid.UUID, fromGroup, toGroup string) error {
	var lockedCluster uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM clusters WHERE id=$1 AND org_id=$2 FOR KEY SHARE`, clusterID, orgID).Scan(&lockedCluster); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGroupScope
		}
		return err
	}
	for _, name := range []string{fromGroup, toGroup} {
		if name == "external" || name == "nodes" {
			continue
		}
		var groupID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM groups WHERE org_id=$1 AND name=$2
AND (cluster_id IS NULL OR cluster_id=$3) FOR KEY SHARE`, orgID, name, clusterID).Scan(&groupID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGroupScope
		}
		if err != nil {
			return err
		}
	}
	return nil
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
