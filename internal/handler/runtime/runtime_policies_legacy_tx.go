package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

var (
	errLegacyPolicyNotFound        = errors.New("policy not found")
	errLegacyPolicyClusterNotFound = errors.New("cluster not found")
)

// legacyPolicyTransaction keeps the exact policy row, its audit event, and the
// returned representation in one commit. Legacy endpoints have no review token;
// row locks serialize their patches without losing fields changed by a peer.
func (s *RuntimePolicyStore) legacyPolicyTransaction(ctx context.Context, mutate func(pgx.Tx) (*RuntimePolicy, error)) (*RuntimePolicy, error) {
	tx, err := s.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	after, err := mutate(tx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return after, nil
}

// Runtime policies have independent UUID scope columns, not an ownership FK.
// Keep the matching cluster locked until commit so it cannot change owners or
// disappear between validation and the policy write.
func requireLegacyPolicyCluster(ctx context.Context, tx pgx.Tx, org, cluster uuid.UUID) error {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM clusters WHERE id=$1 AND org_id=$2 FOR SHARE`, cluster, org).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errLegacyPolicyClusterNotFound
	}
	return err
}

func lockLegacyPolicy(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (*RuntimePolicy, error) {
	p, err := scanPolicy(tx.QueryRow(ctx, `SELECT `+policySelectCols+` FROM runtime_policies WHERE id=$1 AND org_id=$2 FOR UPDATE`, id, org))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errLegacyPolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := requireLegacyPolicyCluster(ctx, tx, org, p.ClusterID); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *RuntimePolicyStore) insertLegacyPolicy(ctx context.Context, p *RuntimePolicy, requestID string) (*RuntimePolicy, error) {
	candidate := *p
	if !candidate.Mode.Valid() {
		return nil, fmt.Errorf("invalid mode %q", candidate.Mode)
	}
	if candidate.Workload == "" || candidate.Namespace == "" || candidate.Name == "" {
		return nil, errors.New("workload, namespace, and name are required")
	}
	if len(candidate.Rules) == 0 {
		candidate.Rules = json.RawMessage("[]")
	}
	direction, err := policyDatabaseDirection(&candidate)
	if err != nil {
		return nil, err
	}
	saved, err := s.legacyPolicyTransaction(ctx, func(tx pgx.Tx) (*RuntimePolicy, error) {
		if err := requireLegacyPolicyCluster(ctx, tx, candidate.OrgID, candidate.ClusterID); err != nil {
			return nil, err
		}
		got, err := scanPolicy(tx.QueryRow(ctx, `INSERT INTO runtime_policies
   (org_id,cluster_id,workload,namespace,name,mode,def_action,apply_dir,rules,version,created_by,updated_by)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,1,$10,$10) RETURNING `+policySelectCols,
			candidate.OrgID, candidate.ClusterID, candidate.Workload, candidate.Namespace, candidate.Name, string(candidate.Mode), int16(candidate.DefAction), direction, string(candidate.Rules), candidate.CreatedBy))
		if err != nil {
			return nil, err
		}
		return got, s.appendLegacyPolicyAudit(ctx, tx, audit.ActionPolicyCreate, nil, got, candidate.CreatedBy, requestID)
	})
	if err != nil {
		return nil, err
	}
	*p = *saved
	return saved, nil
}

func legacyPolicyPatch(before *RuntimePolicy, req UpdatePolicyRequest) RuntimePolicy {
	after := *before
	if req.Rules != nil {
		after.Rules = *req.Rules
	}
	if req.DefAction != nil {
		after.DefAction = *req.DefAction
	}
	if req.ApplyDir != nil {
		after.ApplyDir = *req.ApplyDir
	}
	if req.Name != nil {
		after.Name = *req.Name
	}
	return after
}

func (s *RuntimePolicyStore) updateLegacyPolicy(ctx context.Context, org, id uuid.UUID, req UpdatePolicyRequest, by uuid.UUID, requestID string) (*RuntimePolicy, error) {
	return s.legacyPolicyTransaction(ctx, func(tx pgx.Tx) (*RuntimePolicy, error) {
		before, err := lockLegacyPolicy(ctx, tx, org, id)
		if err != nil {
			return nil, err
		}
		after := legacyPolicyPatch(before, req)
		direction, err := policyDatabaseDirection(&after)
		if err != nil {
			return nil, err
		}
		got, err := scanPolicy(tx.QueryRow(ctx, `UPDATE runtime_policies SET rules=$1::jsonb,def_action=$2,apply_dir=$3,name=$4,updated_by=$5,version=version+1,updated_at=NOW() WHERE id=$6 AND org_id=$7 RETURNING `+policySelectCols,
			string(after.Rules), int16(after.DefAction), direction, after.Name, by, id, org))
		if err != nil {
			return nil, err
		}
		return got, s.appendLegacyPolicyAudit(ctx, tx, audit.ActionPolicyUpdate, before, got, &by, requestID)
	})
}

func (s *RuntimePolicyStore) setLegacyPolicyMode(ctx context.Context, org, id uuid.UUID, mode PolicyMode, by uuid.UUID, system bool, requestID string) (*RuntimePolicy, error) {
	if !mode.Valid() {
		return nil, fmt.Errorf("invalid mode %q", mode)
	}
	return s.legacyPolicyTransaction(ctx, func(tx pgx.Tx) (*RuntimePolicy, error) {
		before, err := lockLegacyPolicy(ctx, tx, org, id)
		if err != nil {
			return nil, err
		}
		after, err := scanPolicy(tx.QueryRow(ctx, `UPDATE runtime_policies SET mode=$1,updated_by=$2 WHERE id=$3 AND org_id=$4 RETURNING `+policySelectCols, string(mode), by, id, org))
		if err != nil {
			return nil, err
		}
		actor := &by
		if system {
			actor = nil
		}
		return after, s.appendLegacyPolicyAudit(ctx, tx, legacyPolicyModeAction(before.Mode, after.Mode, system), before, after, actor, requestID)
	})
}

func legacyPolicyModeAction(before, after PolicyMode, system bool) string {
	switch {
	case after == PolicyModeDisabled:
		return audit.ActionPolicyDisable
	case before == PolicyModeMonitor && after == PolicyModeEnforce:
		return audit.ActionPolicyPromote
	case before == PolicyModeEnforce && after == PolicyModeMonitor && system:
		return audit.ActionPolicyAutoRollback
	case before == PolicyModeEnforce && after == PolicyModeMonitor:
		return audit.ActionPolicyDemote
	default:
		return audit.ActionPolicyUpdate
	}
}

func (s *RuntimePolicyStore) deleteLegacyPolicy(ctx context.Context, org, id uuid.UUID, by *uuid.UUID, requestID string) error {
	_, err := s.legacyPolicyTransaction(ctx, func(tx pgx.Tx) (*RuntimePolicy, error) {
		before, err := lockLegacyPolicy(ctx, tx, org, id)
		if err != nil {
			return nil, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM runtime_policies WHERE id=$1 AND org_id=$2`, id, org)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, errLegacyPolicyNotFound
		}
		return nil, s.appendLegacyPolicyAudit(ctx, tx, audit.ActionPolicyDelete, before, nil, by, requestID)
	})
	return err
}

func legacyPolicyAuditPayload(p *RuntimePolicy) any {
	if p == nil {
		return nil
	}
	snap := snapshot(p)
	return map[string]any{"id": snap.ID, "cluster_id": p.ClusterID, "workload": snap.Workload, "namespace": snap.Namespace, "name": snap.Name, "mode": snap.Mode, "rule_count": snap.RuleCount, "version": snap.Version, "revision": p.Revision}
}

func (s *RuntimePolicyStore) appendLegacyPolicyAudit(ctx context.Context, tx pgx.Tx, action string, before, after *RuntimePolicy, actor *uuid.UUID, requestID string) error {
	if s.auditLog == nil {
		return nil
	}
	target := before
	if after != nil {
		target = after
	}
	_, _, err := s.auditLog.LogInTx(ctx, tx, audit.Event{OrgID: &target.OrgID, ActorID: actor, Action: action, TargetKind: audit.TargetKindPolicy, TargetID: target.ID.String(), Before: legacyPolicyAuditPayload(before), After: legacyPolicyAuditPayload(after), RequestID: requestID})
	return err
}

// ptrSnap remains available to existing policy generation callers; legacy CRUD
// uses transaction-bound payloads with explicit cluster and revision metadata.
func ptrSnap(p *RuntimePolicy) *audit.PolicySnapshot {
	if p == nil {
		return nil
	}
	snap := snapshot(p)
	return &snap
}
