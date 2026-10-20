package runtime

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// Expansion audits the final edge-marked row, not the intermediate learned
// insert. The surrounding edge transaction owns all rows and audit events.
func (s *GroupEdgeStore) expandMemberPolicyTx(ctx context.Context, tx pgx.Tx, policy *RuntimePolicy, flows []netpolicy.Flow, opts netpolicy.BuildDPRulesOptions, edgeID uuid.UUID, by *uuid.UUID) (*RuntimePolicy, bool, error) {
	rules, defAction, applyDir, err := netpolicy.BuildDPRules(policy.Workload, flows, opts)
	if err != nil || len(rules) == 0 {
		return nil, false, err
	}
	policy.DefAction, policy.ApplyDir = defAction, applyDir
	before, err := lockLearnedPolicy(ctx, tx, policy)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	if err == nil {
		if _, owned, err := splitEdgeRules(before.Rules, edgeID); err != nil || !owned {
			return nil, false, errEdgePolicyOwnership
		}
	}
	id, created, err := s.pol.upsertLearnedPolicyTx(ctx, tx, policy, rules, by)
	if err != nil {
		return nil, false, err
	}
	// A policy that appeared after the ownership precheck was not proven to
	// belong to this edge. Roll back the speculative merge, preserving the
	// concurrent author's policy and requiring an explicit retry.
	if !created && before == nil {
		return nil, false, errEdgePolicyOwnership
	}
	if err := markEdgeRules(ctx, tx, id, policy.OrgID, edgeID); err != nil {
		return nil, false, err
	}
	after, err := scanPolicy(tx.QueryRow(ctx, `SELECT `+policySelectCols+` FROM runtime_policies WHERE id=$1 AND org_id=$2`, id, policy.OrgID))
	if err != nil {
		return nil, false, err
	}
	action := audit.ActionPolicyUpdate
	if created {
		action = audit.ActionPolicyCreate
		before = nil
	}
	if err := s.pol.appendLegacyPolicyAudit(ctx, tx, action, before, after, by, ""); err != nil {
		return nil, false, err
	}
	return after, created, nil
}

func (s *GroupEdgeStore) auditRetractedEdgePoliciesTx(ctx context.Context, tx pgx.Tx, by *uuid.UUID, removed []*RuntimePolicy) error {
	if s.pol == nil {
		return nil
	}
	for _, policy := range removed {
		if err := requireLegacyPolicyCluster(ctx, tx, policy.OrgID, policy.ClusterID); err != nil {
			return err
		}
		if err := s.pol.appendLegacyPolicyAudit(ctx, tx, audit.ActionPolicyDelete, policy, nil, by, ""); err != nil {
			return err
		}
	}
	return nil
}

func (s *GroupEdgeStore) retractAndAuditEdgePoliciesTx(ctx context.Context, tx pgx.Tx, org, cluster, id uuid.UUID, mode string, edge netpolicy.GroupEdge, by *uuid.UUID) ([]*RuntimePolicy, error) {
	removed, err := retractEdgePoliciesTx(ctx, tx, org, cluster, id, mode, edge)
	if err != nil {
		return nil, err
	}
	return removed, s.auditRetractedEdgePoliciesTx(ctx, tx, by, removed)
}
