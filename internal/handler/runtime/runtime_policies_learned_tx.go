package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

type learnedPolicyMutation struct {
	Before, After *RuntimePolicy
	Created       bool
}

func lockLearnedPolicy(ctx context.Context, tx pgx.Tx, p *RuntimePolicy) (*RuntimePolicy, error) {
	return scanPolicy(tx.QueryRow(ctx, `SELECT `+policySelectCols+` FROM runtime_policies
 WHERE org_id=$1 AND cluster_id=$2 AND workload=$3 AND name=$4 FOR UPDATE`, p.OrgID, p.ClusterID, p.Workload, p.Name))
}

// Row locks protect authored edits during regeneration. On a concurrent first
// insert, ON CONFLICT waits for the other writer; the next READ COMMITTED
// statement locks and merges that committed row instead of overwriting it.
func (s *RuntimePolicyStore) persistLearnedPolicyTx(ctx context.Context, tx pgx.Tx, p *RuntimePolicy, learned []*dp.PolicyRule, by *uuid.UUID) (learnedPolicyMutation, error) {
	if err := requireLegacyPolicyCluster(ctx, tx, p.OrgID, p.ClusterID); err != nil {
		return learnedPolicyMutation{}, err
	}
	before, err := lockLearnedPolicy(ctx, tx, p)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return learnedPolicyMutation{}, err
	}
	tagged := netpolicy.Tag(learned, netpolicy.CfgTypeLearned)
	if errors.Is(err, pgx.ErrNoRows) {
		candidate := *p
		_, created, err := insertLearnedPolicyTx(ctx, tx, &candidate, tagged, by)
		if err != nil {
			return learnedPolicyMutation{}, err
		}
		if created {
			return learnedPolicyMutation{After: &candidate, Created: true}, nil
		}
		before, err = lockLearnedPolicy(ctx, tx, p)
		if err != nil {
			return learnedPolicyMutation{}, err
		}
	}
	after, err := mergeLearnedPolicyTx(ctx, tx, before, tagged, by)
	return learnedPolicyMutation{Before: before, After: after}, err
}

// The edge-expansion caller owns the outer transaction and audits only after
// markEdgeRules has persisted its final provenance/version. Do not audit here.
func (s *RuntimePolicyStore) upsertLearnedPolicyTx(ctx context.Context, tx pgx.Tx, policy *RuntimePolicy, learned []*dp.PolicyRule, by *uuid.UUID) (uuid.UUID, bool, error) {
	result, err := s.persistLearnedPolicyTx(ctx, tx, policy, learned, by)
	if err != nil {
		return uuid.Nil, false, err
	}
	*policy = *result.After
	return policy.ID, result.Created, nil
}

func insertLearnedPolicyTx(ctx context.Context, tx pgx.Tx, policy *RuntimePolicy, tagged []*netpolicy.SourcedRule, by *uuid.UUID) (uuid.UUID, bool, error) {
	if err := requireLegacyPolicyCluster(ctx, tx, policy.OrgID, policy.ClusterID); err != nil {
		return uuid.Nil, false, err
	}
	candidate := *policy
	if candidate.Mode == "" {
		candidate.Mode = PolicyModeMonitor
	}
	if !candidate.Mode.Valid() || candidate.Workload == "" || candidate.Namespace == "" || candidate.Name == "" {
		return uuid.Nil, false, errBadRequest("invalid learned policy")
	}
	encoded, err := json.Marshal(tagged)
	if err != nil {
		return uuid.Nil, false, err
	}
	candidate.Rules = encoded
	direction, err := policyDatabaseDirection(&candidate)
	if err != nil {
		return uuid.Nil, false, err
	}
	saved, err := scanPolicy(tx.QueryRow(ctx, `INSERT INTO runtime_policies
 (org_id,cluster_id,workload,namespace,name,mode,def_action,apply_dir,rules,created_by,updated_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$10)
 ON CONFLICT(org_id,cluster_id,workload,name) DO NOTHING RETURNING `+policySelectCols,
		candidate.OrgID, candidate.ClusterID, candidate.Workload, candidate.Namespace, candidate.Name, string(candidate.Mode), int16(candidate.DefAction), direction, string(candidate.Rules), by))
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	*policy = *saved
	return saved.ID, true, nil
}

func mergeLearnedPolicyTx(ctx context.Context, tx pgx.Tx, before *RuntimePolicy, tagged []*netpolicy.SourcedRule, by *uuid.UUID) (*RuntimePolicy, error) {
	prior, err := netpolicy.DecodeSourced(before.Rules)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(netpolicy.MergeRules(prior, tagged))
	if err != nil {
		return nil, err
	}
	candidate := *before
	candidate.Rules = encoded
	if _, err := policyDatabaseDirection(&candidate); err != nil {
		return nil, err
	}
	return scanPolicy(tx.QueryRow(ctx, `UPDATE runtime_policies SET rules=$1::jsonb,updated_by=$2
 WHERE id=$3 AND org_id=$4 RETURNING `+policySelectCols, string(encoded), by, before.ID, before.OrgID))
}

func (s *RuntimePolicyStore) applyLearnedPolicy(ctx context.Context, p *RuntimePolicy, learned []*dp.PolicyRule, by *uuid.UUID, requestID string) (*RuntimePolicy, bool, error) {
	candidate := *p
	candidate.Mode = PolicyModeMonitor // Auto-generation cannot promote a new policy.
	created := false
	saved, err := s.legacyPolicyTransaction(ctx, func(tx pgx.Tx) (*RuntimePolicy, error) {
		result, err := s.persistLearnedPolicyTx(ctx, tx, &candidate, learned, by)
		if err != nil {
			return nil, err
		}
		action := audit.ActionPolicyUpdate
		if result.Created {
			action = audit.ActionPolicyCreate
		}
		created = result.Created
		return result.After, s.appendLegacyPolicyAudit(ctx, tx, action, result.Before, result.After, by, requestID)
	})
	if err != nil {
		return nil, false, err
	}
	*p = *saved
	return saved, created, nil
}

func writeGeneratedPolicyError(w http.ResponseWriter, err error) {
	var invalid errBadRequest
	switch {
	case errors.As(err, &invalid):
		jsonError(w, http.StatusBadRequest, invalid.Error())
	case errors.Is(err, errLegacyPolicyClusterNotFound):
		jsonError(w, http.StatusNotFound, "cluster not found")
	default:
		jsonError(w, http.StatusInternalServerError, "policy generation failed")
	}
}
