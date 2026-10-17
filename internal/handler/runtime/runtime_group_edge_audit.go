package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

var errEdgeCompletionAudit = errors.New("required edge completion audit unavailable")

type edgeAuditTxWriter func(context.Context, pgx.Tx, audit.Event) error

type edgeMutationAudit struct {
	actor     *uuid.UUID
	requestID string
	write     edgeAuditTxWriter
}

// Explicit nil policy loggers remain supported by isolated store tests. Server
// routes and the membership worker both supply the configured policy logger.
// HTTP never falls back to this optional path: its completion writer is required.
func (s *GroupEdgeStore) completionAudit(by *uuid.UUID) edgeMutationAudit {
	result := edgeMutationAudit{actor: by}
	if s.pol != nil && s.pol.auditLog != nil {
		result.write = func(ctx context.Context, tx pgx.Tx, event audit.Event) error {
			_, _, err := s.pol.auditLog.LogInTx(ctx, tx, event)
			return err
		}
	}
	return result
}

func (h *GroupEdgesHTTP) completionAudit(r *http.Request, sub authctx.Subject) edgeMutationAudit {
	writer := h.auditTxWriter
	if writer == nil {
		writer = func(context.Context, pgx.Tx, audit.Event) error { return errEdgeCompletionAudit }
	}
	return edgeMutationAudit{actor: &sub.UserID, requestID: requestIDFrom(r), write: writer}
}

func (a edgeMutationAudit) append(ctx context.Context, tx pgx.Tx, org uuid.UUID, kind, id, action string, before, after any) error {
	if a.write == nil {
		return nil
	}
	err := a.write(ctx, tx, audit.Event{OrgID: &org, ActorID: a.actor, Action: action, TargetKind: kind, TargetID: id, Before: before, After: after, RequestID: a.requestID})
	if err != nil {
		return errors.Join(errEdgeCompletionAudit, err)
	}
	return nil
}

func edgeSnapshot(row *GroupEdgeRow) any {
	if row == nil {
		return nil
	}
	return *row
}

func (a edgeMutationAudit) upsert(ctx context.Context, tx pgx.Tx, org uuid.UUID, before *GroupEdgeRow, after GroupEdgeRow, expansion *ExpandResult) error {
	if err := a.append(ctx, tx, org, "group_rule_edge", after.ID.String(), "group_rule_edge.upsert", edgeSnapshot(before), after); err != nil {
		return err
	}
	if expansion != nil {
		return a.expand(ctx, tx, org, after, *expansion)
	}
	return nil
}

func (a edgeMutationAudit) expand(ctx context.Context, tx pgx.Tx, org uuid.UUID, row GroupEdgeRow, result ExpandResult) error {
	return a.append(ctx, tx, org, "group_rule_edge", row.ID.String(), "group_rule_edge.expand", row, map[string]any{"cluster_id": row.ClusterID, "expansion": result})
}

func edgeSnapshotTx(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (*GroupEdgeRow, error) {
	if id == uuid.Nil {
		return nil, nil
	}
	row, err := scanGroupEdge(tx.QueryRow(ctx, `SELECT id,cluster_id,from_group,to_group,ports,mode,comment,updated_at FROM group_rule_edges WHERE id=$1 AND org_id=$2 FOR UPDATE`, id, org))
	return &row, err
}

// A transport error during Commit cannot prove whether the server committed.
// Keep that uncertainty separate from failures before the commit was attempted.
type edgeCommitFailure struct{ cause error }

func (e edgeCommitFailure) Error() string { return e.cause.Error() }
func (e edgeCommitFailure) Unwrap() error { return e.cause }

func commitEdgeTransaction(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return edgeCommitFailure{cause: err}
	}
	return nil
}

// Failure receipts follow the transaction's cleanup. A failed response is not
// proof of rollback when the database's commit acknowledgement was lost.
func (h *GroupEdgesHTTP) mutationFailed(r *http.Request, sub authctx.Subject, targetID string, err error, actions ...string) {
	outcome := edgeFailureOutcome(err)
	for _, action := range actions {
		_ = h.writeAudit(r, sub, action+"_failed", targetID, nil, outcome)
	}
}

func edgeFailureOutcome(err error) map[string]any {
	var unconfirmed edgeCommitFailure
	if errors.As(err, &unconfirmed) {
		return map[string]any{"commit_status": "unknown", "reason": "commit_unconfirmed"}
	}
	reason := "mutation_rejected"
	if errors.Is(err, errEdgeCompletionAudit) {
		reason = "audit_unavailable"
	}
	return map[string]any{"committed": false, "reason": reason}
}

// A natural-key lock also covers the row's absence. Concurrent first upserts
// must observe the first committed edge before deciding whether to retract its
// old policies and before recording the actual previous edge configuration.
func lockEdgeForUpsertTx(ctx context.Context, tx pgx.Tx, org, cluster uuid.UUID, e netpolicy.GroupEdge, ports []byte) (*GroupEdgeRow, bool, error) {
	key, err := json.Marshal([4]string{org.String(), cluster.String(), e.FromGroup, e.ToGroup})
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,471916859))`, string(key)); err != nil {
		return nil, false, err
	}
	var id uuid.UUID
	var samePorts bool
	err = tx.QueryRow(ctx, `SELECT id,ports=$5::jsonb FROM group_rule_edges WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3 AND to_group=$4 FOR UPDATE`, org, cluster, e.FromGroup, e.ToGroup, string(ports)).Scan(&id, &samePorts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	before, err := edgeSnapshotTx(ctx, tx, org, id)
	return before, samePorts, err
}

func (r *GroupMembershipReconciler) auditMembershipTx(ctx context.Context, tx pgx.Tx, org, id uuid.UUID, cluster *uuid.UUID, name string, before, after []string) error {
	completion := r.edges.completionAudit(nil)
	snapshot := func(members []string) any {
		return map[string]any{"cluster_id": cluster, "name": name, "members": members}
	}
	return completion.append(ctx, tx, org, "group", id.String(), "group.membership.refresh", snapshot(before), snapshot(after))
}

func (r *GroupMembershipReconciler) expandMembershipEdgesTx(ctx context.Context, tx pgx.Tx, org uuid.UUID, edges []GroupEdgeRow) error {
	for _, edge := range edges {
		result, current, err := r.edges.expandTx(ctx, tx, org, edge.ClusterID, netpolicy.GroupEdge{ID: edge.ID.String(), FromGroup: edge.FromGroup, ToGroup: edge.ToGroup, Ports: edge.Ports, Mode: edge.Mode, Comment: edge.Comment}, nil)
		if err != nil {
			return err
		}
		if err := r.edges.completionAudit(nil).expand(ctx, tx, org, *current, result); err != nil {
			return err
		}
	}
	return nil
}
