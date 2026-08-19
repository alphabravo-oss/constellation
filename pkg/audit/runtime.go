// Wave A5: convenience wrappers for runtime_policies audit events.
//
// Every state transition on a runtime policy lands a hash-chained
// audit_events row via the same Logger that handles findings.suppress,
// scan-token rotations, etc. The action vocabulary lives here so callers
// don't sprinkle the strings inline.
//
// The before/after payload is a sparse snapshot of the policy row — enough
// to reconstruct what changed without copying the full rule list every
// time a mode toggles. The full rules list lives on the runtime_policies
// row itself; auditors who need to replay a historic state pull it from
// audit_events via target_id + the policy's version field.
package audit

import (
	"context"

	"github.com/google/uuid"
)

// Action constants for runtime policies. Keep the string values stable —
// they're indexed into audit_events.action and referenced by downstream
// compliance reports.
const (
	ActionPolicyCreate       = "runtime.policy.create"
	ActionPolicyUpdate       = "runtime.policy.update"
	ActionPolicyPromote      = "runtime.policy.promote"       // mode → enforce
	ActionPolicyDemote       = "runtime.policy.demote"        // mode → monitor (operator-initiated)
	ActionPolicyDisable      = "runtime.policy.disable"       // mode → disabled
	ActionPolicyDelete       = "runtime.policy.delete"
	ActionPolicyAutoRollback = "runtime.policy.auto_rollback" // mode → monitor (system-initiated)
)

// TargetKindPolicy is the value the `target_kind` column gets for any
// runtime-policy event. Distinguishes from `compliance_policy`, etc.
const TargetKindPolicy = "runtime_policy"

// PolicySnapshot is the trimmed shape stored in the before/after JSONB
// columns. It's deliberately small: full rules are in runtime_policies, and
// duplicating them on every mode flip would bloat audit_events.
type PolicySnapshot struct {
	ID         uuid.UUID `json:"id"`
	Workload   string    `json:"workload"`
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	Mode       string    `json:"mode"`
	RuleCount  int       `json:"rule_count"`
	Version    int64     `json:"version"`
}

// LogPolicyEvent is the underlying writer. Specific helpers below pick the
// right Action string and pass through to here. Errors are surfaced so
// callers can decide whether a failed audit write should fail the
// originating operation (default: log and continue — better to lose an
// audit row than refuse a policy edit, but the caller chooses).
func (l *Logger) LogPolicyEvent(ctx context.Context, orgID uuid.UUID, actor *uuid.UUID,
	action string, before, after *PolicySnapshot, requestID string) error {
	ev := Event{
		OrgID:      &orgID,
		ActorID:    actor,
		Action:     action,
		TargetKind: TargetKindPolicy,
		RequestID:  requestID,
	}
	// Use whichever side has an ID — both should agree when both are set.
	if after != nil {
		ev.TargetID = after.ID.String()
		ev.After = after
	}
	if before != nil {
		if ev.TargetID == "" {
			ev.TargetID = before.ID.String()
		}
		ev.Before = before
	}
	_, _, err := l.Log(ctx, ev)
	return err
}

// LogPolicyCreate records a newly-created policy. before is nil.
func (l *Logger) LogPolicyCreate(ctx context.Context, orgID uuid.UUID, actor *uuid.UUID,
	after PolicySnapshot, requestID string) error {
	return l.LogPolicyEvent(ctx, orgID, actor, ActionPolicyCreate, nil, &after, requestID)
}

// LogPolicyModeChange picks the right action string for a mode transition:
// monitor→enforce = promote, enforce→monitor = demote (or auto_rollback if
// system-initiated), anything→disabled = disable. `system` true means the
// auto-rollback watcher made the change, not an operator.
func (l *Logger) LogPolicyModeChange(ctx context.Context, orgID uuid.UUID, actor *uuid.UUID,
	before, after PolicySnapshot, system bool, requestID string) error {
	var action string
	switch {
	case after.Mode == "disabled":
		action = ActionPolicyDisable
	case before.Mode == "monitor" && after.Mode == "enforce":
		action = ActionPolicyPromote
	case before.Mode == "enforce" && after.Mode == "monitor" && system:
		action = ActionPolicyAutoRollback
	case before.Mode == "enforce" && after.Mode == "monitor":
		action = ActionPolicyDemote
	default:
		// Catchall — record as a generic update.
		action = ActionPolicyUpdate
	}
	return l.LogPolicyEvent(ctx, orgID, actor, action, &before, &after, requestID)
}

// LogPolicyDelete records a policy deletion. after is nil.
func (l *Logger) LogPolicyDelete(ctx context.Context, orgID uuid.UUID, actor *uuid.UUID,
	before PolicySnapshot, requestID string) error {
	return l.LogPolicyEvent(ctx, orgID, actor, ActionPolicyDelete, &before, nil, requestID)
}
