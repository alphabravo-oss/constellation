// Wave A2: storage shape for per-workload dp policies.
//
// The CRUD handlers themselves land in Wave B1 (UI). This file defines the
// row type + read helpers used by:
//   - the runtime-agent's policy-sync goroutine (Wave A3)
//   - the audit log + state-machine machinery (Wave A5)
//   - the policy-authoring UI (Wave B1)
//
// The wire format pushed to dp lives in internal/runtime/dp.WorkloadPolicy;
// every RuntimePolicy.Rules JSONB array is a slice of dp.PolicyRule once
// decoded. We keep the rules opaque to JSONB at the storage layer so the
// rule shape can evolve (eg. adding L7 fields) without a schema migration.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// PolicyMode mirrors the CHECK constraint on runtime_policies.mode.
type PolicyMode string

const (
	PolicyModeMonitor  PolicyMode = "monitor"
	PolicyModeEnforce  PolicyMode = "enforce"
	PolicyModeDisabled PolicyMode = "disabled"
)

// Valid returns true for the three mode values the schema accepts.
func (m PolicyMode) Valid() bool {
	switch m {
	case PolicyModeMonitor, PolicyModeEnforce, PolicyModeDisabled:
		return true
	}
	return false
}

// RuntimePolicy is one row in runtime_policies. Rules is JSONB on disk;
// callers that want the typed shape call Decode() to get a dp.PolicyRule
// slice ready to pass to dp.Supervisor.PushPolicy.
//
// DPPolicyID (Wave A6) is the numeric ID dp sees on the wire. Allocated by
// the runtime_policies_dp_id_seq Postgres sequence on insert; the agent
// stamps every rule it pushes to dp with this value so the policy_id field
// echoed in DPMsgConnect → network_flows.policy_id joins back to this row.
type RuntimePolicy struct {
	ID         uuid.UUID       `json:"id"`
	DPPolicyID int64           `json:"dp_policy_id"`
	OrgID      uuid.UUID       `json:"org_id"`
	ClusterID  uuid.UUID       `json:"cluster_id"`
	Workload   string          `json:"workload"`
	Namespace  string          `json:"namespace"`
	Name       string          `json:"name"`
	Mode       PolicyMode      `json:"mode"`
	DefAction  uint8           `json:"def_action"`
	ApplyDir   int             `json:"apply_dir"`
	Rules      json.RawMessage `json:"rules"`
	Revision   string          `json:"revision"`
	Version    int64           `json:"version"`
	CreatedBy  *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedBy  *uuid.UUID      `json:"updated_by,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// DecodeRules unmarshals the JSONB rules column into a slice of dp.PolicyRule.
// Returns an empty slice for an empty/null rules column.
func (p *RuntimePolicy) DecodeRules() ([]*dp.PolicyRule, error) {
	if len(p.Rules) == 0 || string(p.Rules) == "null" {
		return nil, nil
	}
	var out []*dp.PolicyRule
	if err := json.Unmarshal(p.Rules, &out); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	for _, rule := range out {
		if rule == nil || rule.Action > dp.PolicyActionDeny {
			return nil, errors.New("rules must contain supported non-null dataplane rules")
		}
	}
	return out, nil
}

// EncodeRules sets the Rules column from a typed slice. Round-trip-safe:
// the database-side JSONB normalises whitespace but preserves order and types.
func (p *RuntimePolicy) EncodeRules(rules []*dp.PolicyRule) error {
	if rules == nil {
		p.Rules = json.RawMessage("[]")
		return nil
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("encode rules: %w", err)
	}
	p.Rules = b
	return nil
}

// ToWorkloadPolicy builds the dp-bound shape from a stored row + the set
// of MACs the agent has identified for this workload. The agent's
// policy-sync goroutine calls this just before dp.Supervisor.PushPolicy.
//
// The mode-to-action mapping happens here: monitor mode rewrites every
// `deny`-action rule to `violate` (logged but allowed); enforce mode
// keeps `deny`. `disabled` mode returns an empty rule list so dp clears
// the workload's table.
func (p *RuntimePolicy) ToWorkloadPolicy(macs []string) (*dp.WorkloadPolicy, error) {
	wireID, err := policyWireID(p.DPPolicyID)
	if err != nil {
		return nil, err
	}
	rules, err := p.DecodeRules()
	if err != nil {
		return nil, err
	}
	if p.Mode == PolicyModeDisabled {
		return &dp.WorkloadPolicy{
			WorkloadID: p.Workload,
			Mode:       string(p.Mode),
			DefAction:  p.DefAction,
			ApplyDir:   p.ApplyDir,
			MACs:       macs,
		}, nil
	}
	if p.Mode == PolicyModeMonitor {
		// Demote every deny → violate so dp logs but doesn't drop.
		for _, r := range rules {
			if r.Action == dp.PolicyActionDeny {
				r.Action = dp.PolicyActionViolate
			}
		}
	}
	// Wave A6: stamp every rule with the policy's dp_policy_id so the wire
	// PolicyRule.ID echoes back through DPMsgConnect.PolicyId →
	// network_flows.policy_id, letting the rollback watcher join on it.
	// We deliberately overwrite any caller-supplied rule.ID — the runtime
	// policy ID is the only stable bridge between our UUID + dp's uint32.
	if p.DPPolicyID > 0 {
		for _, r := range rules {
			r.ID = wireID
		}
	}
	return &dp.WorkloadPolicy{
		WorkloadID: p.Workload,
		Mode:       string(p.Mode),
		DefAction:  p.DefAction,
		ApplyDir:   p.ApplyDir,
		MACs:       macs,
		Rules:      rules,
	}, nil
}

// RuntimePolicyStore is the data-layer wrapper. CRUD operations + the
// agent-side "list everything I need to push to dp" query. Every mutation
// writes a hash-chained audit_events row via the supplied audit.Logger so
// compliance can reconstruct any historic state — see pkg/audit/runtime.go.
type RuntimePolicyStore struct {
	db       *db.DB
	auditLog *audit.Logger
}

// NewRuntimePolicyStore — auditLog may be nil in tests; production callers
// pass the same Logger threaded through the server.
func NewRuntimePolicyStore(d *db.DB, auditLog *audit.Logger) *RuntimePolicyStore {
	return &RuntimePolicyStore{db: d, auditLog: auditLog}
}

// snapshot pulls the trimmed shape audit.PolicySnapshot wants.
func snapshot(p *RuntimePolicy) audit.PolicySnapshot {
	rc := 0
	if rules, err := p.DecodeRules(); err == nil {
		rc = len(rules)
	}
	return audit.PolicySnapshot{
		ID: p.ID, Workload: p.Workload, Namespace: p.Namespace, Name: p.Name,
		Mode: string(p.Mode), RuleCount: rc, Version: p.Version,
	}
}

// Insert persists a new policy. Returns the generated ID. Validates mode +
// rules JSON before writing so a bad input fails fast with a 4xx-shaped error.
// Writes a runtime.policy.create audit row.
func (s *RuntimePolicyStore) Insert(ctx context.Context, p *RuntimePolicy, requestID string) (uuid.UUID, error) {
	got, err := s.insertLegacyPolicy(ctx, p, requestID)
	if err != nil {
		return uuid.Nil, err
	}
	return got.ID, nil
}

// SetMode flips a policy's mode. The bump-version trigger handles the
// version bump and updated_at automatically. Writes one of the
// runtime.policy.{promote,demote,disable,auto_rollback} audit actions
// depending on the transition. `system=true` means the call came from the
// auto-rollback watcher rather than an operator (demote audits as
// auto_rollback in that case).
func (s *RuntimePolicyStore) SetMode(ctx context.Context, orgID, id uuid.UUID,
	mode PolicyMode, by uuid.UUID, system bool, requestID string) error {
	_, err := s.setLegacyPolicyMode(ctx, orgID, id, mode, by, system, requestID)
	return err
}

// policySelectCols is the canonical column list used by Get / List / etc.
// Kept in one place so adding a column updates every caller in lockstep.
const policySelectCols = `
  id, dp_policy_id, org_id, cluster_id, workload, namespace, name, mode,
  def_action, apply_dir, rules, version, created_by, created_at,
  updated_by, updated_at`

// Get fetches one policy by id, scoped to the org for safety.
func (s *RuntimePolicyStore) Get(ctx context.Context, orgID, id uuid.UUID) (*RuntimePolicy, error) {
	row := s.db.Pool().QueryRow(ctx, `SELECT `+policySelectCols+
		` FROM runtime_policies WHERE id = $1 AND org_id = $2`, id, orgID)
	return scanPolicy(row)
}

// ListInventoryForCluster includes disabled policies so operators can review,
// edit and re-enable them. The agent distribution method below remains filtered.
func (s *RuntimePolicyStore) ListInventoryForCluster(ctx context.Context, orgID, clusterID uuid.UUID) ([]*RuntimePolicy, error) {
	rows, err := s.db.Pool().Query(ctx, `SELECT `+policySelectCols+` FROM runtime_policies WHERE org_id=$1 AND cluster_id=$2 ORDER BY namespace,name,id`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*RuntimePolicy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListForCluster returns every policy that should drive dp on the given
// cluster — mode in (monitor, enforce). Ordered by namespace then name
// for deterministic agent-side reconcile.
func (s *RuntimePolicyStore) ListForCluster(ctx context.Context, orgID, clusterID uuid.UUID) ([]*RuntimePolicy, error) {
	rows, err := s.db.Pool().Query(ctx, `SELECT `+policySelectCols+
		` FROM runtime_policies
 WHERE org_id = $1 AND cluster_id = $2 AND mode <> 'disabled'
 ORDER BY namespace, name`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*RuntimePolicy, 0, 16)
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpsertLearnedPolicy inserts p (with learned-tagged rules) when no policy with
// its natural key exists, or non-destructively MERGEs the learned rules into the
// existing row — preserving user/fed-authored rules (P2-2). Mode is only set on
// INSERT (always monitor for machine-seeded rows); an existing row's mode is
// never changed here, so re-expansion cannot re-arm or disarm enforcement.
// Returns the resulting policy ID.
func (s *RuntimePolicyStore) UpsertLearnedPolicy(ctx context.Context, p *RuntimePolicy, learned []*dp.PolicyRule, by *uuid.UUID) (uuid.UUID, error) {
	saved, _, err := s.applyLearnedPolicy(ctx, p, learned, by, "")
	if err != nil {
		return uuid.Nil, err
	}
	return saved.ID, nil
}

// GetByName fetches one policy by its natural key (org, cluster, workload,
// name), returning (nil, nil) when no such row exists. Used by the regenerate
// path to decide MERGE-vs-INSERT (P2-2).
func (s *RuntimePolicyStore) GetByName(ctx context.Context, orgID, clusterID uuid.UUID, workload, name string) (*RuntimePolicy, error) {
	row := s.db.Pool().QueryRow(ctx, `SELECT `+policySelectCols+
		` FROM runtime_policies
		 WHERE org_id = $1 AND cluster_id = $2 AND workload = $3 AND name = $4`,
		orgID, clusterID, workload, name)
	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

// scanPolicy reads one runtime_policies row out of either pgx.Row or
// pgx.Rows — both satisfy the rowScanner interface declared elsewhere
// in this package (see api_tokens.go).
func scanPolicy(s rowScanner) (*RuntimePolicy, error) {
	var p RuntimePolicy
	var mode string
	var defAct, applyDir int16
	var rulesText string
	if err := s.Scan(
		&p.ID, &p.DPPolicyID, &p.OrgID, &p.ClusterID, &p.Workload, &p.Namespace, &p.Name, &mode,
		&defAct, &applyDir, &rulesText, &p.Version, &p.CreatedBy, &p.CreatedAt,
		&p.UpdatedBy, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	p.Mode = PolicyMode(mode)
	p.Revision = strconv.FormatInt(p.Version, 10)
	if defAct < 0 || defAct > 255 {
		return nil, errors.New("stored policy action exceeds the wire range")
	}
	p.DefAction = uint8(defAct)
	p.ApplyDir = int(applyDir)
	p.Rules = json.RawMessage(rulesText)
	return &p, nil
}

// Delete removes one policy. Org-scoped. Writes a runtime.policy.delete
// audit row using a snapshot taken before the DELETE.
func (s *RuntimePolicyStore) Delete(ctx context.Context, orgID, id uuid.UUID, by *uuid.UUID, requestID string) error {
	return s.deleteLegacyPolicy(ctx, orgID, id, by, requestID)
}
