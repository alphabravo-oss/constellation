// P1-1: group→group rule edges (control-plane model + expansion).
//
// A GroupEdge (from_group → to_group : ports) is authored once and applies to
// every current and future member of both groups. Storage is group_rule_edges
// (migration 121); the `groups` table (owned by internal/handler/groups.go) is
// read-only here for membership resolution. Expansion turns an edge into
// concrete monitor-mode runtime_policies rows for each involved member workload,
// reusing the existing pkg/netpolicy expansion + BuildDPRules path — no new
// datapath primitive. Re-running Expand after a group-sync membership change is
// how "applies to future members" is honoured (live membership update).
//
// Discover/monitor edges expand to informational policies; protect edges expand
// to enforcing policies. Rows are tagged provenance=learned so a later
// regeneration merges non-destructively (P2-2).
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// GroupEdgeRow is one group_rule_edges row.
type GroupEdgeRow struct {
	ID        uuid.UUID            `json:"id"`
	ClusterID uuid.UUID            `json:"cluster_id"`
	FromGroup string               `json:"from_group"`
	ToGroup   string               `json:"to_group"`
	Ports     []netpolicy.PortSpec `json:"ports"`
	Mode      string               `json:"mode"`
	Comment   string               `json:"comment,omitempty"`
	UpdatedAt time.Time            `json:"updated_at"`
}

// GroupEdgeStore persists group_rule_edges and expands them to member rules.
type GroupEdgeStore struct {
	db  *db.DB
	pol *RuntimePolicyStore
}

var errEdgeClusterNotFound = errors.New("cluster not found")
var errEdgeNotFound = errors.New("edge not found")
var errEdgeGroupNotFound = errors.New("group not found in cluster")
var errEdgePolicyOwnership = errors.New("edge policy ownership cannot be verified")
var errEdgeExpandedMutation = errors.New("expanded edge mode or ports cannot change without a policy transition")

func (s *GroupEdgeStore) clusterExists(ctx context.Context, orgID, clusterID uuid.UUID) (bool, error) {
	var exists bool
	err := s.db.Pool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, clusterID, orgID).Scan(&exists)
	return exists, err
}

// NewGroupEdgeStore builds the edge store. It shares the runtime-policy store so
// expansion can upsert-merge the per-member policies.
func NewGroupEdgeStore(d *db.DB, pol *RuntimePolicyStore) *GroupEdgeStore {
	return &GroupEdgeStore{db: d, pol: pol}
}

// Upsert validates and persists an edge (create or replace by natural key).
func (s *GroupEdgeStore) Upsert(ctx context.Context, orgID, clusterID uuid.UUID, e netpolicy.GroupEdge, by *uuid.UUID) (GroupEdgeRow, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return GroupEdgeRow{}, err
	}
	defer tx.Rollback(ctx)
	row, err := s.upsertTx(ctx, tx, orgID, clusterID, e, by)
	if err != nil {
		return GroupEdgeRow{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return GroupEdgeRow{}, err
	}
	return row, nil
}

func (s *GroupEdgeStore) upsertTx(ctx context.Context, tx pgx.Tx, orgID, clusterID uuid.UUID, e netpolicy.GroupEdge, by *uuid.UUID) (GroupEdgeRow, error) {
	if err := e.Validate(); err != nil {
		return GroupEdgeRow{}, err
	}
	ports, err := json.Marshal(e.Ports)
	if err != nil {
		return GroupEdgeRow{}, err
	}
	var lockedOrgID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE`, orgID).Scan(&lockedOrgID); err != nil {
		return GroupEdgeRow{}, err
	}
	var lockedClusterID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM clusters WHERE id=$1 AND org_id=$2 FOR KEY SHARE`, clusterID, orgID).Scan(&lockedClusterID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return GroupEdgeRow{}, errEdgeClusterNotFound
		}
		return GroupEdgeRow{}, err
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE group_rule_edges IN ROW EXCLUSIVE MODE`); err != nil {
		return GroupEdgeRow{}, err
	}
	for _, name := range []string{e.FromGroup, e.ToGroup} {
		if name == "external" || name == "nodes" {
			continue
		}
		var groupID uuid.UUID
		err := tx.QueryRow(ctx, `
SELECT id FROM groups
 WHERE org_id = $1 AND name = $2 AND (cluster_id IS NULL OR cluster_id = $3)
 FOR KEY SHARE`, orgID, name, clusterID).Scan(&groupID)
		if errors.Is(err, pgx.ErrNoRows) {
			return GroupEdgeRow{}, fmt.Errorf("group %q does not exist in cluster: %w", name, errEdgeGroupNotFound)
		}
		if err != nil {
			return GroupEdgeRow{}, err
		}
	}
	var existingID uuid.UUID
	var existingMode string
	var samePorts bool
	err = tx.QueryRow(ctx, `SELECT id, mode, ports=$5::jsonb FROM group_rule_edges
 WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3 AND to_group=$4 FOR UPDATE`,
		orgID, clusterID, e.FromGroup, e.ToGroup, string(ports)).Scan(&existingID, &existingMode, &samePorts)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return GroupEdgeRow{}, err
	}
	if err == nil && (existingMode != e.Mode || !samePorts) {
		var expanded bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM runtime_policies
 WHERE org_id=$1 AND cluster_id=$2 AND name=$3)`, orgID, clusterID, edgePolicyName(e)).Scan(&expanded); err != nil {
			return GroupEdgeRow{}, err
		}
		if expanded {
			return GroupEdgeRow{}, errEdgeExpandedMutation
		}
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `
INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group, ports, mode, comment, created_by, updated_by)
VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$8)
ON CONFLICT (org_id, cluster_id, from_group, to_group) DO UPDATE
   SET ports = EXCLUDED.ports, mode = EXCLUDED.mode, comment = EXCLUDED.comment,
       updated_by = EXCLUDED.updated_by, updated_at = NOW()
RETURNING id`,
		orgID, clusterID, e.FromGroup, e.ToGroup, string(ports), e.Mode, e.Comment, by).Scan(&id)
	if err != nil {
		return GroupEdgeRow{}, err
	}
	row, err := scanGroupEdge(tx.QueryRow(ctx, `
SELECT id, cluster_id, from_group, to_group, ports, mode, comment, updated_at
  FROM group_rule_edges WHERE id = $1 AND org_id = $2`, id, orgID))
	if err != nil {
		return GroupEdgeRow{}, err
	}
	return row, nil
}

func (s *GroupEdgeStore) UpsertAndExpand(ctx context.Context, orgID, clusterID uuid.UUID, edge netpolicy.GroupEdge, by *uuid.UUID) (GroupEdgeRow, ExpandResult, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return GroupEdgeRow{}, ExpandResult{}, err
	}
	defer tx.Rollback(ctx)
	row, err := s.upsertTx(ctx, tx, orgID, clusterID, edge, by)
	if err != nil {
		return GroupEdgeRow{}, ExpandResult{}, err
	}
	edge.ID = row.ID.String()
	result, createdPolicies, err := s.expandTx(ctx, tx, orgID, clusterID, edge, by)
	if err != nil {
		return GroupEdgeRow{}, ExpandResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return GroupEdgeRow{}, ExpandResult{}, err
	}
	s.auditCreatedPolicies(ctx, orgID, by, createdPolicies)
	return row, result, nil
}

func (s *GroupEdgeStore) get(ctx context.Context, orgID, id uuid.UUID) (GroupEdgeRow, error) {
	row := s.db.Pool().QueryRow(ctx, `
SELECT id, cluster_id, from_group, to_group, ports, mode, comment, updated_at
  FROM group_rule_edges WHERE id = $1 AND org_id = $2`, id, orgID)
	return scanGroupEdge(row)
}

// List returns every edge for a cluster.
func (s *GroupEdgeStore) List(ctx context.Context, orgID, clusterID uuid.UUID) ([]GroupEdgeRow, error) {
	rows, err := s.db.Pool().Query(ctx, `
SELECT id, cluster_id, from_group, to_group, ports, mode, comment, updated_at
  FROM group_rule_edges WHERE org_id = $1 AND cluster_id = $2
 ORDER BY from_group, to_group`, orgID, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupEdgeRow
	for rows.Next() {
		e, err := scanGroupEdge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Delete retracts only policies whose rules are entirely owned by this edge.
// Mixed or legacy policies have ambiguous policy-level posture, so deletion
// refuses them rather than weakening authored enforcement or leaving stale rules.
func (s *GroupEdgeStore) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var lockedOrgID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE`, orgID).Scan(&lockedOrgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errEdgeNotFound
		}
		return err
	}
	row, err := scanGroupEdge(tx.QueryRow(ctx, `
SELECT id, cluster_id, from_group, to_group, ports, mode, comment, updated_at
  FROM group_rule_edges WHERE id=$1 AND org_id=$2 FOR UPDATE`, id, orgID))
	if errors.Is(err, pgx.ErrNoRows) {
		return errEdgeNotFound
	}
	if err != nil {
		return err
	}
	edge := netpolicy.GroupEdge{ID: row.ID.String(), FromGroup: row.FromGroup, ToGroup: row.ToGroup}
	policies, err := tx.Query(ctx, `SELECT `+policySelectCols+`
 FROM runtime_policies WHERE org_id=$1 AND cluster_id=$2 AND name=$3 FOR UPDATE`,
		orgID, row.ClusterID, edgePolicyName(edge))
	if err != nil {
		return err
	}
	var owned []*RuntimePolicy
	for policies.Next() {
		policy, err := scanPolicy(policies)
		if err != nil {
			policies.Close()
			return err
		}
		owned = append(owned, policy)
	}
	err = policies.Err()
	policies.Close()
	if err != nil {
		return err
	}
	expectedMode, posture := edgePolicyPosture(row.Mode)
	expectedDefault := uint8(dp.PolicyActionAllow)
	if posture.DefaultDeny {
		expectedDefault = dp.PolicyActionDeny
	}
	var removed []*RuntimePolicy
	for _, policy := range owned {
		retained, ownedRules, err := splitEdgeRules(policy.Rules, id)
		if err != nil {
			return err
		}
		if !ownedRules {
			return errEdgePolicyOwnership
		}
		if len(retained) != 0 || policy.Mode != expectedMode || policy.DefAction != expectedDefault || policy.ApplyDir != dp.ApplyDirBoth {
			return errEdgePolicyOwnership
		}
		if _, err := tx.Exec(ctx, `DELETE FROM runtime_policies WHERE id=$1 AND org_id=$2`, policy.ID, orgID); err != nil {
			return err
		}
		removed = append(removed, policy)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM group_rule_edges WHERE id=$1 AND org_id=$2`, id, orgID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if s.pol != nil && s.pol.auditLog != nil {
		for _, policy := range removed {
			if err := s.pol.auditLog.LogPolicyDelete(ctx, orgID, nil, snapshot(policy), ""); err != nil {
				slog.Default().Warn("edge retraction policy audit failed after commit", "policy_id", policy.ID, "error", err)
			}
		}
	}
	return nil
}

func splitEdgeRules(raw json.RawMessage, edgeID uuid.UUID) ([]json.RawMessage, bool, error) {
	var rules []json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, false, err
	}
	retained := make([]json.RawMessage, 0, len(rules))
	owned := false
	for _, rule := range rules {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(rule, &fields); err != nil || fields == nil {
			return nil, false, errEdgePolicyOwnership
		}
		var source, owner string
		if err := json.Unmarshal(fields["cfg"], &source); err != nil && len(fields["cfg"]) != 0 {
			return nil, false, errEdgePolicyOwnership
		}
		if err := json.Unmarshal(fields["edge_id"], &owner); err != nil && len(fields["edge_id"]) != 0 {
			return nil, false, errEdgePolicyOwnership
		}
		if owner != "" && (owner != edgeID.String() || source != string(netpolicy.CfgTypeLearned)) {
			return nil, false, errEdgePolicyOwnership
		}
		if source == string(netpolicy.CfgTypeLearned) && owner == "" {
			return nil, false, errEdgePolicyOwnership
		}
		if owner == edgeID.String() {
			owned = true
			continue
		}
		retained = append(retained, rule)
	}
	return retained, owned, nil
}

func markEdgeRules(ctx context.Context, tx pgx.Tx, policyID, orgID, edgeID uuid.UUID) error {
	var raw json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT rules FROM runtime_policies WHERE id=$1 AND org_id=$2 FOR UPDATE`,
		policyID, orgID).Scan(&raw); err != nil {
		return err
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		return err
	}
	owner, err := json.Marshal(edgeID.String())
	if err != nil {
		return err
	}
	marked := false
	for _, rule := range rules {
		var source string
		if err := json.Unmarshal(rule["cfg"], &source); err != nil && len(rule["cfg"]) != 0 {
			return errEdgePolicyOwnership
		}
		if source == string(netpolicy.CfgTypeLearned) {
			rule["edge_id"] = owner
			marked = true
		}
	}
	if !marked {
		return errEdgePolicyOwnership
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE runtime_policies SET rules=$1::jsonb WHERE id=$2 AND org_id=$3`,
		string(encoded), policyID, orgID)
	return err
}

// groupMembers reads the cached member list for a group by name from the groups
// table (owned elsewhere; read-only here). Members are "namespace/name" ids.
func (s *GroupEdgeStore) groupMembers(ctx context.Context, tx pgx.Tx, orgID, clusterID uuid.UUID, name string) ([]string, error) {
	if name == "external" || name == "nodes" {
		return nil, nil
	}
	var raw json.RawMessage
	err := tx.QueryRow(ctx,
		`SELECT members FROM groups WHERE org_id = $1 AND name = $2 AND (cluster_id IS NULL OR cluster_id = $3) FOR SHARE`, orgID, name, clusterID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("group %q does not exist in cluster: %w", name, errEdgeGroupNotFound)
	}
	if err != nil {
		return nil, err
	}
	var members []string
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &members); err != nil {
			return nil, err
		}
	}
	return members, nil
}

// ExpandResult reports what an expansion produced.
type ExpandResult struct {
	FromMembers int      `json:"from_members"`
	ToMembers   int      `json:"to_members"`
	Flows       int      `json:"flows"`
	Policies    []string `json:"policies"` // affected workloads
}

// Expand resolves an edge's group memberships and upsert-merges runtime_policies for every
// involved member workload, in the edge's authored mode (protect => enforcing default-deny,
// discover/monitor => informational). Safe to re-run (idempotent via the provenance merge);
// call it after group membership changes.
func (s *GroupEdgeStore) Expand(ctx context.Context, orgID, clusterID uuid.UUID, e netpolicy.GroupEdge, by *uuid.UUID) (ExpandResult, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return ExpandResult{}, err
	}
	defer tx.Rollback(ctx)
	result, createdPolicies, err := s.expandTx(ctx, tx, orgID, clusterID, e, by)
	if err != nil {
		return ExpandResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ExpandResult{}, err
	}
	s.auditCreatedPolicies(ctx, orgID, by, createdPolicies)
	return result, nil
}

func (s *GroupEdgeStore) expandTx(ctx context.Context, tx pgx.Tx, orgID, clusterID uuid.UUID, e netpolicy.GroupEdge, by *uuid.UUID) (ExpandResult, []*RuntimePolicy, error) {
	if err := e.Validate(); err != nil {
		return ExpandResult{}, nil, err
	}
	var lockedOrgID, lockedClusterID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE`, orgID).Scan(&lockedOrgID); err != nil {
		return ExpandResult{}, nil, err
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM clusters WHERE id=$1 AND org_id=$2 FOR KEY SHARE`, clusterID, orgID).Scan(&lockedClusterID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ExpandResult{}, nil, errEdgeClusterNotFound
		}
		return ExpandResult{}, nil, err
	}
	if e.ID != "" {
		edgeID, err := uuid.Parse(e.ID)
		if err != nil {
			return ExpandResult{}, nil, err
		}
		row, err := scanGroupEdge(tx.QueryRow(ctx, `
SELECT id, cluster_id, from_group, to_group, ports, mode, comment, updated_at
  FROM group_rule_edges WHERE id=$1 AND org_id=$2 AND cluster_id=$3 FOR UPDATE`, edgeID, orgID, clusterID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ExpandResult{}, nil, errEdgeNotFound
		}
		if err != nil {
			return ExpandResult{}, nil, err
		}
		e = netpolicy.GroupEdge{ID: row.ID.String(), FromGroup: row.FromGroup, ToGroup: row.ToGroup,
			Ports: row.Ports, Mode: row.Mode, Comment: row.Comment}
	}
	fromMembers, err := s.groupMembers(ctx, tx, orgID, clusterID, e.FromGroup)
	if err != nil {
		return ExpandResult{}, nil, err
	}
	toMembers, err := s.groupMembers(ctx, tx, orgID, clusterID, e.ToGroup)
	if err != nil {
		return ExpandResult{}, nil, err
	}
	flows := netpolicy.ExpandEdge(e, fromMembers, toMembers)
	res := ExpandResult{FromMembers: len(fromMembers), ToMembers: len(toMembers), Flows: len(flows)}
	if len(flows) == 0 {
		return res, nil, nil
	}
	// P0-07: honor the edge's authored mode instead of always emitting informational
	// monitor policies. A 'protect' edge produces an ENFORCING policy with a default-deny
	// posture (AllowDNS so name resolution survives the deny); 'discover'/'monitor' stay
	// informational (allow default action, monitor mode) until an operator promotes. e.Mode
	// is normalized to discover|monitor|protect by e.Validate() above.
	policyMode, opts := edgePolicyPosture(e.Mode)
	members := uniqueStrings(append(append([]string{}, fromMembers...), toMembers...))
	name := edgePolicyName(e)
	if e.ID == "" {
		return ExpandResult{}, nil, errEdgeNotFound
	}
	edgeID, err := uuid.Parse(e.ID)
	if err != nil {
		return ExpandResult{}, nil, err
	}
	policies, err := tx.Query(ctx, `SELECT rules FROM runtime_policies
 WHERE org_id=$1 AND cluster_id=$2 AND name=$3 FOR UPDATE`, orgID, clusterID, name)
	if err != nil {
		return ExpandResult{}, nil, err
	}
	for policies.Next() {
		var rules json.RawMessage
		if err := policies.Scan(&rules); err != nil {
			policies.Close()
			return ExpandResult{}, nil, err
		}
		if _, owned, err := splitEdgeRules(rules, edgeID); err != nil || !owned {
			policies.Close()
			return ExpandResult{}, nil, errEdgePolicyOwnership
		}
	}
	err = policies.Err()
	policies.Close()
	if err != nil {
		return ExpandResult{}, nil, err
	}
	createdPolicies := []*RuntimePolicy{}
	for _, m := range members {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		rules, defAction, applyDir := netpolicy.BuildDPRules(m, flows, opts)
		if len(rules) == 0 {
			continue
		}
		policy := &RuntimePolicy{
			OrgID: orgID, ClusterID: clusterID,
			Workload: m, Namespace: namespaceOfWorkload(m), Name: name,
			Mode: policyMode, DefAction: defAction, ApplyDir: applyDir,
			CreatedBy: by,
		}
		var existingRules json.RawMessage
		err := tx.QueryRow(ctx, `SELECT rules FROM runtime_policies
 WHERE org_id=$1 AND cluster_id=$2 AND workload=$3 AND name=$4 FOR UPDATE`,
			orgID, clusterID, m, name).Scan(&existingRules)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ExpandResult{}, nil, err
		}
		if err == nil {
			if _, owned, err := splitEdgeRules(existingRules, edgeID); err != nil || !owned {
				return ExpandResult{}, nil, errEdgePolicyOwnership
			}
		}
		policyID, created, err := s.pol.upsertLearnedPolicyTx(ctx, tx, policy, rules, by)
		if err != nil {
			return ExpandResult{}, nil, err
		}
		if created {
			createdPolicies = append(createdPolicies, policy)
		}
		if err := markEdgeRules(ctx, tx, policyID, orgID, edgeID); err != nil {
			return ExpandResult{}, nil, err
		}
		res.Policies = append(res.Policies, m)
	}
	return res, createdPolicies, nil
}

func (s *GroupEdgeStore) auditCreatedPolicies(ctx context.Context, orgID uuid.UUID, by *uuid.UUID, createdPolicies []*RuntimePolicy) {
	if s.pol.auditLog != nil {
		for _, policy := range createdPolicies {
			if err := s.pol.auditLog.LogPolicyCreate(ctx, orgID, by, snapshot(policy), ""); err != nil {
				slog.Default().Warn("edge expansion policy audit failed after commit", "policy_id", policy.ID, "error", err)
			}
		}
	}
}

// edgePolicyPosture maps an edge's authored mode (discover|monitor|protect, already normalized
// by GroupEdge.Validate) to the runtime policy mode and dp-rule build options. Only 'protect'
// enforces (default-deny with DNS allowed); discover/monitor stay informational allow-default
// monitor policies until an operator promotes them.
func edgePolicyPosture(mode string) (PolicyMode, netpolicy.BuildDPRulesOptions) {
	if mode == "protect" {
		return PolicyModeEnforce, netpolicy.DefaultBuildDPRulesOptions() // AllowDNS:true, DefaultDeny:true
	}
	return PolicyModeMonitor, netpolicy.BuildDPRulesOptions{AllowDNS: false, DefaultDeny: false}
}

func edgePolicyName(e netpolicy.GroupEdge) string {
	return "edge-" + sanitizeName(e.FromGroup) + "-to-" + sanitizeName(e.ToGroup)
}

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

func namespaceOfWorkload(id string) string {
	if i := strings.IndexByte(id, '/'); i > 0 {
		return id[:i]
	}
	return "default"
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func scanGroupEdge(sc rowScanner) (GroupEdgeRow, error) {
	var e GroupEdgeRow
	var ports json.RawMessage
	if err := sc.Scan(&e.ID, &e.ClusterID, &e.FromGroup, &e.ToGroup, &ports, &e.Mode, &e.Comment, &e.UpdatedAt); err != nil {
		return GroupEdgeRow{}, err
	}
	if len(ports) > 0 && string(ports) != "null" {
		_ = json.Unmarshal(ports, &e.Ports)
	}
	return e, nil
}

// ------------------------------------ HTTP ----------------------------------

// GroupEdgesHTTP serves the group-edge CRUD + expansion endpoints.
type GroupEdgesHTTP struct {
	store       *GroupEdgeStore
	auditWriter func(context.Context, audit.Event) error
}

// NewGroupEdgesHTTP builds the HTTP surface, sharing the runtime-policy store.
func NewGroupEdgesHTTP(d *db.DB, pol *RuntimePolicyStore, auditLog *audit.Logger) *GroupEdgesHTTP {
	h := &GroupEdgesHTTP{store: NewGroupEdgeStore(d, pol)}
	if auditLog != nil {
		h.auditWriter = func(ctx context.Context, event audit.Event) error {
			_, _, err := auditLog.Log(ctx, event)
			return err
		}
	}
	return h
}

func (h *GroupEdgesHTTP) writeAudit(r *http.Request, sub authctx.Subject, action, targetID string, before, after any) error {
	if h.auditWriter == nil {
		return errors.New("audit writer unavailable")
	}
	return h.auditWriter(r.Context(), audit.Event{
		OrgID: &sub.OrgID, ActorID: &sub.UserID, Action: action,
		TargetKind: "group_rule_edge", TargetID: targetID,
		Before: before, After: after, RequestID: requestIDFrom(r),
	})
}

func (h *GroupEdgesHTTP) requireAuditAttempt(w http.ResponseWriter, r *http.Request, sub authctx.Subject, action, targetID string, before, after any) bool {
	if err := h.writeAudit(r, sub, action+"_attempt", targetID, before, after); err != nil {
		slog.Default().Error("group edge audit attempt failed; mutation rejected", "action", action, "target_id", targetID, "error", err)
		jsonError(w, http.StatusServiceUnavailable, "audit unavailable; mutation rejected")
		return false
	}
	return true
}

func (h *GroupEdgesHTTP) auditMutation(r *http.Request, sub authctx.Subject, action string, row GroupEdgeRow, before, after any) {
	if err := h.writeAudit(r, sub, action, row.ID.String(), before, after); err != nil {
		slog.Default().Warn("group edge completion audit failed; mutation already committed", "action", action, "edge_id", row.ID, "error", err)
	}
}

// CreateEdgeRequest is the POST body.
type CreateEdgeRequest struct {
	ClusterID uuid.UUID            `json:"cluster_id"`
	FromGroup string               `json:"from_group"`
	ToGroup   string               `json:"to_group"`
	Ports     []netpolicy.PortSpec `json:"ports"`
	Mode      string               `json:"mode"`
	Comment   string               `json:"comment"`
	Expand    bool                 `json:"expand"` // also expand to member policies now
}

// List handles GET /group-edges?cluster_id=...
func (h *GroupEdgesHTTP) List(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	clusterID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	exists, err := h.store.clusterExists(r.Context(), sub.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to check cluster")
		return
	}
	if !exists {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return
	}
	rows, err := h.store.List(r.Context(), sub.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"edges": rows})
}

// Create handles POST /group-edges — upsert an edge and optionally expand it.
func (h *GroupEdgesHTTP) Create(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req CreateEdgeRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.ClusterID == uuid.Nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	edge := netpolicy.GroupEdge{
		FromGroup: req.FromGroup, ToGroup: req.ToGroup,
		Ports: req.Ports, Mode: req.Mode, Comment: req.Comment,
	}
	if err := edge.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.requireAuditAttempt(w, r, sub, "group_rule_edge.upsert", req.ClusterID.String()+"/"+edge.FromGroup+"/"+edge.ToGroup, nil, map[string]any{"cluster_id": req.ClusterID, "edge": edge, "expand": req.Expand}) {
		return
	}
	if req.Expand && !h.requireAuditAttempt(w, r, sub, "group_rule_edge.expand", req.ClusterID.String()+"/"+edge.FromGroup+"/"+edge.ToGroup, nil, map[string]any{"requested_by_create": true, "edge": edge}) {
		return
	}
	var row GroupEdgeRow
	var expansion ExpandResult
	var err error
	if req.Expand {
		row, expansion, err = h.store.UpsertAndExpand(r.Context(), sub.OrgID, req.ClusterID, edge, &sub.UserID)
	} else {
		row, err = h.store.Upsert(r.Context(), sub.OrgID, req.ClusterID, edge, &sub.UserID)
	}
	if err != nil {
		if errors.Is(err, errEdgeClusterNotFound) {
			jsonError(w, http.StatusNotFound, "cluster not found")
			return
		}
		if errors.Is(err, errEdgeGroupNotFound) {
			code := http.StatusBadRequest
			if req.Expand {
				code = http.StatusConflict
			}
			jsonError(w, code, err.Error())
			return
		}
		if errors.Is(err, errEdgePolicyOwnership) {
			jsonError(w, http.StatusConflict, "edge policies have ambiguous ownership; resolve them before expansion")
			return
		}
		if errors.Is(err, errEdgeExpandedMutation) {
			jsonError(w, http.StatusConflict, err.Error())
			return
		}
		jsonError(w, http.StatusInternalServerError, "failed to save edge or expansion")
		return
	}
	h.auditMutation(r, sub, "group_rule_edge.upsert", row, nil, row)
	resp := map[string]any{"edge": row}
	if req.Expand {
		h.auditMutation(r, sub, "group_rule_edge.expand", row, row, expansion)
		resp["expansion"] = expansion
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// Expand handles POST /group-edges/{id}/expand — re-expand after membership change.
func (h *GroupEdgesHTTP) Expand(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id, err := uuid.Parse(pathSegmentBeforeExpand(r.URL.Path))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := h.store.get(r.Context(), sub.OrgID, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "not found")
		} else {
			jsonError(w, http.StatusInternalServerError, "failed to read edge")
		}
		return
	}
	exists, err := h.store.clusterExists(r.Context(), sub.OrgID, row.ClusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to check cluster")
		return
	}
	if !exists {
		jsonError(w, http.StatusNotFound, "cluster not found")
		return
	}
	edge := netpolicy.GroupEdge{
		ID: row.ID.String(), FromGroup: row.FromGroup, ToGroup: row.ToGroup,
		Ports: row.Ports, Mode: row.Mode, Comment: row.Comment,
	}
	if !h.requireAuditAttempt(w, r, sub, "group_rule_edge.expand", row.ID.String(), row, map[string]any{"requested_by_create": false}) {
		return
	}
	exp, err := h.store.Expand(r.Context(), sub.OrgID, row.ClusterID, edge, &sub.UserID)
	if err != nil {
		if errors.Is(err, errEdgeGroupNotFound) {
			jsonError(w, http.StatusConflict, err.Error())
			return
		}
		if errors.Is(err, errEdgePolicyOwnership) {
			jsonError(w, http.StatusConflict, "edge policies have ambiguous ownership; resolve them before expansion")
			return
		}
		jsonError(w, http.StatusInternalServerError, "failed to expand edge")
		return
	}
	h.auditMutation(r, sub, "group_rule_edge.expand", row, row, exp)
	httpx.WriteJSON(w, http.StatusOK, exp)
}

// Delete handles DELETE /group-edges/{id}.
func (h *GroupEdgesHTTP) Delete(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	id, err := uuid.Parse(pathTail(r.URL.Path))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := h.store.get(r.Context(), sub.OrgID, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "not found")
		} else {
			jsonError(w, http.StatusInternalServerError, "failed to read edge")
		}
		return
	}
	if !h.requireAuditAttempt(w, r, sub, "group_rule_edge.delete", row.ID.String(), row, nil) {
		return
	}
	if err := h.store.Delete(r.Context(), sub.OrgID, id); err != nil {
		if errors.Is(err, errEdgeNotFound) {
			jsonError(w, http.StatusNotFound, "not found")
		} else if errors.Is(err, errEdgePolicyOwnership) {
			jsonError(w, http.StatusConflict, "edge policies have ambiguous ownership; resolve them before deletion")
		} else {
			jsonError(w, http.StatusInternalServerError, "failed to delete edge")
		}
		return
	}
	h.auditMutation(r, sub, "group_rule_edge.delete", row, row, nil)
	w.WriteHeader(http.StatusNoContent)
}

// pathSegmentBeforeExpand pulls the {id} out of ".../group-edges/{id}/expand".
func pathSegmentBeforeExpand(p string) string {
	p = strings.TrimSuffix(p, "/expand")
	return pathTail(p)
}
