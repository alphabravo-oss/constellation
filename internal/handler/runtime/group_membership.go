// Live group membership reconcile (NeuVector groupWorkloadJoin/Leave parity).
//
// NeuVector re-evaluates every group's criteria whenever a workload starts or
// stops (controller/cache/group.go groupWorkloadJoin/groupWorkloadLeave/
// refreshGroupMember), so a rule authored against a group automatically covers
// future members. Constellation computes groups.members eagerly, but only inside
// the group Create/Update handlers — a new pod replica ingested by the discoverer
// (which writes the deployments table out-of-band) never joins existing groups,
// and the group→group edge expansion (GroupEdgeStore.Expand, which reads the
// cached members column) has no automatic caller.
//
// This reconciler recomputes membership on a short cadence. A changed group is
// written only when it has no policy references; referenced membership needs an
// explicit, atomic policy transition before it can be changed safely. Deployment
// ingest lives in a separate binary, so the poll is the coherent seam.
//
// ENFORCEMENT NOTE: referenced groups are not refreshed by this loop, so newly
// joined workloads do not inherit their policies until an explicit safe transition
// exists. Set CONSTELLATION_GROUP_MEMBERSHIP_RECONCILE=false to disable polling.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/group"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// GroupMembershipReconciler periodically recomputes unreferenced groups.members.
type GroupMembershipReconciler struct {
	db       *db.DB
	edges    *GroupEdgeStore
	log      *slog.Logger
	interval time.Duration
	enabled  bool
}

// NewGroupMembershipReconciler builds the reconciler. It shares the runtime-policy
// store so edge re-expansion can upsert-merge per-member policies. log may be nil.
func NewGroupMembershipReconciler(d *db.DB, pol *RuntimePolicyStore, log *slog.Logger) *GroupMembershipReconciler {
	if log == nil {
		log = slog.Default()
	}
	return &GroupMembershipReconciler{
		db:       d,
		edges:    NewGroupEdgeStore(d, pol),
		log:      log,
		interval: envDurationDefault("CONSTELLATION_GROUP_MEMBERSHIP_INTERVAL", 2*time.Minute),
		// On by default: this is a correctness fix (members must not go stale).
		// Set CONSTELLATION_GROUP_MEMBERSHIP_RECONCILE=false to disable.
		enabled: envBoolDefault("CONSTELLATION_GROUP_MEMBERSHIP_RECONCILE", true),
	}
}

// Run blocks until ctx is cancelled, reconciling membership every interval. It is
// a no-op (returns immediately) when disabled, so wiring it into the singleton
// loops unconditionally is safe.
func (r *GroupMembershipReconciler) Run(ctx context.Context) {
	if !r.enabled {
		return
	}
	interval := r.interval
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	r.log.Info("group membership reconcile started", slog.Duration("interval", interval))
	t := time.NewTicker(interval)
	defer t.Stop()
	// Reconcile once on start so a freshly-elected leader converges promptly.
	if n, err := r.reconcileOnce(ctx); err != nil {
		r.log.Warn("group membership reconcile failed", slog.String("err", err.Error()))
	} else if n > 0 {
		r.log.Info("group membership reconcile updated groups", slog.Int("changed", n))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := r.reconcileOnce(ctx); err != nil {
				r.log.Warn("group membership reconcile failed", slog.String("err", err.Error()))
			} else if n > 0 {
				r.log.Debug("group membership reconcile updated groups", slog.Int("changed", n))
			}
		}
	}
}

// reconcileGroup identifies a group observed at the start of a tick.
type reconcileGroup struct {
	id   uuid.UUID
	name string
}

// reconcileOnce attempts membership refresh for every group and returns the
// number of unreferenced groups whose members were updated.
func (r *GroupMembershipReconciler) reconcileOnce(ctx context.Context) (int, error) {
	rows, err := r.db.Pool().Query(ctx,
		`SELECT id, org_id, name FROM groups`)
	if err != nil {
		return 0, err
	}
	byOrg := map[uuid.UUID][]reconcileGroup{}
	for rows.Next() {
		var id, orgID uuid.UUID
		var name string
		if err := rows.Scan(&id, &orgID, &name); err != nil {
			rows.Close()
			return 0, err
		}
		byOrg[orgID] = append(byOrg[orgID], reconcileGroup{id: id, name: name})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	changed := 0
	for orgID, groups := range byOrg {
		wls, err := r.loadWorkloads(ctx, orgID)
		if err != nil {
			r.log.Warn("group membership: load workloads failed",
				slog.String("org", orgID.String()), slog.String("err", err.Error()))
			continue
		}
		changedNames := map[string]bool{}
		for i := range groups {
			rg := &groups[i]
			name, updated, err := r.reconcileMembership(ctx, orgID, rg.id, wls)
			if err != nil {
				r.log.Warn("group membership: persist failed",
					slog.String("group", rg.name), slog.String("err", err.Error()))
				continue
			}
			if updated {
				changed++
				changedNames[name] = true
			}
		}
		if len(changedNames) > 0 {
			r.reexpandEdges(ctx, orgID, changedNames)
		}
	}
	return changed, nil
}

func (r *GroupMembershipReconciler) reconcileMembership(ctx context.Context, orgID, groupID uuid.UUID, workloads []group.Workload) (string, bool, error) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		name, changed, err := r.writeMembership(ctx, orgID, groupID, workloads)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" || time.Now().After(deadline) {
			return name, changed, err
		}
		select {
		case <-ctx.Done():
			return "", false, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (r *GroupMembershipReconciler) writeMembership(ctx context.Context, orgID, groupID uuid.UUID, workloads []group.Workload) (string, bool, error) {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx)
	var lockedOrgID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE`, orgID).Scan(&lockedOrgID); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE group_rule_edges, group_dpi_sensor_bindings, response_rules_v2, policies IN SHARE MODE NOWAIT`); err != nil {
		return "", false, err
	}
	var name string
	var clusterID *uuid.UUID
	var criteria, members []byte
	err = tx.QueryRow(ctx, `SELECT name, cluster_id, criteria, members FROM groups WHERE id=$1 AND org_id=$2 FOR UPDATE NOWAIT`, groupID, orgID).
		Scan(&name, &clusterID, &criteria, &members)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	var current group.Group
	if err := json.Unmarshal(criteria, &current.Criteria); err != nil {
		return "", false, err
	}
	if err := json.Unmarshal(members, &current.Members); err != nil {
		return "", false, err
	}
	if clusterID != nil {
		workloads = filterByCluster(workloads, clusterID.String())
	}
	nextMembers := current.ComputeMembers(workloads)
	if !current.MembersChanged(nextMembers) {
		return name, false, nil
	}
	references, err := learnedGroupReferenceCount(ctx, tx, orgID, groupID, name)
	if err != nil {
		return name, false, err
	}
	if references > 0 {
		return name, false, fmt.Errorf("group %q has %d policy references; membership refresh requires explicit unlink", name, references)
	}
	membersJSON, err := json.Marshal(nextMembers)
	if err != nil {
		return name, false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE groups SET members=$1, updated_at=NOW() WHERE id=$2 AND org_id=$3`, membersJSON, groupID, orgID); err != nil {
		return name, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return name, false, err
	}
	return name, true, nil
}

// loadWorkloads returns every deployment in the org as a group.Workload, tagging
// each with its cluster so cluster-scoped groups can be filtered.
func (r *GroupMembershipReconciler) loadWorkloads(ctx context.Context, orgID uuid.UUID) ([]group.Workload, error) {
	rows, err := r.db.Pool().Query(ctx,
		`SELECT cluster_id, namespace, name, COALESCE(labels,'{}'::jsonb) FROM deployments WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []group.Workload
	for rows.Next() {
		var cluster *uuid.UUID
		var ns, name string
		var labels []byte
		if err := rows.Scan(&cluster, &ns, &name, &labels); err != nil {
			return nil, err
		}
		lm := map[string]string{}
		_ = json.Unmarshal(labels, &lm)
		clusterStr := ""
		if cluster != nil {
			clusterStr = cluster.String()
		}
		out = append(out, group.Workload{ID: ns + "/" + name, Cluster: clusterStr, Namespace: ns, Labels: lm})
	}
	return out, rows.Err()
}

// reexpandEdges re-runs Expand for every group_rule_edge whose from/to group is in
// changedNames. Expand reads the freshly-persisted members column, so new replicas
// pick up the group→group rule. Best-effort: a failure is logged, not fatal.
func (r *GroupMembershipReconciler) reexpandEdges(ctx context.Context, orgID uuid.UUID, changedNames map[string]bool) {
	rows, err := r.db.Pool().Query(ctx, `
SELECT id, cluster_id, from_group, to_group, ports, mode, comment, updated_at
  FROM group_rule_edges WHERE org_id = $1`, orgID)
	if err != nil {
		r.log.Warn("group membership: load edges failed",
			slog.String("org", orgID.String()), slog.String("err", err.Error()))
		return
	}
	var edges []GroupEdgeRow
	for rows.Next() {
		e, err := scanGroupEdge(rows)
		if err != nil {
			rows.Close()
			r.log.Warn("group membership: scan edge failed", slog.String("err", err.Error()))
			return
		}
		if changedNames[e.FromGroup] || changedNames[e.ToGroup] {
			edges = append(edges, e)
		}
	}
	rows.Close()
	for _, e := range edges {
		ge := netpolicy.GroupEdge{
			ID: e.ID.String(), FromGroup: e.FromGroup, ToGroup: e.ToGroup,
			Ports: e.Ports, Mode: e.Mode, Comment: e.Comment,
		}
		if _, err := r.edges.Expand(ctx, orgID, e.ClusterID, ge, nil); err != nil {
			r.log.Warn("group membership: edge re-expansion failed",
				slog.String("edge", e.ID.String()), slog.String("err", err.Error()))
		}
	}
}

// filterByCluster returns the subset of wls in the given cluster.
func filterByCluster(wls []group.Workload, cluster string) []group.Workload {
	out := make([]group.Workload, 0, len(wls))
	for _, w := range wls {
		if w.Cluster == cluster {
			out = append(out, w)
		}
	}
	return out
}
