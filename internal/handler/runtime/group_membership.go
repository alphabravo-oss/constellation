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
// This reconciler closes that gap server-side: on a short cadence it recomputes
// every group's members from the current deployments table and, for any group
// whose membership changed, re-persists members and re-expands the group_rule_edges
// that reference it. It is the equivalent of NeuVector's live membership update,
// implemented as a singleton background loop (deployment ingest lives in a
// separate binary, so a poll is the coherent seam) rather than a per-event watch.
//
// ENFORCEMENT NOTE: recompute only rewrites the derived members cache, but
// re-expansion reuses GroupEdgeStore.Expand, which honors each edge's authored
// mode (see edgePolicyPosture). For discover/monitor edges that means informational
// allow-default policies; for a PROTECT-mode edge it means an ENFORCING default-deny
// policy for every newly-joined member — by design, so protection follows replicas
// (NeuVector parity). This loop therefore can start blocking a freshly-joined
// workload if an operator has authored a protect edge; disable it with
// CONSTELLATION_GROUP_MEMBERSHIP_RECONCILE=false if that is not wanted.
package runtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/group"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// GroupMembershipReconciler periodically recomputes groups.members from current
// deployments and re-expands group→group edges whose membership changed.
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

// reconcileGroup carries a group row plus its parsed selector.
type reconcileGroup struct {
	id      uuid.UUID
	cluster *uuid.UUID // group scope; nil = org-wide
	name    string
	g       group.Group
}

// reconcileOnce recomputes membership for every group and returns the number of
// groups whose members were updated.
func (r *GroupMembershipReconciler) reconcileOnce(ctx context.Context) (int, error) {
	rows, err := r.db.Pool().Query(ctx,
		`SELECT id, org_id, cluster_id, name, COALESCE(criteria,'[]'::jsonb), COALESCE(members,'[]'::jsonb) FROM groups`)
	if err != nil {
		return 0, err
	}
	byOrg := map[uuid.UUID][]reconcileGroup{}
	for rows.Next() {
		var id, orgID uuid.UUID
		var cluster *uuid.UUID
		var name string
		var criteria, members []byte
		if err := rows.Scan(&id, &orgID, &cluster, &name, &criteria, &members); err != nil {
			rows.Close()
			return 0, err
		}
		rg := reconcileGroup{id: id, cluster: cluster, name: name, g: group.Group{Name: name}}
		_ = json.Unmarshal(criteria, &rg.g.Criteria)
		_ = json.Unmarshal(members, &rg.g.Members)
		byOrg[orgID] = append(byOrg[orgID], rg)
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
			scoped := wls
			if rg.cluster != nil {
				scoped = filterByCluster(wls, rg.cluster.String())
			}
			newMembers := rg.g.ComputeMembers(scoped)
			if !rg.g.MembersChanged(newMembers) {
				continue
			}
			membersJSON, _ := json.Marshal(newMembers)
			if _, err := r.db.Pool().Exec(ctx,
				`UPDATE groups SET members = $1 WHERE id = $2`, membersJSON, rg.id); err != nil {
				r.log.Warn("group membership: persist failed",
					slog.String("group", rg.name), slog.String("err", err.Error()))
				continue
			}
			changed++
			changedNames[rg.name] = true
		}
		if len(changedNames) > 0 {
			r.reexpandEdges(ctx, orgID, changedNames)
		}
	}
	return changed, nil
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
