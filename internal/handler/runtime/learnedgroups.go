// P0-05: learned-group synthesizer.
//
// NeuVector auto-creates a learned group (nv.<service>) the moment a workload
// appears (controller/cache/group.go createLearnedGroup, invoked from
// groupWorkloadJoin) and keeps it current via refreshLearnedGroupMembership.
// Learned groups are the anchor for per-service policy mode, learned rules and
// profiles.
//
// Constellation had the learner (pkg/group.LearnFromObservations) but nothing
// called it: KindLearned groups could only appear via manual REST create, so the
// learned half of the taxonomy was dead code. This leader-gated worker closes the
// gap: every tick it reads the observed deployments (the workload templates), runs
// the learner at per-service granularity, and upserts cfg_type='learned' rows into
// the groups table — one group per (cluster, namespace, service) to match NV.
//
// The synthesized groups are INERT: they land in discover (Learn) mode and drive
// no enforcement, exactly like a freshly learned nv.<service> group. Because they
// only ever touch cfg_type='learned' rows (ON CONFLICT ... WHERE cfg_type='learned')
// they can never clobber an operator's ground group or a federated group that
// happens to share a name.
package runtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/group"
)

// LearnedGroupWorkerConfig tunes the synthesizer. The zero value is disabled;
// LearnedGroupWorkerConfigFromEnv defaults it ON with a 10m cadence.
type LearnedGroupWorkerConfig struct {
	Enabled  bool          // master gate
	Interval time.Duration // synthesis cadence; default 10m
	// MinMembers is the smallest bucket promoted to a learned group. 1 mirrors
	// NeuVector's "learn on first sight" (a service becomes a group as soon as its
	// deployment is observed).
	MinMembers int
}

// LearnedGroupWorkerConfigFromEnv reads the worker knobs. Unlike the ATMO worker
// this defaults ON: a learned group changes nothing about enforcement (it is a
// discover-mode anchor), so synthesizing it on upgrade is safe and is the parity
// behaviour. Set CONSTELLATION_LEARNED_GROUPS_ENABLED=false to opt out.
func LearnedGroupWorkerConfigFromEnv() LearnedGroupWorkerConfig {
	return LearnedGroupWorkerConfig{
		Enabled:    envBoolDefault("CONSTELLATION_LEARNED_GROUPS_ENABLED", true),
		Interval:   envDurationDefault("CONSTELLATION_LEARNED_GROUPS_INTERVAL", 10*time.Minute),
		MinMembers: 1,
	}
}

// LearnedGroupWorker periodically synthesizes cfg_type='learned' groups from the
// observed deployments.
type LearnedGroupWorker struct {
	db  *db.DB
	log *slog.Logger
	cfg LearnedGroupWorkerConfig
}

// NewLearnedGroupWorker builds the synthesizer. log may be nil (falls back to the
// default logger).
func NewLearnedGroupWorker(d *db.DB, cfg LearnedGroupWorkerConfig, log *slog.Logger) *LearnedGroupWorker {
	if log == nil {
		log = slog.Default()
	}
	if cfg.MinMembers <= 0 {
		cfg.MinMembers = 1
	}
	return &LearnedGroupWorker{db: d, log: log, cfg: cfg}
}

// Run blocks until ctx is cancelled, synthesizing every Interval. It is a no-op
// (returns immediately) when disabled, so wiring it into the singleton loops
// unconditionally is safe.
func (w *LearnedGroupWorker) Run(ctx context.Context) {
	if !w.cfg.Enabled {
		return
	}
	interval := w.cfg.Interval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	w.log.Info("learned-group synthesizer started", slog.Duration("interval", interval))
	t := time.NewTicker(interval)
	defer t.Stop()
	// Synthesize once on start so a freshly-elected leader acts promptly.
	if n, err := w.synthesize(ctx); err != nil {
		w.log.Warn("learned-group synthesis failed", slog.String("err", err.Error()))
	} else if n > 0 {
		w.log.Info("learned-group synthesis upserted groups", slog.Int("count", n))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := w.synthesize(ctx); err != nil {
				w.log.Warn("learned-group synthesis failed", slog.String("err", err.Error()))
			} else if n > 0 {
				w.log.Debug("learned-group synthesis upserted groups", slog.Int("count", n))
			}
		}
	}
}

// obsKey scopes observations to one (org, cluster) so a learned group is written
// with the right org_id and cluster_id. cluster_id is nullable (org-wide
// deployments), so the key carries the string form and the pointer separately.
type obsKey struct {
	orgID     uuid.UUID
	clusterID string
}

// synthesize reads every observed deployment, runs the per-service learner scoped
// to each (org, cluster), and upserts the learned groups. Returns the number of
// rows upserted.
func (w *LearnedGroupWorker) synthesize(ctx context.Context) (int, error) {
	rows, err := w.db.Pool().Query(ctx, `
SELECT org_id, cluster_id, namespace, name, COALESCE(labels,'{}'::jsonb), last_seen_at
  FROM deployments`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	// Group observations by (org, cluster). LearnFromObservations buckets by
	// (cluster, namespace, service); scoping the input per (org, cluster) keeps the
	// output attributable to the row we upsert.
	obsByScope := map[obsKey][]group.Observation{}
	clusterUUID := map[string]*uuid.UUID{}
	for rows.Next() {
		var (
			orgID     uuid.UUID
			clusterID *uuid.UUID
			ns, name  string
			labelsRaw []byte
			lastSeen  time.Time
		)
		if err := rows.Scan(&orgID, &clusterID, &ns, &name, &labelsRaw, &lastSeen); err != nil {
			return 0, err
		}
		labels := map[string]string{}
		_ = json.Unmarshal(labelsRaw, &labels)
		clusterStr := ""
		if clusterID != nil {
			clusterStr = clusterID.String()
		}
		key := obsKey{orgID: orgID, clusterID: clusterStr}
		clusterUUID[clusterStr] = clusterID
		obsByScope[key] = append(obsByScope[key], group.Observation{
			At: lastSeen,
			Workload: group.Workload{
				ID:        deploymentWorkloadID(ns, name),
				Cluster:   clusterStr,
				Namespace: ns,
				Service:   name, // one learned group per workload template
				Labels:    labels,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	upserted := 0
	for key, obs := range obsByScope {
		// window 0: no staleness filter — a deployment present in the table is a
		// current workload, mirroring NV's join-driven creation.
		for _, g := range group.LearnFromObservations(obs, 0, w.cfg.MinMembers) {
			if err := w.upsertLearnedGroup(ctx, key.orgID, clusterUUID[key.clusterID], g); err != nil {
				w.log.Warn("learned-group upsert failed",
					slog.String("group", g.Name), slog.String("err", err.Error()))
				continue
			}
			upserted++
		}
	}
	return upserted, nil
}

// upsertLearnedGroup writes one learned group. It only ever creates or refreshes a
// cfg_type='learned' row: the DO UPDATE ... WHERE guard means a name collision with
// an operator's ground group or a federated group is a no-op rather than a clobber.
// New rows land in discover (Learn) mode; an operator's later mode promotion is
// preserved across ticks because the UPDATE does not touch policy_mode/profile_mode.
func (w *LearnedGroupWorker) upsertLearnedGroup(ctx context.Context, orgID uuid.UUID, clusterID *uuid.UUID, g group.Group) error {
	criteria, err := json.Marshal(g.Criteria)
	if err != nil {
		return err
	}
	members, err := json.Marshal(g.Members)
	if err != nil {
		return err
	}
	_, err = w.db.Pool().Exec(ctx, `
INSERT INTO groups (org_id, cluster_id, name, kind, comment, criteria, members,
                    learned_from, cfg_type, policy_mode, profile_mode)
VALUES ($1, $2, $3, 'learned', 'auto-learned from observed workloads',
        $4, $5, $6, 'learned', 'discover', 'discover')
ON CONFLICT (org_id, name) DO UPDATE SET
    criteria     = EXCLUDED.criteria,
    members      = EXCLUDED.members,
    learned_from = EXCLUDED.learned_from,
    cluster_id   = EXCLUDED.cluster_id,
    updated_at   = NOW()
 WHERE groups.cfg_type = 'learned'`,
		orgID, clusterID, g.Name, criteria, members, g.LearnedFrom)
	return err
}
