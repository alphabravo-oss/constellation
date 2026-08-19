// Wave A5: auto-rollback watcher for enforce-mode policies.
//
// When a policy in `enforce` mode produces too many drops per unit time,
// the watcher demotes it back to `monitor`. This is the "safety belt" that
// keeps a misconfigured rule from quietly breaking a workload's network
// for hours before someone notices.
//
// Signal: count of network_flows rows with policy_id matching the policy
// and verdict='deny' in the last `WindowSeconds`. Crude but uses only data
// we already collect — no new counters needed. The exact heuristic will
// evolve once we have real production data (eg. rate vs flat count,
// per-workload baseline, etc.); for Wave A5 the bar is "stop catastrophic
// outages without manual intervention."
//
// Thresholds:
//   - Default: 1000 denies per 60s window per policy → rollback.
//   - Per-cluster overrides are reserved for a future runtime_enforce_config table.
//   - Override globally via env: CONSTELLATION_ENFORCE_AUTO_ROLLBACK_*
//     (intended for emergency turning off; documented in deployment-helm.md).
//
// Tests use the inner CheckOnce() entry point with a fixed clock; production
// uses Run() with a 30s tick.
package runtime

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// RollbackConfig — knobs for the auto-rollback watcher.
type RollbackConfig struct {
	// WindowSeconds is the look-back window for the deny count.
	WindowSeconds int
	// Threshold is the deny count above which we demote the policy.
	Threshold int
	// TickInterval is how often Run() scans. Defaults to 30s.
	TickInterval time.Duration
	// MinAgeSeconds is the minimum age a policy must have in enforce
	// mode before it's eligible for auto-rollback. Stops a policy from
	// rollback-flapping during its first reconcile cycle while dp is
	// still warming up.
	MinAgeSeconds int
}

// DefaultRollbackConfig returns the production defaults, with env-var
// overrides applied. Empty / unparseable env vars fall through to the
// hardcoded defaults rather than crashing the API.
func DefaultRollbackConfig() RollbackConfig {
	c := RollbackConfig{
		WindowSeconds: 60,
		Threshold:     1000,
		TickInterval:  30 * time.Second,
		MinAgeSeconds: 120, // 2 minutes
	}
	if v, err := strconv.Atoi(os.Getenv("CONSTELLATION_ENFORCE_AUTO_ROLLBACK_WINDOW_S")); err == nil && v > 0 {
		c.WindowSeconds = v
	}
	if v, err := strconv.Atoi(os.Getenv("CONSTELLATION_ENFORCE_AUTO_ROLLBACK_THRESHOLD")); err == nil && v > 0 {
		c.Threshold = v
	}
	if v, err := strconv.Atoi(os.Getenv("CONSTELLATION_ENFORCE_AUTO_ROLLBACK_MIN_AGE_S")); err == nil && v >= 0 {
		c.MinAgeSeconds = v
	}
	return c
}

// PolicyRollbackWatcher demotes enforce-mode policies that produce more
// drops than the configured threshold in a rolling window. Owns no state
// of its own; queries network_flows + runtime_policies directly each tick.
type PolicyRollbackWatcher struct {
	store  *RuntimePolicyStore
	cfg    RollbackConfig
	logger *slog.Logger
}

// NewPolicyRollbackWatcher constructs the watcher. cfg.TickInterval ≤ 0
// gets replaced with 30s in Run().
func NewPolicyRollbackWatcher(store *RuntimePolicyStore, cfg RollbackConfig, logger *slog.Logger) *PolicyRollbackWatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &PolicyRollbackWatcher{store: store, cfg: cfg, logger: logger}
}

// Run blocks until ctx is canceled, ticking every cfg.TickInterval and
// invoking CheckOnce on every tick.
func (w *PolicyRollbackWatcher) Run(ctx context.Context) {
	interval := w.cfg.TickInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	// First check happens immediately so a fresh agent starts demoting
	// promptly rather than waiting `interval`.
	w.CheckOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.CheckOnce(ctx)
		}
	}
}

// CheckOnce runs one pass of the rollback heuristic. Public for testability.
//
// For each enforce-mode policy old enough to be eligible, the query joins
// the policy against network_flows.policy_id and counts deny rows in the
// window. If count > threshold, we call SetMode(monitor, system=true) which
// writes a runtime.policy.auto_rollback audit row.
//
// Errors are logged + counted; one bad policy doesn't stop us scanning the
// rest. The watcher is best-effort safety; if it misses one tick the worst
// case is a 30s longer outage before the next pass.
func (w *PolicyRollbackWatcher) CheckOnce(ctx context.Context) {
	// Query enforce-mode policies eligible for rollback (older than MinAge).
	// Wave A6: pull dp_policy_id so we can join network_flows.policy_id
	// directly (BIGINT = BIGINT) instead of the string-cast hack.
	rows, err := w.store.db.Pool().Query(ctx, `
SELECT id, dp_policy_id, org_id, cluster_id, workload, namespace
  FROM runtime_policies
 WHERE mode = 'enforce'
   AND updated_at < NOW() - ($1 || ' seconds')::interval`,
		strconv.Itoa(w.cfg.MinAgeSeconds))
	if err != nil {
		w.logger.Warn("rollback watcher: list enforce policies",
			slog.String("err", err.Error()))
		return
	}
	type candidate struct {
		ID                  uuid.UUID
		DPPolicyID          int64
		OrgID, ClusterID    uuid.UUID
		Workload, Namespace string
	}
	var cands []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.ID, &c.DPPolicyID, &c.OrgID, &c.ClusterID, &c.Workload, &c.Namespace); err != nil {
			w.logger.Warn("rollback watcher: scan", slog.String("err", err.Error()))
			continue
		}
		cands = append(cands, c)
	}
	rows.Close()

	for _, c := range cands {
		var denies int
		// Wave A6: join on dp_policy_id (BIGINT = BIGINT). Before A6 we
		// were comparing policy_id::text against the policy UUID, which
		// never matched in production.
		err := w.store.db.Pool().QueryRow(ctx, `
SELECT COUNT(*)::int
  FROM network_flows
 WHERE org_id = $1 AND cluster_id = $2
   AND policy_id = $3
   AND verdict = 'deny'
   AND at >= NOW() - ($4 || ' seconds')::interval`,
			c.OrgID, c.ClusterID, c.DPPolicyID,
			strconv.Itoa(w.cfg.WindowSeconds)).Scan(&denies)
		if err != nil {
			w.logger.Debug("rollback watcher: count denies",
				slog.String("policy", c.ID.String()), slog.String("err", err.Error()))
			continue
		}
		if denies <= w.cfg.Threshold {
			continue
		}
		w.logger.Warn("auto-rollback firing",
			slog.String("policy_id", c.ID.String()),
			slog.String("workload", c.Workload),
			slog.Int("denies", denies),
			slog.Int("threshold", w.cfg.Threshold),
			slog.Int("window_s", w.cfg.WindowSeconds))
		// System-initiated demote. The store writes a
		// runtime.policy.auto_rollback audit row.
		if err := w.store.SetMode(ctx, c.OrgID, c.ID, PolicyModeMonitor,
			uuid.Nil, true /*system*/, "auto-rollback"); err != nil {
			w.logger.Error("rollback watcher: demote failed",
				slog.String("policy_id", c.ID.String()),
				slog.String("err", err.Error()))
		}
	}
}
