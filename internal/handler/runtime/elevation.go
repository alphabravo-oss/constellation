// P2-1: ATMO (auto mode-elevation) background worker.
//
// The elevation DECISION logic lives in pkg/netpolicy.Manager (learn-window,
// stability, and alert gates for discover→monitor→protect). Until now it only
// ran on-demand inside the network-policy LIST handler and only persisted when
// an operator explicitly POSTed an approval. This worker is the leader-gated
// background driver: every tick it re-evaluates the tracked candidates in
// network_policy_lifecycle_states, records the PROPOSAL on each row, and — only
// when explicitly opted in via config — PERSISTS the transition.
//
// SAFETY (the whole reason this is opt-in):
//   - Disabled by default. Nothing runs unless CONSTELLATION_ATMO_WORKER_ENABLED
//     is set, so an upgrade never spontaneously starts moving workloads.
//   - Even when enabled, the default behaviour is PROPOSE ONLY: it writes
//     target_mode + a "pending" approval, exactly what the operator would see in
//     the UI, and changes nothing about enforcement.
//   - Auto-applying discover→monitor requires CONSTELLATION_ATMO_AUTO_PERSIST.
//   - Auto-applying monitor→protect (the transition that actually starts
//     BLOCKING traffic) requires the additional CONSTELLATION_ATMO_AUTO_ENFORCE.
//     It can never be reached by the discover→monitor flag alone, so the worker
//     cannot silently start enforcing.
package runtime

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// ElevationWorkerConfig tunes the ATMO worker. The zero value is a valid
// propose-only worker (no auto-persist, no auto-enforce) once Enabled is true.
type ElevationWorkerConfig struct {
	Enabled     bool          // master gate; false = do not run at all
	AutoPersist bool          // apply discover→monitor automatically
	AutoEnforce bool          // apply monitor→protect (BLOCKING) automatically
	Interval    time.Duration // evaluation cadence; default 10m
	LearnWindow time.Duration // per-workload learn-window override; 0 = use the mover windows
	// D2MWindow / M2PWindow mirror NeuVector's ATMO complete periods: how long a
	// workload must learn before discover→monitor, and how long it must stay
	// CONTINUOUSLY clean (no alerts/threats) before monitor→protect. 0 disables
	// that transition (NeuVector ConfigureCompleteDuration(mover, 0)).
	D2MWindow time.Duration // default 6h
	M2PWindow time.Duration // default 12h
}

// ElevationWorkerConfigFromEnv reads the worker knobs from the environment. All
// default to the safe value (disabled / propose-only).
func ElevationWorkerConfigFromEnv() ElevationWorkerConfig {
	return ElevationWorkerConfig{
		Enabled:     envBoolDefault("CONSTELLATION_ATMO_WORKER_ENABLED", false),
		AutoPersist: envBoolDefault("CONSTELLATION_ATMO_AUTO_PERSIST", false),
		AutoEnforce: envBoolDefault("CONSTELLATION_ATMO_AUTO_ENFORCE", false),
		Interval:    envDurationDefault("CONSTELLATION_ATMO_INTERVAL", 10*time.Minute),
		LearnWindow: envDurationDefault("CONSTELLATION_ATMO_LEARN_WINDOW", 0),
		D2MWindow:   envDurationDefault("CONSTELLATION_ATMO_D2M", 6*time.Hour),
		M2PWindow:   envDurationDefault("CONSTELLATION_ATMO_M2P", 12*time.Hour),
	}
}

// ElevationWorker periodically advances the discover→monitor→protect lifecycle.
type ElevationWorker struct {
	db  *db.DB
	log *slog.Logger
	cfg ElevationWorkerConfig
	mgr *netpolicy.Manager
	now func() time.Time
}

// NewElevationWorker builds an ATMO worker. log may be nil (falls back to the
// default logger).
func NewElevationWorker(d *db.DB, cfg ElevationWorkerConfig, log *slog.Logger) *ElevationWorker {
	if log == nil {
		log = slog.Default()
	}
	mgr := netpolicy.NewManager()
	// Mirror NeuVector's per-mover complete periods (0 disables that mover).
	mgr.D2MWindow = cfg.D2MWindow
	mgr.M2PWindow = cfg.M2PWindow
	return &ElevationWorker{db: d, log: log, cfg: cfg, mgr: mgr, now: time.Now}
}

// Run blocks until ctx is cancelled, evaluating candidates every Interval. It is
// a no-op (returns immediately) when the worker is disabled, so wiring it into
// the singleton loops unconditionally is safe.
func (w *ElevationWorker) Run(ctx context.Context) {
	if !w.cfg.Enabled {
		return
	}
	interval := w.cfg.Interval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	w.log.Info("ATMO elevation worker started",
		slog.Bool("auto_persist", w.cfg.AutoPersist),
		slog.Bool("auto_enforce", w.cfg.AutoEnforce),
		slog.Duration("interval", interval))
	t := time.NewTicker(interval)
	defer t.Stop()
	// Evaluate once on start so a freshly-elected leader acts promptly.
	if n, err := w.evaluateAll(ctx); err != nil {
		w.log.Warn("ATMO evaluation failed", slog.String("err", err.Error()))
	} else if n > 0 {
		w.log.Info("ATMO evaluated candidates", slog.Int("count", n))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := w.evaluateAll(ctx); err != nil {
				w.log.Warn("ATMO evaluation failed", slog.String("err", err.Error()))
			} else if n > 0 {
				w.log.Debug("ATMO evaluated candidates", slog.Int("count", n))
			}
		}
	}
}

// candidate is one tracked workload lifecycle row.
type candidate struct {
	orgID     uuid.UUID
	clusterID uuid.UUID
	workload  string
	namespace string
	mode      netpolicy.Mode
	modeSince time.Time
}

// evaluateAll re-evaluates every tracked candidate and persists proposals /
// transitions. Returns the number of candidates evaluated.
func (w *ElevationWorker) evaluateAll(ctx context.Context) (int, error) {
	cands, err := w.loadCandidates(ctx)
	if err != nil {
		return 0, err
	}
	for _, c := range cands {
		summary, err := w.flowSummary(ctx, c)
		if err != nil {
			w.log.Warn("ATMO flow summary failed",
				slog.String("workload", c.workload), slog.String("err", err.Error()))
			continue
		}
		state := netpolicy.WorkloadState{
			Workload:    c.workload,
			Namespace:   c.namespace,
			Mode:        c.mode,
			ModeSince:   c.modeSince,
			LearnWindow: w.cfg.LearnWindow,
		}
		d := w.mgr.Evaluate(state, summary)
		if err := w.persist(ctx, c, d); err != nil {
			w.log.Warn("ATMO persist failed",
				slog.String("workload", c.workload), slog.String("err", err.Error()))
		}
	}
	return len(cands), nil
}

// loadCandidates pulls tracked, non-protect lifecycle rows (protect is terminal
// for elevation). Cluster/namespace/mode/mode_since drive the gates.
func (w *ElevationWorker) loadCandidates(ctx context.Context) ([]candidate, error) {
	rows, err := w.db.Pool().Query(ctx, `
SELECT org_id, cluster_id, workload, namespace, current_mode, mode_since
  FROM network_policy_lifecycle_states
 WHERE current_mode <> 'protect'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []candidate
	for rows.Next() {
		var c candidate
		var mode string
		if err := rows.Scan(&c.orgID, &c.clusterID, &c.workload, &c.namespace, &mode, &c.modeSince); err != nil {
			return nil, err
		}
		c.mode = netpolicy.Mode(mode)
		out = append(out, c)
	}
	return out, rows.Err()
}

// flowSummary computes the elevation inputs for one workload over the learn
// window: total flows, distinct (peer,proto,port) tuples, out-of-policy alerts
// in the last 24h, and tuples first-seen in the last 24h (stability signal).
func (w *ElevationWorker) flowSummary(ctx context.Context, c candidate) (netpolicy.FlowsSummary, error) {
	window := w.cfg.LearnWindow
	if window <= 0 {
		window = 7 * 24 * time.Hour
	}
	m2p := w.cfg.M2PWindow
	if m2p <= 0 {
		m2p = 12 * time.Hour
	}
	if window < m2p { // the learn scan must cover the M2P window so its alert count is complete
		window = m2p
	}
	windowStr := strconv.FormatInt(int64(window.Seconds()), 10) + " seconds"
	m2pStr := strconv.FormatInt(int64(m2p.Seconds()), 10) + " seconds"
	var s netpolicy.FlowsSummary
	// Peer is the non-target side of the flow; a tuple is (peer, proto, port).
	// OutOfPolicyAlerts is counted over the M2P window so any violation inside it
	// fails the monitor→protect gate (NeuVector reset-on-activity).
	err := w.db.Pool().QueryRow(ctx, `
WITH scoped AS (
    SELECT protocol, COALESCE(dst_port,0) AS port, verdict, at,
           CASE WHEN src_workload = $3 THEN dst_workload ELSE src_workload END AS peer
      FROM network_flows
     WHERE org_id = $1 AND cluster_id = $2
       AND (src_workload = $3 OR dst_workload = $3)
       AND at >= NOW() - $4::interval
),
tuples AS (
    SELECT peer, protocol, port, MIN(at) AS first_at
      FROM scoped
     GROUP BY peer, protocol, port
)
SELECT
  (SELECT COUNT(*) FROM scoped),
  (SELECT COUNT(*) FROM tuples),
  (SELECT COUNT(*) FROM scoped WHERE verdict <> 'allow' AND at >= NOW() - $5::interval),
  (SELECT COUNT(*) FROM tuples WHERE first_at >= NOW() - INTERVAL '24 hours')`,
		c.orgID, c.clusterID, c.workload, windowStr, m2pStr).
		Scan(&s.TotalFlows, &s.UniquePortProtocol, &s.OutOfPolicyAlerts, &s.NewTuplesLast24h)
	if err != nil {
		return s, err
	}
	// DPI threats attributed to the workload within the M2P window also reset the
	// clean clock (NeuVector counts threats + violations + incidents). Workload id
	// is "namespace/name"; threats carry namespace + pod_name ("name-<hash>").
	name := c.workload
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if err := w.db.Pool().QueryRow(ctx, `
SELECT COUNT(*) FROM runtime_threats
 WHERE org_id = $1 AND cluster_id = $2 AND namespace = $3
   AND (workload_id = $4 OR pod_name LIKE $5 || '%')
   AND at >= NOW() - $6::interval`,
		c.orgID, c.clusterID, c.namespace, c.workload, name, m2pStr).Scan(&s.ThreatsInWindow); err != nil {
		w.log.Debug("ATMO threats query failed", slog.String("workload", c.workload), slog.String("err", err.Error()))
	}
	return s, nil
}

// persist records the proposal and, when opted in, applies the transition.
func (w *ElevationWorker) persist(ctx context.Context, c candidate, d netpolicy.Decision) error {
	// No proposed change: clear any stale target and record the holding reason.
	if d.TargetMode == "" {
		_, err := w.db.Pool().Exec(ctx, `
UPDATE network_policy_lifecycle_states
   SET target_mode = NULL, reason = $3, updated_at = NOW()
 WHERE org_id = $1 AND workload = $2`, c.orgID, c.workload, d.Reason)
		return err
	}

	apply := false
	switch d.TargetMode {
	case netpolicy.ModeMonitor: // discover → monitor (non-blocking)
		apply = w.cfg.AutoPersist
	case netpolicy.ModeProtect: // monitor → protect (BLOCKING): needs both gates
		apply = w.cfg.AutoPersist && w.cfg.AutoEnforce
	}

	if apply {
		// Advance current_mode; mode_since resets so the next transition's
		// time-in-mode gate starts now. approval marks it machine-applied.
		_, err := w.db.Pool().Exec(ctx, `
UPDATE network_policy_lifecycle_states
   SET current_mode = $3, target_mode = NULL, approval_status = 'auto_applied',
       reason = $4, mode_since = NOW(), updated_at = NOW()
 WHERE org_id = $1 AND workload = $2`, c.orgID, c.workload, string(d.TargetMode), d.Reason)
		if err == nil {
			w.log.Info("ATMO applied transition",
				slog.String("workload", c.workload),
				slog.String("from", string(d.CurrentMode)),
				slog.String("to", string(d.TargetMode)))
		}
		return err
	}

	// Propose only: surface the recommendation for operator approval.
	_, err := w.db.Pool().Exec(ctx, `
UPDATE network_policy_lifecycle_states
   SET target_mode = $3, approval_status = 'pending', reason = $4, updated_at = NOW()
 WHERE org_id = $1 AND workload = $2`, c.orgID, c.workload, string(d.TargetMode), d.Reason)
	return err
}

func envBoolDefault(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "t", "true", "y", "yes", "on", "enabled":
		return true
	case "0", "f", "false", "n", "no", "off", "disabled":
		return false
	default:
		return def
	}
}

func envDurationDefault(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}
