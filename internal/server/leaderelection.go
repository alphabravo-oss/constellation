package server

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/findings"
	"github.com/alphabravocompany/constellation/internal/handler/network"
	"github.com/alphabravocompany/constellation/internal/handler/runtime"
	"github.com/alphabravocompany/constellation/internal/syscfg"
	"github.com/alphabravocompany/constellation/pkg/backup"
	regsecrets "github.com/alphabravocompany/constellation/pkg/registry/secrets"
)

// startBackgroundWork starts the singleton background loops, optionally gated
// behind a Kubernetes Lease so only one api replica runs them.
//
// LEADER_ELECTION_ENABLED defaults to off: in that mode the loops start inline
// on this replica exactly as they always have, so the single-replica deploy is
// byte-for-byte unchanged. When enabled, the loops only run while this replica
// holds the lease; on lease loss the leader-election context is canceled, which
// cancels every loop (they all derive from it).
func (s *Server) startBackgroundWork(ctx context.Context) {
	if !envBool("LEADER_ELECTION_ENABLED", false) {
		s.startSingletonLoops(ctx)
		return
	}
	go s.runLeaderElection(ctx)
}

// startSingletonLoops launches every cluster-wide singleton loop. Each loop
// already exits when its context is canceled, so a single ctx governs all of
// them. This is the set of loops that must NOT be duplicated across replicas.
func (s *Server) startSingletonLoops(ctx context.Context) {
	// Live CVE-intelligence: CISA KEV + FIRST EPSS straight from the public feeds
	// (the live replacement for the dropped vulndb bundle). Fills cve_records with
	// known-exploited flags + exploit-probability scores; NVD base catalog is a
	// syscfg-gated follow-up. URLs overridable for air-gapped mirrors.
	go findings.ReconcileCVEIntelLoop(ctx, s.db.Pool(), findings.CVEIntelConfig{}, s.tel.Logger)
	// NVD full-catalog importer (descriptions + CVSS). Opt-in + keyed via
	// system_config (nvd_enabled / nvd_api_key / nvd_mirror_url). No-op until enabled.
	go findings.ReconcileNVDLoop(ctx, s.db.Pool(), 0, s.tel.Logger)
	// Opt-in CVE enrichment (descriptions/remediation) from a separate artifact;
	// no-op unless CONSTELLATION_CVE_ENRICHMENT_PATH is delivered (air-gapped).
	go findings.ReconcileCVEEnrichmentLoop(ctx, s.db.Pool(), strings.TrimSpace(os.Getenv("CONSTELLATION_CVE_ENRICHMENT_PATH")), 0, s.tel.Logger)
	// G3b: federation joint poller. No-op unless this controller is a joint with
	// CONSTELLATION_FED_MASTER_URL set; pulls master /sync and replicates fed rules.
	// D2: the install-KEK cipher decrypts the joint's stored client key so the poll
	// presents its per-joint client cert (mutual auth). A cipher failure leaves the
	// poller on the D1 bearer-only path (nil sealer) rather than blocking startup.
	var fedSealer auth.Sealer
	if cipher, cerr := regsecrets.Default(ctx, s.db.Pool(), s.tel.Logger); cerr == nil {
		fedSealer = cipher
	}
	go handler.ReconcileFedSyncLoop(ctx, s.db.Pool(), fedSealer,
		strings.TrimSpace(os.Getenv("CONSTELLATION_FED_MASTER_URL")),
		strings.TrimSpace(os.Getenv("CONSTELLATION_FED_MASTER_TOKEN")), 0, s.tel.Logger)

	// Wave A5: auto-rollback watcher. Demotes enforce-mode runtime_policies
	// back to monitor when their deny-rate spikes past threshold.
	rollbackStore := runtime.NewRuntimePolicyStore(s.db, s.auditLog)
	rollbackWatcher := runtime.NewPolicyRollbackWatcher(rollbackStore,
		runtime.DefaultRollbackConfig(), s.tel.Logger)
	go rollbackWatcher.Run(ctx)

	// P2-1: ATMO auto mode-elevation worker. Leader-gated background driver that
	// periodically re-evaluates the discover→monitor→protect candidates and
	// records proposals. Disabled by default (CONSTELLATION_ATMO_WORKER_ENABLED);
	// even when enabled it only PROPOSES unless CONSTELLATION_ATMO_AUTO_PERSIST is
	// set, and can only auto-enter the blocking protect mode with the additional
	// CONSTELLATION_ATMO_AUTO_ENFORCE — so it can never silently start enforcing.
	elevationWorker := runtime.NewElevationWorker(s.db, runtime.ElevationWorkerConfigFromEnv(), s.tel.Logger)
	go elevationWorker.Run(ctx)

	// P0-05: learned-group synthesizer. NeuVector auto-creates an nv.<service>
	// learned group when a workload appears; Constellation's learner was dead code
	// (no ingest path called it). This leader-gated worker reads the observed
	// deployments and upserts one cfg_type='learned' group per (cluster, namespace,
	// service). Enabled by default — the groups are inert discover-mode anchors that
	// change nothing about enforcement (CONSTELLATION_LEARNED_GROUPS_ENABLED=false to
	// opt out).
	learnedGroupWorker := runtime.NewLearnedGroupWorker(s.db, runtime.LearnedGroupWorkerConfigFromEnv(), s.tel.Logger)
	go learnedGroupWorker.Run(ctx)

	// P0-06: live group-membership reconcile (NeuVector groupWorkloadJoin/Leave
	// parity). Recomputes groups.members from current deployments and re-expands
	// group→group edges whose membership changed, so a rule authored against a
	// group follows future pod replicas instead of going stale until the next
	// group write. Singleton (deployment ingest lands out-of-band via the
	// discoverer); on by default. Re-expansion honors each edge's authored mode, so
	// a protect-mode edge produces ENFORCING default-deny policies for newly-joined
	// members by design (see edgePolicyPosture); gate off with
	// CONSTELLATION_GROUP_MEMBERSHIP_RECONCILE=false.
	membershipReconciler := runtime.NewGroupMembershipReconciler(s.db,
		runtime.NewRuntimePolicyStore(s.db, s.auditLog), s.tel.Logger)
	go membershipReconciler.Run(ctx)

	// Retention horizons resolved LIVE from system config (primary org) each pass, so
	// an admin can set them from the Settings UI without a restart. 0 days = disabled
	// (falls back to any env default). Bounds the two biggest storage sinks.
	retentionResolver := func(pick func(syscfg.Config) int) func(context.Context) time.Duration {
		return func(rctx context.Context) time.Duration {
			if s.syscfg == nil {
				return 0
			}
			var orgID uuid.UUID
			if err := s.db.Pool().QueryRow(rctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
				return 0
			}
			return time.Duration(pick(s.syscfg.Get(rctx, orgID))) * 24 * time.Hour
		}
	}
	// Day-count variant of the same resolver, for the partition manager (which drops
	// whole daily partitions past the horizon rather than DELETE-ing rows).
	retentionDaysResolver := func(pick func(syscfg.Config) int) func(context.Context) int {
		return func(rctx context.Context) int {
			if s.syscfg == nil {
				return 0
			}
			var orgID uuid.UUID
			if err := s.db.Pool().QueryRow(rctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
				return 0
			}
			return pick(s.syscfg.Get(rctx, orgID))
		}
	}

	// Auto-scan running workloads (NeuVector enable_auto_scan_workload): the discoverer
	// inventories running images but does NOT scan them — this loop closes that gap by
	// (re)scanning each running image via the live Trivy/Grype pipeline on a cadence.
	// Default ON (auto_scan_disabled=false); rescan window from auto_scan_rescan_hours.
	go handler.RunWorkloadAutoScan(ctx, s.db.Pool(),
		func(rctx context.Context) bool {
			if s.syscfg == nil {
				return true
			}
			var orgID uuid.UUID
			if err := s.db.Pool().QueryRow(rctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
				return true
			}
			return !s.syscfg.Get(rctx, orgID).AutoScanDisabled
		},
		retentionDaysResolver(func(c syscfg.Config) int { return c.AutoScanRescanHours }),
		s.tel.Logger)

	// Partition manager: pre-create daily partitions for events + network_flows and DROP
	// ones past the retention horizon. A partition DROP reclaims disk instantly (no dead-
	// tuple bloat), so this is the primary retention mechanism for the two big time-series
	// tables; the DELETE loops above drain the legacy DEFAULT partition of pre-partitioning
	// history. Leader-gated.
	go handler.RunPartitionManager(ctx, s.db.Pool(), []handler.PartitionedTable{
		{Parent: "events", RetentionDays: retentionDaysResolver(func(c syscfg.Config) int { return c.EventsRetentionDays })},
		{Parent: "network_flows", RetentionDays: retentionDaysResolver(func(c syscfg.Config) int { return c.NetworkFlowRetentionDays })},
	}, s.tel.Logger)

	// NET perf: keep the network_flow_rollups pre-aggregate hot (the durable
	// backing for /network/map + /network/conversations). Singleton so replicas
	// don't race the fold watermark; retention prune reads the live horizon.
	rollupRefresher := network.NewRollupRefresher(s.db)
	rollupRefresher.SetRetentionResolver(retentionResolver(func(c syscfg.Config) int { return c.NetworkFlowRetentionDays }))
	rollupRefresher.Start(ctx)

	// Events retention: prune the events table (the other unbounded sink) on the live
	// horizon. Leader-gated + batched; no-op while events_retention_days is 0.
	go handler.RunEventsRetentionMonitor(ctx, s.db.Pool(),
		retentionResolver(func(c syscfg.Config) int { return c.EventsRetentionDays }), s.tel.Logger)

	// scan_jobs retention: prune terminal (completed/failed/canceled) jobs past the
	// horizon (NeuVector-style stale-job cleanup). Live jobs + image_scan_results untouched.
	go handler.RunScanJobsRetentionMonitor(ctx, s.db.Pool(),
		retentionResolver(func(c syscfg.Config) int { return c.ScanJobRetentionDays }), s.tel.Logger)

	// Orphan evidence scan-result cleanup: drop digest-only image_scan_results that no
	// longer back a running workload (node-local evidence of dead containers). Keeps the
	// CVE affected-images list honest; named registry scans untouched. Runs once on start.
	go handler.RunOrphanImageScanResultMonitor(ctx, s.db.Pool(), s.tel.Logger)

	// Phase B: retroactively re-resolve flows stamped "cluster/<ip>" at ingest,
	// now that pod_ips retains history and the resolver is time-aware. Shares the
	// rollup refresher so it can refold the buckets its rewrites disturb. Leader-
	// gated (derives from ctx) so replicas don't race each other or the watermark.
	network.NewFlowBackfiller(s.db, rollupRefresher).Start(ctx)

	// A9: scheduled-backup executor + retention. Leader-gated cron runner for the
	// per-org backup_schedules an operator created via the /backups/schedule API. With
	// no schedules it is a pure no-op; it never enables/deletes/enforces anything on live
	// workloads, only reading org data into a tarball and pruning its own old artifacts.
	go backup.RunScheduleExecutor(ctx, s.db.Pool(), backup.ScheduleExecutorConfig{
		BackupDir:   env("CONSTELLATION_BACKUP_DIR", "/var/lib/constellation/backups"),
		SignKeyPath: os.Getenv("CONSTELLATION_BACKUP_SIGN_KEY"),
	}, s.tel.Logger)

	// P1-11: scheduled registry rescan. NeuVector enforces per-registry Schedule
	// (auto/periodical + PollPeriod) via an always-on in-controller scheduler. The
	// standalone constellation-registry-walker binary implements the same cadence
	// loop but ships in no Dockerfile/Helm/systemd/compose, so in every shipped
	// deployment only the manual sync-now path fired. Run the same loop here,
	// leader-gated, so auto/hourly/6h/daily/weekly cadences actually fire. Each tick
	// takes a pg_advisory_xact_lock per registry, so it never double-walks. On by
	// default; gate off with CONSTELLATION_REGISTRY_WALKER_ENABLED=false.
	if envBool("CONSTELLATION_REGISTRY_WALKER_ENABLED", true) {
		go handler.RunRegistryWalker(ctx, s.db.Pool(), s.tel.Logger, s.auditLog,
			registryWalkerConcurrency(), registryWalkerInterval())
	}

	// P1-18: deliver admission-deny notifications (NeuVector EventAdmCtrl -> webhookAudit
	// + logAudit parity). The constellation-admission webhook pod writes admission.deny
	// audit rows directly but has no dispatcher; this leader-gated poller fans each new
	// deny out through the notify.Dispatcher so org webhook receivers and the syslog/SIEM
	// mirror actually see Constellation's own admission denies. A durable single-row cursor
	// makes it exactly-once across restarts.
	go handler.RunAdmissionNotifyDispatcher(ctx, s.db.Pool(), s.dispatcher, 0, s.tel.Logger)

	go handler.RunRepositoryScanRetentionMonitor(ctx, s.db.Pool(), handler.RepositoryScanRetentionConfig{
		Enabled:   s.cfg.RepositoryScanRetentionEnabled,
		MaxAge:    s.cfg.RepositoryScanRetentionMaxAge,
		Interval:  s.cfg.RepositoryScanRetentionInterval,
		BatchSize: s.cfg.RepositoryScanRetentionBatchSize,
		DryRun:    s.cfg.RepositoryScanRetentionDryRun,
	}, s.tel.Logger)
}

// registryWalkerInterval reads WALKER_INTERVAL (a Go duration, e.g. "60s"),
// falling back to the handler default when unset or unparseable.
func registryWalkerInterval() time.Duration {
	if v := strings.TrimSpace(os.Getenv("WALKER_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return handler.DefaultRegistryWalkerInterval
}

// registryWalkerConcurrency reads WALKER_CONCURRENCY, falling back to the handler
// default when unset or invalid.
func registryWalkerConcurrency() int {
	if v := strings.TrimSpace(os.Getenv("WALKER_CONCURRENCY")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return handler.DefaultRegistryWalkerConcurrency
}

// env returns the env var or a default when unset/empty.
func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// envBool parses a boolean env var, returning def when unset or unparseable.
func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "t", "true", "y", "yes", "on", "enabled":
		return true
	case "0", "f", "false", "n", "no", "off", "disabled":
		return false
	default:
		return def
	}
}

// runLeaderElection blocks (until ctx is done) running a client-go lease-based
// leader election. Only the elected leader runs the singleton loops. It mirrors
// the operator's lease pattern (cmd/constellation-operator/main.go).
func (s *Server) runLeaderElection(ctx context.Context) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		// No in-cluster config (e.g. run outside k8s): fail safe by running the
		// loops inline rather than silently disabling them.
		s.tel.Logger.Warn("leader election enabled but no in-cluster config; running singleton loops without a lease",
			slog.String("err", err.Error()))
		s.startSingletonLoops(ctx)
		<-ctx.Done()
		return
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		s.tel.Logger.Warn("leader election: kubernetes client init failed; running singleton loops without a lease",
			slog.String("err", err.Error()))
		s.startSingletonLoops(ctx)
		<-ctx.Done()
		return
	}

	namespace := env("POD_NAMESPACE", env("LEADER_ELECTION_NAMESPACE", "constellation-system"))
	identity := env("POD_NAME", env("HOSTNAME", "constellation-api"))
	leaseName := env("LEADER_ELECTION_ID", "constellation-api.alphabravo.io")

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace},
		Client:    client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: identity,
		},
	}

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leaderCtx context.Context) {
				s.tel.Logger.Info("acquired leader lease; starting singleton loops",
					slog.String("lease", leaseName), slog.String("identity", identity))
				s.startSingletonLoops(leaderCtx)
			},
			OnStoppedLeading: func() {
				// leaderCtx passed to OnStartedLeading is canceled before this
				// fires, so the loops are already winding down.
				s.tel.Logger.Info("lost leader lease; singleton loops stopping",
					slog.String("lease", leaseName), slog.String("identity", identity))
			},
		},
	})
}
