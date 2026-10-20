package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/alphabravocompany/constellation/internal/netpolicyapply"
	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/internal/telemetry"
	"github.com/alphabravocompany/constellation/pkg/version"
)

const defaultInterval = 15 * time.Second

type config struct {
	databaseURL string
	kubeconfig  string
	clusterID   string
	clusterName string
	flavor      netpolicyapply.Flavor
	interval    time.Duration
	oneShot     bool
}

func loadConfig() (config, error) {
	var cfg config
	cfg.databaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if cfg.databaseURL == "" {
		return cfg, errors.New("DATABASE_URL is required")
	}
	cfg.kubeconfig = strings.TrimSpace(os.Getenv("KUBECONFIG"))
	cfg.clusterID = strings.TrimSpace(os.Getenv("CLUSTER_ID"))
	cfg.clusterName = strings.TrimSpace(os.Getenv("CLUSTER_NAME"))
	if cfg.clusterID == "" && cfg.clusterName == "" {
		return cfg, errors.New("CLUSTER_ID or CLUSTER_NAME is required")
	}
	flavor, err := netpolicyapply.ParseFlavor(os.Getenv("CONSTELLATION_NETWORK_POLICY_APPLIER_FLAVOR"))
	if err != nil {
		return cfg, err
	}
	cfg.flavor = flavor
	cfg.interval = defaultInterval
	if raw := strings.TrimSpace(os.Getenv("NETWORK_POLICY_APPLIER_INTERVAL")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return cfg, fmt.Errorf("NETWORK_POLICY_APPLIER_INTERVAL: %w", err)
		}
		if d > 0 {
			cfg.interval = d
		}
	}
	cfg.oneShot = strings.EqualFold(os.Getenv("ONE_SHOT"), "true") || os.Getenv("ONE_SHOT") == "1"
	return cfg, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()}))
	slog.SetDefault(logger)
	version.LogStartup(logger, "network-policy-applier")

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", slog.String("err", err.Error()))
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	tel, err := telemetry.Init(ctx, telemetry.ConfigFromEnv("constellation-netpolicy-applier"))
	if err != nil {
		logger.Error("telemetry init", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer func() {
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = tel.Shutdown(sctx)
	}()
	// Liveness/readiness/metrics for the Deployment probes and Prometheus (guide ch.05).
	telemetry.StartAdmin(ctx, telemetry.AdminAddrFromEnv(), tel.AdminHandler(telemetry.AdminOptions{}), logger)

	pool, err := pgxpool.New(ctx, cfg.databaseURL)
	if err != nil {
		logger.Error("db connect", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		logger.Error("db ping", slog.String("err", err.Error()))
		os.Exit(1)
	}

	restCfg, err := kubernetesConfig(cfg.kubeconfig)
	if err != nil {
		logger.Error("kube config", slog.String("err", err.Error()))
		os.Exit(1)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		logger.Error("dynamic client", slog.String("err", err.Error()))
		os.Exit(1)
	}
	protection, err := netpolicyapply.NewProtection(os.Getenv("CONSTELLATION_POD_NAMESPACE"), strings.Split(os.Getenv("CONSTELLATION_ENFORCEMENT_PROTECTED_NAMESPACES"), ","))
	if err != nil {
		logger.Error("network policy protection", slog.String("err", err.Error()))
		os.Exit(2)
	}
	client := netpolicyapply.KubernetesResourceClient{Client: dyn, FieldManager: "constellation-netpolicy-applier", Protection: protection}

	logger.Info("network policy applier starting",
		slog.String("cluster_id", cfg.clusterID),
		slog.String("cluster_name", cfg.clusterName),
		slog.String("flavor", string(cfg.flavor)),
		slog.Duration("interval", cfg.interval),
		slog.Bool("one_shot", cfg.oneShot))

	hbCfg := version.HeartbeatConfigFromEnv("network-policy-applier", version.HeartbeatEnvOptions{
		TokenEnv:     []string{"CONSTELLATION_NETWORK_POLICY_APPLIER_TOKEN", "RUNTIME_AGENT_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_NETWORK_POLICY_APPLIER_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE"},
		ClusterID:    cfg.clusterID,
		ClusterName:  cfg.clusterName,
		Logger:       logger,
		MetadataFn: func() any {
			return map[string]any{
				"flavor":           string(cfg.flavor),
				"interval_seconds": cfg.interval.Seconds(),
				"one_shot":         cfg.oneShot,
			}
		},
	})
	if cfg.oneShot {
		if version.HeartbeatConfigured(hbCfg) {
			if err := version.SendOnceExternal(ctx, hbCfg); err != nil {
				logger.Warn("heartbeat failed", slog.String("err", err.Error()))
			}
		}
	} else {
		go version.HeartbeatLoop(ctx, hbCfg)
	}

	if err := runOnce(ctx, pool, client, cfg, logger); err != nil {
		logger.Warn("first reconcile failed", slog.String("err", err.Error()))
	}
	if cfg.oneShot {
		return
	}

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("network policy applier shutting down")
			return
		case <-ticker.C:
			if err := runOnce(ctx, pool, client, cfg, logger); err != nil {
				logger.Warn("reconcile failed", slog.String("err", err.Error()))
			}
		}
	}
}

func kubernetesConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func runOnce(ctx context.Context, pool *pgxpool.Pool, client netpolicyapply.ResourceClient, cfg config, logger *slog.Logger) error {
	clusterID, err := resolveClusterID(ctx, pool, cfg)
	if err != nil {
		return err
	}
	states, err := loadActionableStates(ctx, pool, clusterID, cfg.flavor)
	if err != nil {
		return err
	}
	for _, state := range states {
		result, err := reconcileLifecycleState(ctx, pool, client, state, cfg.flavor)
		if err != nil {
			logger.Warn("policy reconcile failed",
				slog.String("workload", state.Workload),
				slog.String("err", err.Error()))
			continue
		}
		attrs := []any{
			slog.String("workload", state.Workload),
			slog.String("action", string(result.Action)),
			slog.String("status", string(result.Status)),
			slog.String("resource", result.ResourceRef),
		}
		if result.Error != "" {
			attrs = append(attrs, slog.String("err", result.Error))
		}
		logger.Info("network policy reconciled", attrs...)
	}
	if err := reconcileEnforcement(ctx, pool, client, clusterID, logger); err != nil {
		logger.Warn("enforcement reconcile failed", slog.String("err", err.Error()))
	}
	return nil
}

// reconcileEnforcement applies Phase-1 block/isolate actions to the cluster.
// active  -> apply the stored manifest; lifting -> delete it, then mark removed.
// The manifest carries its own flavor (native NetworkPolicy for isolate, Cilium
// CiliumNetworkPolicy for block_ip), independent of the applier's allow-policy flavor.
func reconcileEnforcement(ctx context.Context, pool *pgxpool.Pool, client netpolicyapply.ResourceClient, clusterID string, logger *slog.Logger) error {
	rows, err := pool.Query(ctx, `
SELECT id::text, manifest_flavor, manifest, state
  FROM network_enforcement_actions
 WHERE cluster_id = $1 AND state IN ('active', 'lifting')`, clusterID)
	if err != nil {
		return err
	}
	type action struct{ id, flavor, manifest, state string }
	var actions []action
	for rows.Next() {
		var a action
		if err := rows.Scan(&a.id, &a.flavor, &a.manifest, &a.state); err != nil {
			rows.Close()
			return err
		}
		actions = append(actions, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, a := range actions {
		if err := reconcileEnforcementAction(ctx, pool, client, a.id, a.flavor, a.manifest, a.state); err != nil {
			logger.Warn("enforcement reconcile failed", slog.String("id", a.id), slog.String("err", err.Error()))
		}
	}
	return nil
}

// Lock the intent across the Kubernetes operation and its report. A lift waits
// for an in-flight apply, and another applier must recheck state after acquiring
// the lock, preventing stale snapshots from recreating a removed policy.
func reconcileEnforcementAction(ctx context.Context, pool *pgxpool.Pool, client netpolicyapply.ResourceClient, id, flavor, manifest, expectedState string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var current string
	err = tx.QueryRow(ctx, `SELECT state FROM network_enforcement_actions WHERE id=$1 FOR UPDATE`, id).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if current != expectedState || (current != "active" && current != "lifting") {
		return nil
	}
	resource, manifestJSON, operationErr := netpolicyapply.ParseManifest(netpolicyapply.Flavor(flavor), manifest)
	newState := ""
	if operationErr == nil {
		if current == "lifting" {
			operationErr = client.Delete(ctx, resource)
			if operationErr == nil {
				newState = "removed"
			}
		} else {
			operationErr = client.Apply(ctx, resource, manifestJSON)
		}
	}
	status, message := "ok", ""
	if operationErr != nil {
		status, message = "error", operationErr.Error()
	}
	if err := updateEnforcementStatus(ctx, tx, id, current, status, message, newState); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type enforcementStatusWriter interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// updateEnforcementStatus records the reconcile outcome; newState (when non-empty)
// transitions the row (e.g. lifting -> removed after a successful delete).
func updateEnforcementStatus(ctx context.Context, pool enforcementStatusWriter, id, expectedState, status, errMsg, newState string) error {
	_, err := pool.Exec(ctx, `
UPDATE network_enforcement_actions
   SET last_status = $2,
       last_error = $3,
       state = COALESCE(NULLIF($4,''), state),
       last_applied_at = CASE WHEN $2 = 'ok' AND $4 = '' THEN NOW() ELSE last_applied_at END,
       last_deleted_at = CASE WHEN $2 = 'ok' AND $4 = 'removed' THEN NOW() ELSE last_deleted_at END,
       updated_at = NOW()
 WHERE id = $1 AND state = $5`, id, status, errMsg, newState, expectedState)
	return err
}

func resolveClusterID(ctx context.Context, pool *pgxpool.Pool, cfg config) (string, error) {
	if cfg.clusterID != "" {
		return cfg.clusterID, nil
	}
	var id string
	err := pool.QueryRow(ctx, `
SELECT id::text
  FROM clusters
 WHERE name = $1
 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END, last_heartbeat_at DESC NULLS LAST, created_at ASC
 LIMIT 1`, cfg.clusterName).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("cluster %q not found", cfg.clusterName)
	}
	if err != nil {
		return "", fmt.Errorf("resolve cluster %q: %w", cfg.clusterName, err)
	}
	return id, nil
}

func loadActionableStates(ctx context.Context, pool *pgxpool.Pool, clusterID string, flavor netpolicyapply.Flavor) ([]netpolicyapply.LifecycleState, error) {
	rows, err := pool.Query(ctx, `
SELECT org_id::text, cluster_id::text, workload, namespace, current_mode, approval_status,
       COALESCE(candidate_hash, ''), COALESCE(applied_ref, ''), COALESCE(rollback_ref, ''),
       preview_manifests
  FROM network_policy_lifecycle_states
 WHERE cluster_id = $1
   AND approval_status IN ('applied', 'demoted', 'rolled_back')
   AND preview_manifests ? $2
 ORDER BY namespace, workload`, clusterID, string(flavor))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var states []netpolicyapply.LifecycleState
	for rows.Next() {
		var state netpolicyapply.LifecycleState
		var manifestsRaw []byte
		if err := rows.Scan(&state.OrgID, &state.ClusterID, &state.Workload, &state.Namespace, &state.CurrentMode, &state.ApprovalStatus, &state.CandidateHash, &state.AppliedRef, &state.RollbackRef, &manifestsRaw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(manifestsRaw, &state.Manifests); err != nil {
			state.Manifests = map[string]string{}
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

// Re-read intent under its row lock rather than executing the polling snapshot.
// Demotion, rollback, candidate replacement and concurrent appliers serialize with
// the Kubernetes operation and its status write.
func reconcileLifecycleState(ctx context.Context, pool *pgxpool.Pool, client netpolicyapply.ResourceClient, key netpolicyapply.LifecycleState, flavor netpolicyapply.Flavor) (netpolicyapply.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	skipped := netpolicyapply.Result{Action: netpolicyapply.ActionSkip, Status: netpolicyapply.StatusSkipped}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return skipped, err
	}
	defer tx.Rollback(ctx)
	var state netpolicyapply.LifecycleState
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT org_id::text,cluster_id::text,workload,namespace,current_mode,approval_status,
 COALESCE(candidate_hash,''),COALESCE(applied_ref,''),COALESCE(rollback_ref,''),preview_manifests
 FROM network_policy_lifecycle_states WHERE org_id=$1 AND cluster_id=$2 AND workload=$3 FOR UPDATE`, key.OrgID, key.ClusterID, key.Workload).Scan(
		&state.OrgID, &state.ClusterID, &state.Workload, &state.Namespace, &state.CurrentMode, &state.ApprovalStatus, &state.CandidateHash, &state.AppliedRef, &state.RollbackRef, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return skipped, nil
	}
	if err != nil {
		return skipped, err
	}
	if netpolicyapply.DesiredAction(state) == netpolicyapply.ActionSkip {
		return skipped, nil
	}
	if err := json.Unmarshal(raw, &state.Manifests); err != nil {
		return skipped, fmt.Errorf("decode current policy manifests: %w", err)
	}
	result := netpolicyapply.ReconcileState(ctx, client, state, flavor)
	if err := recordStatus(ctx, tx, state, flavor, result); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func recordStatus(ctx context.Context, pool enforcementStatusWriter, state netpolicyapply.LifecycleState, flavor netpolicyapply.Flavor, result netpolicyapply.Result) error {
	_, err := pool.Exec(ctx, `
INSERT INTO network_policy_apply_status (
    org_id, cluster_id, workload, namespace, flavor, resource_ref, desired_mode, approval_status,
    last_action, status, error, candidate_hash, applied_ref, rollback_ref,
    last_applied_at, last_deleted_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,''),NULLIF($13,''),NULLIF($14,''),
    CASE WHEN $9 = 'apply' AND $10 = 'ok' THEN NOW() ELSE NULL END,
    CASE WHEN $9 = 'delete' AND $10 = 'ok' THEN NOW() ELSE NULL END,
    NOW()
)
ON CONFLICT (org_id, cluster_id, workload, flavor) DO UPDATE SET
    namespace = EXCLUDED.namespace,
    resource_ref = EXCLUDED.resource_ref,
    desired_mode = EXCLUDED.desired_mode,
    approval_status = EXCLUDED.approval_status,
    last_action = EXCLUDED.last_action,
    status = EXCLUDED.status,
    error = EXCLUDED.error,
    candidate_hash = EXCLUDED.candidate_hash,
    applied_ref = EXCLUDED.applied_ref,
    rollback_ref = EXCLUDED.rollback_ref,
    last_applied_at = COALESCE(EXCLUDED.last_applied_at, network_policy_apply_status.last_applied_at),
    last_deleted_at = COALESCE(EXCLUDED.last_deleted_at, network_policy_apply_status.last_deleted_at),
    updated_at = NOW()`,
		state.OrgID, state.ClusterID, state.Workload, state.Namespace, string(flavor), result.ResourceRef, state.CurrentMode, state.ApprovalStatus,
		string(result.Action), string(result.Status), result.Error, state.CandidateHash, state.AppliedRef, state.RollbackRef)
	return err
}
