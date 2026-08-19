// constellation-k8s-compliance-collector reads Kubernetes API objects and writes
// direct object evidence into compliance_checks.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/alphabravocompany/constellation/internal/k8scompliance"
	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/compliance"
	"github.com/alphabravocompany/constellation/pkg/version"
)

const defaultInterval = 6 * time.Hour

type config struct {
	databaseURL             string
	clusterID               *uuid.UUID
	clusterName             string
	kubeconfig              string
	namespaceFilter         []string
	includeSystemNamespaces bool
	interval                time.Duration
	oneShot                 bool
}

type clusterRef struct {
	ID    uuid.UUID
	OrgID uuid.UUID
	Name  string
}

type collectorHeartbeatState struct {
	mu                      sync.Mutex
	lastRows                int
	lastError               string
	lastRunAt               time.Time
	interval                time.Duration
	oneShot                 bool
	namespaceFilter         []string
	includeSystemNamespaces bool
}

func (s *collectorHeartbeatState) record(rows int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRows = rows
	s.lastRunAt = time.Now().UTC()
	if err != nil {
		s.lastError = err.Error()
		return
	}
	s.lastError = ""
}

func (s *collectorHeartbeatState) lastErrorValue() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastError
}

func (s *collectorHeartbeatState) snapshot() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var lastRun any
	if !s.lastRunAt.IsZero() {
		lastRun = s.lastRunAt.Format(time.RFC3339)
	}
	return map[string]any{
		"last_rows":                 s.lastRows,
		"last_run_at":               lastRun,
		"interval_seconds":          s.interval.Seconds(),
		"one_shot":                  s.oneShot,
		"namespace_filter":          s.namespaceFilter,
		"include_system_namespaces": s.includeSystemNamespaces,
	}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "constellation-k8s-compliance-collector")
	version.LogStartup(logger, "k8s-compliance-collector")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.databaseURL)
	if err != nil {
		logger.Error("pgxpool", "err", err.Error())
		os.Exit(1)
	}
	defer pool.Close()

	cluster, err := resolveCluster(ctx, pool, cfg)
	if err != nil {
		logger.Error("resolve cluster", "err", err.Error())
		os.Exit(1)
	}
	client, err := kubeClient(cfg.kubeconfig)
	if err != nil {
		logger.Error("kubernetes client", "err", err.Error())
		os.Exit(1)
	}

	clusterID := ""
	if cfg.clusterID != nil {
		clusterID = cfg.clusterID.String()
	}
	hbState := &collectorHeartbeatState{
		interval:                cfg.interval,
		oneShot:                 cfg.oneShot,
		namespaceFilter:         append([]string(nil), cfg.namespaceFilter...),
		includeSystemNamespaces: cfg.includeSystemNamespaces,
	}
	hbCfg := version.HeartbeatConfigFromEnv("k8s-compliance-collector", version.HeartbeatEnvOptions{
		TokenEnv:     []string{"CONSTELLATION_K8S_COMPLIANCE_COLLECTOR_TOKEN", "RUNTIME_AGENT_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_K8S_COMPLIANCE_COLLECTOR_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE"},
		ClusterID:    clusterID,
		ClusterName:  cfg.clusterName,
		Logger:       logger,
		LastErrorFn:  hbState.lastErrorValue,
		MetadataFn:   hbState.snapshot,
	})
	if !cfg.oneShot {
		go version.HeartbeatLoop(ctx, hbCfg)
	}

	runOnce := func() {
		count, err := collectAndPersist(ctx, pool, client, cluster, cfg)
		hbState.record(count, err)
		if err != nil {
			logger.Error("collect failed", "cluster", cluster.Name, "err", err.Error())
			return
		}
		logger.Info("collect succeeded", "cluster", cluster.Name, "rows", count)
	}
	runOnce()
	if cfg.oneShot {
		if version.HeartbeatConfigured(hbCfg) {
			if err := version.SendOnceExternal(ctx, hbCfg); err != nil {
				logger.Warn("heartbeat failed", "err", err.Error())
			}
		}
		return
	}
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("collector stopping")
			return
		case <-ticker.C:
			runOnce()
		}
	}
}

func loadConfig() (config, error) {
	cfg := config{
		databaseURL: strings.TrimSpace(os.Getenv("DATABASE_URL")),
		clusterName: strings.TrimSpace(os.Getenv("CLUSTER_NAME")),
		kubeconfig:  strings.TrimSpace(os.Getenv("KUBECONFIG")),
		interval:    defaultInterval,
		oneShot:     strings.EqualFold(os.Getenv("ONE_SHOT"), "true"),
	}
	if cfg.databaseURL == "" {
		return cfg, errors.New("DATABASE_URL required")
	}
	if raw := strings.TrimSpace(os.Getenv("CLUSTER_ID")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return cfg, fmt.Errorf("CLUSTER_ID is not a valid uuid: %w", err)
		}
		cfg.clusterID = &id
	}
	if cfg.clusterID == nil && cfg.clusterName == "" {
		return cfg, errors.New("CLUSTER_ID or CLUSTER_NAME required")
	}
	rawFilter := strings.TrimSpace(os.Getenv("NAMESPACE_FILTER"))
	if rawFilter == "" {
		rawFilter = "*"
	}
	for _, part := range strings.Split(rawFilter, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			cfg.namespaceFilter = append(cfg.namespaceFilter, part)
		}
	}
	cfg.includeSystemNamespaces = strings.EqualFold(os.Getenv("INCLUDE_SYSTEM_NAMESPACES"), "true")
	if raw := strings.TrimSpace(os.Getenv("COMPLIANCE_COLLECTOR_INTERVAL")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return cfg, fmt.Errorf("COMPLIANCE_COLLECTOR_INTERVAL must be a positive duration")
		}
		cfg.interval = parsed
	}
	return cfg, nil
}

func resolveCluster(ctx context.Context, pool *pgxpool.Pool, cfg config) (clusterRef, error) {
	var ref clusterRef
	if cfg.clusterID != nil {
		err := pool.QueryRow(ctx, `SELECT id, org_id, name FROM clusters WHERE id = $1`, *cfg.clusterID).Scan(&ref.ID, &ref.OrgID, &ref.Name)
		if errors.Is(err, pgx.ErrNoRows) {
			return ref, fmt.Errorf("cluster id %s not found", cfg.clusterID.String())
		}
		return ref, err
	}
	err := pool.QueryRow(ctx, `
SELECT id, org_id, name
  FROM clusters
 WHERE name = $1
 ORDER BY updated_at DESC
 LIMIT 1`, cfg.clusterName).Scan(&ref.ID, &ref.OrgID, &ref.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return ref, fmt.Errorf("cluster %q not found", cfg.clusterName)
	}
	return ref, err
}

func kubeClient(kubeconfig string) (kubernetes.Interface, error) {
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
		return kubernetes.NewForConfig(cfg)
	}
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return kubernetes.NewForConfig(cfg)
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		path := filepath.Join(home, ".kube", "config")
		if _, statErr := os.Stat(path); statErr == nil {
			cfg, err = clientcmd.BuildConfigFromFlags("", path)
			if err != nil {
				return nil, err
			}
			return kubernetes.NewForConfig(cfg)
		}
	}
	return nil, err
}

func collectAndPersist(ctx context.Context, pool *pgxpool.Pool, client kubernetes.Interface, cluster clusterRef, cfg config) (int, error) {
	customChecks, err := loadCustomChecks(ctx, pool, cluster.OrgID)
	if err != nil {
		return 0, err
	}
	items, err := k8scompliance.Collect(ctx, client, k8scompliance.Options{
		NamespaceFilter:        cfg.namespaceFilter,
		IncludeSystemNamespace: cfg.includeSystemNamespaces,
		ObservedAt:             time.Now().UTC(),
		CustomChecks:           customChecks,
	})
	if err != nil {
		return 0, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
DELETE FROM compliance_checks
 WHERE org_id = $1
   AND cluster_id = $2
   AND evidence LIKE 'collector=constellation-k8s-object%'`, cluster.OrgID, cluster.ID); err != nil {
		return 0, err
	}
	rows := 0
	for _, item := range items {
		tagsRaw, _ := json.Marshal(compliance.BuildTagsV2(item.InternalID))
		for _, check := range item.Expand() {
			if _, err := tx.Exec(ctx, `
INSERT INTO compliance_checks (
    org_id, cluster_id, framework, control_id, title, description,
    status, severity, evidence, evaluated_at, tags_v2
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
				cluster.OrgID, cluster.ID, check.Framework, check.ControlID, check.Title,
				item.TargetKind+" "+item.Target, check.Status, check.Severity, check.Evidence,
				item.ObservedAt, tagsRaw); err != nil {
				return rows, err
			}
			rows++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return rows, err
	}
	emitCustomCheckViolations(ctx, pool, cluster, items)
	return rows, nil
}

// loadCustomChecks reads the org's enabled user-supplied CEL compliance checks. Parity with
// NeuVector's per-group custom check scripts (neuvector/controller/rest/bench.go).
func loadCustomChecks(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) ([]k8scompliance.CustomCheck, error) {
	rows, err := pool.Query(ctx, `
SELECT id, name, severity, target_kind, expression, remediation
  FROM custom_compliance_checks
 WHERE org_id = $1 AND enabled = TRUE`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var checks []k8scompliance.CustomCheck
	for rows.Next() {
		var (
			id                                      uuid.UUID
			name, severity, kind, expr, remediation string
		)
		if err := rows.Scan(&id, &name, &severity, &kind, &expr, &remediation); err != nil {
			return nil, err
		}
		checks = append(checks, k8scompliance.CustomCheck{
			ID:          id.String(),
			Name:        name,
			Severity:    severity,
			TargetKind:  kind,
			Expression:  expr,
			Remediation: remediation,
		})
	}
	return checks, rows.Err()
}

// emitCustomCheckViolations records an audit event for each object that failed a user-supplied
// custom check. Parity with NeuVector's CLUSAuditComplianceContainerCustomCheckViolation
// (neuvector/agent/bench.go:1048). Best-effort: a logging failure never fails the collection.
func emitCustomCheckViolations(ctx context.Context, pool *pgxpool.Pool, cluster clusterRef, items []k8scompliance.Evidence) {
	auditLog := audit.New(pool)
	orgID := cluster.OrgID
	for _, item := range items {
		if !item.Custom || item.Status != "fail" {
			continue
		}
		_, _, _ = auditLog.Log(ctx, audit.Event{
			OrgID:      &orgID,
			Action:     "compliance.custom_check.violation",
			TargetKind: item.TargetKind,
			TargetID:   item.Target,
			After: map[string]any{
				"check_id":   item.InternalID,
				"check":      item.Title,
				"severity":   item.Severity,
				"cluster_id": cluster.ID.String(),
				"evidence":   item.Evidence,
			},
		})
	}
}
