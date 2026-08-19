package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

type admissionPolicyRow struct {
	Name        string
	Description string
	Mode        string
	SpecYAML    string
}

// loadPolicyRowsByEngine fetches the active, deduped policy rows for one engine
// kind (e.g. "constellation-admission", "opa", "cel"). The newest enabled
// version wins per name, preferring cluster-scoped rows over org-wide ones.
func loadPolicyRowsByEngine(ctx context.Context, pool *pgxpool.Pool, clusterID uuid.UUID, engine string) ([]admissionPolicyRow, error) {
	rows, err := pool.Query(ctx, `
SELECT DISTINCT ON (p.name)
       p.name, COALESCE(p.description, ''), p.mode, p.spec_yaml
  FROM policies p
  JOIN clusters c ON c.id = $1 AND c.org_id = p.org_id
 WHERE p.enabled = TRUE
   AND p.engine = $2
   AND (p.cluster_id IS NULL OR p.cluster_id = $1)
 ORDER BY p.name,
          CASE WHEN p.cluster_id = $1 THEN 1 ELSE 0 END DESC,
          p.version DESC,
          p.updated_at DESC`, clusterID, engine)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	policies := []admissionPolicyRow{}
	for rows.Next() {
		var row admissionPolicyRow
		if err := rows.Scan(&row.Name, &row.Description, &row.Mode, &row.SpecYAML); err != nil {
			return nil, err
		}
		policies = append(policies, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return policies, nil
}

func loadAdmissionPolicyRules(ctx context.Context, pool *pgxpool.Pool, clusterID uuid.UUID) ([]admission.Rule, error) {
	policies, err := loadPolicyRowsByEngine(ctx, pool, clusterID, "constellation-admission")
	if err != nil {
		return nil, err
	}
	return admissionPolicyRowsToRules(policies)
}

// loadRegoEngine compiles every engine='opa' row into a RegoEngine. The
// spec_yaml column holds the Rego module source verbatim. Per-rule compile
// errors are logged (and the offending policy skipped) rather than failing the
// whole reload, matching the catalog's "one bad row never wedges the rest" rule.
func loadRegoEngine(ctx context.Context, pool *pgxpool.Pool, clusterID uuid.UUID, logger *slog.Logger) (*admission.RegoEngine, error) {
	rows, err := loadPolicyRowsByEngine(ctx, pool, clusterID, "opa")
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	modules := make(map[string]string, len(rows))
	modes := make(map[string]string, len(rows))
	for _, row := range rows {
		modules[row.Name] = row.SpecYAML
		modes[row.Name] = row.Mode
	}
	eng, compileErrs, err := admission.NewRegoEngine(ctx, modules, modes)
	if err != nil {
		return nil, err
	}
	for id, cerr := range compileErrs {
		logger.Warn("admission rego policy compile failed; skipping", "policy", id, "err", cerr)
	}
	return eng, nil
}

// celPolicySpec is the spec_yaml shape for engine='cel' rows: a CEL boolean
// expression (true = allow) plus an optional message expression.
type celPolicySpec struct {
	Spec struct {
		Expression        string `yaml:"expression"`
		MessageExpression string `yaml:"messageExpression"`
	} `yaml:"spec"`
}

// loadCELEngine compiles every engine='cel' row into a CELEngine. Per-rule
// compile errors are logged and the policy skipped, never failing the reload.
func loadCELEngine(ctx context.Context, pool *pgxpool.Pool, clusterID uuid.UUID, logger *slog.Logger) (*admission.CELEngine, error) {
	rows, err := loadPolicyRowsByEngine(ctx, pool, clusterID, "cel")
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	celRules := make([]*admission.CELRule, 0, len(rows))
	for _, row := range rows {
		var spec celPolicySpec
		if err := yaml.Unmarshal([]byte(row.SpecYAML), &spec); err != nil {
			logger.Warn("admission cel policy parse failed; skipping", "policy", row.Name, "err", err)
			continue
		}
		celRules = append(celRules, &admission.CELRule{
			ID:                row.Name,
			Expression:        spec.Spec.Expression,
			MessageExpression: spec.Spec.MessageExpression,
			Mode:              row.Mode,
		})
	}
	eng, compileErrs, err := admission.NewCELEngine(celRules)
	if err != nil {
		return nil, err
	}
	for id, cerr := range compileErrs {
		logger.Warn("admission cel policy compile failed; skipping", "policy", id, "err", cerr)
	}
	return eng, nil
}

func admissionPolicyRowsToRules(rows []admissionPolicyRow) ([]admission.Rule, error) {
	rules := make([]admission.Rule, 0, len(rows))
	for _, row := range rows {
		rule, supported, err := admission.RuleFromYAML(row.Name, row.Name, row.Description, row.Mode, row.SpecYAML)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", row.Name, err)
		}
		if supported {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// refreshAdmissionPolicies reloads all three engine kinds and swaps them into
// the composite chain: built-in rows onto the PolicyEngine, and the recompiled
// Rego/CEL engines onto the chain (nil = no rows of that kind, which disables it).
func refreshAdmissionPolicies(ctx context.Context, chain *admission.ChainEngine, pool *pgxpool.Pool, clusterID uuid.UUID, logger *slog.Logger) (int, error) {
	dbRules, err := loadAdmissionPolicyRules(ctx, pool, clusterID)
	if err != nil {
		return 0, err
	}
	rules := append(admission.DefaultRules(), dbRules...)
	chain.Policy().SetRules(rules)

	regoEngine, err := loadRegoEngine(ctx, pool, clusterID, logger)
	if err != nil {
		return 0, err
	}
	chain.SetRego(regoEngine)

	celEngine, err := loadCELEngine(ctx, pool, clusterID, logger)
	if err != nil {
		return 0, err
	}
	chain.SetCEL(celEngine)

	return len(dbRules), nil
}

func runAdmissionPolicyRefresh(ctx context.Context, chain *admission.ChainEngine, pool *pgxpool.Pool, clusterID uuid.UUID, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := refreshAdmissionPolicies(ctx, chain, pool, clusterID, logger)
			if err != nil {
				logger.Warn("admission policy refresh failed", "err", err)
				continue
			}
			logger.Info("admission policy refresh complete", "cluster_id", clusterID, "db_rules", n)
		}
	}
}
