-- +goose Up
-- +goose StatementBegin
-- The kube-bench / docker-bench host-compliance ingest (internal/handler/compliance
-- Ingest) INSERTs one row per control with cluster_id NULL and no de-duplication, so
-- the 6-hourly CronJob accumulates a fresh copy of every control on each run. After N
-- runs the Summary COUNT(*) is inflated N× and the Checks list (LIMIT 500) truncates
-- real controls behind duplicates.
--
-- These host-compliance rows are exactly the ones with cluster_id IS NULL. The
-- k8s-object collector (cmd/constellation-k8s-compliance-collector) is intentionally
-- NOT affected: it always writes a non-NULL cluster_id, legitimately stores many rows
-- per (framework, control_id) — one per evaluated object — and de-dupes itself with a
-- DELETE+reinsert. A unique index over (org_id, cluster_id, framework, control_id)
-- across all rows would break that path, so the index is scoped to the NULL-cluster
-- host-compliance rows via a partial index.
--
-- Collapse pre-existing duplicates first (keep the most-recently-evaluated row per
-- org_id+framework+control_id) so the index build does not fail on existing data —
-- following the dedup-before-constrain pattern of migration 061.
WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY org_id, framework, control_id
               ORDER BY evaluated_at DESC, id DESC
           ) AS rn
      FROM compliance_checks
     WHERE cluster_id IS NULL
)
DELETE FROM compliance_checks cc
 USING ranked r
 WHERE cc.id = r.id
   AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_compliance_checks_hostbench_unique
    ON compliance_checks (org_id, framework, control_id)
    WHERE cluster_id IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_compliance_checks_hostbench_unique;
-- +goose StatementEnd
