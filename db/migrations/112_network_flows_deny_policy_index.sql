-- +goose Up
-- +goose StatementBegin
-- The auto-rollback watcher (internal/handler/runtime PolicyRollbackWatcher)
-- runs every MinAge tick for every enforce-mode policy and executes:
--
--   SELECT COUNT(*) FROM network_flows
--    WHERE org_id = $1 AND cluster_id = $2 AND policy_id = $3
--      AND verdict = 'deny' AND at >= NOW() - ($4||' seconds')::interval
--
-- With no supporting index this full-scans every flow in the org (network_flows
-- is high-volume and partitioned by RANGE(at)), so each enforce policy costs a
-- table scan per tick. Add a composite partial index whose leading columns are
-- the query's equality predicates (org_id, cluster_id, policy_id) followed by
-- the at range/order column, restricted to verdict='deny' so the index stays
-- small (deny rows are the rare minority). This mirrors the existing partial
-- index idx_flows_org_threat added in migration 040.
--
-- CREATE INDEX on the partitioned parent cascades to all partitions. Partial
-- indexes on partitioned tables are supported since PG11.
CREATE INDEX IF NOT EXISTS idx_flows_deny_policy
    ON network_flows (org_id, cluster_id, policy_id, at DESC)
    WHERE verdict = 'deny';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_flows_deny_policy;
-- +goose StatementEnd
