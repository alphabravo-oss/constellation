-- Network-map perf (Tier 1): the /network/map and /network/conversations
-- aggregations filter network_flows by (org_id, cluster_id, at >= now()-window)
-- but no index covered that combination, so on a large table the planner did a
-- full parallel seq scan of the default partition (millions of rows) plus an
-- on-disk sort — ~13s for a single day's window. This composite index lets the
-- window filter use an index range scan instead. It also serves the
-- recentFlows ORDER BY at DESC LIMIT 50 path directly.
--
-- Aggregation cost (GROUP BY over the selected rows) is addressed separately by
-- the network_flow_rollups pre-aggregate (migration 115).

-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_flows_org_cluster_at
    ON network_flows (org_id, cluster_id, at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_flows_org_cluster_at;
-- +goose StatementEnd
