-- Network-map perf (Tier 2 support): the rollup refresher folds newly-ingested
-- flows by their timestamp (at > watermark) across all tenants, so it needs an
-- index on `at` alone — the (org_id,cluster_id,at) index (114) can't serve a
-- leading-column-free range, forcing a full scan each pass (~2 min on a large
-- table). A BRIN index is ideal here: network_flows is append-only and
-- time-correlated, so BRIN gives a tight range scan of only the recent blocks at
-- a fraction of a btree's size.

-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_flows_at_brin
    ON network_flows USING brin (at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_flows_at_brin;
-- +goose StatementEnd
