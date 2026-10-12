-- +goose Up
-- Catalog feeds are global, not tenant data. Fixed keys bound this table to two
-- rows; never retain one row per CVE, request, import, or upstream URL.
CREATE TABLE cve_feed_checkpoints (
    feed text PRIMARY KEY CHECK (feed IN ('kev-epss', 'nvd')),
    source_hash text NOT NULL CHECK (length(source_hash) = 64),
    content_hash text CHECK (length(content_hash) = 64),
    completed_through timestamptz,
    row_count bigint NOT NULL CHECK (row_count >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
-- Removing checkpoints causes safe re-import on the next sync.
DROP TABLE cve_feed_checkpoints;
