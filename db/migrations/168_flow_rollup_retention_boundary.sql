-- +goose Up
-- Existing installations may already have partial raw history. Never rebuild
-- those historical aggregate buckets from incomplete raw rows after upgrade.
-- New late observations are added transactionally by the ingest path instead.
ALTER TABLE network_flow_rollup_state ADD COLUMN raw_pruned_before timestamptz
  NOT NULL DEFAULT (date_trunc('hour', CURRENT_TIMESTAMP AT TIME ZONE 'UTC') AT TIME ZONE 'UTC');

-- +goose Down
ALTER TABLE network_flow_rollup_state DROP COLUMN raw_pruned_before;
