-- +goose Up
ALTER TABLE network_flow_rollup_state ADD COLUMN rollups_pruned_before timestamptz
 NOT NULL DEFAULT '0001-01-01T00:00:00Z';
CREATE INDEX idx_network_rollups_expiry ON network_flow_rollups(bucket);
