-- Carry the egress destination FQDN through the network_flow_rollups
-- pre-aggregate so the traffic map can show "svc → api.github.com" instead of a
-- bare external IP. network_flows.fqdn is populated by the Hubble lane
-- (destination_names); the dp/bpf lanes leave it empty, so this is NULL/'' on
-- dp-only clusters. The rollup fold keeps one representative non-empty fqdn per
-- conversation bucket.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE network_flow_rollups ADD COLUMN IF NOT EXISTS fqdn text NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE network_flow_rollups DROP COLUMN IF EXISTS fqdn;
-- +goose StatementEnd
