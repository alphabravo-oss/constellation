-- +goose Up
-- +goose StatementBegin
-- Wave M1: tag network_flows rows by their provenance so the Network Map UI can
-- distinguish real, BPF-observed flows from synthesized backfill rows.
--
-- 'bpf'       — emitted by cmd/constellation-runtime-agent (tcp_connect /
--               inet_csk_accept BPF probes, aggregated into 30s buckets and
--               POSTed to /api/v1/network-flows:bulk).
-- 'synthetic' — pre-existing demo/seed rows produced before the BPF ingest
--               path existed; kept so older fixtures still render.
-- 'declared'  — flow inferred from a NetworkPolicy / DNS rule (used by other
--               waves; reserved here for forward compat).
--
-- Default 'bpf' so new inserts written by the agent need no explicit value;
-- the in-flight backfill below stamps every pre-existing row to 'synthetic'.
ALTER TABLE network_flows
  ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'bpf';

UPDATE network_flows SET source = 'synthetic' WHERE source = 'bpf';

CREATE INDEX IF NOT EXISTS idx_flows_org_source_at
  ON network_flows(org_id, source, at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_flows_org_source_at;
ALTER TABLE network_flows DROP COLUMN IF EXISTS source;
-- +goose StatementEnd
