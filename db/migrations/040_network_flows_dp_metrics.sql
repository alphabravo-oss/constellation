-- +goose Up
-- +goose StatementBegin
-- Wave 4: add real-metric columns produced by the NeuVector C data-plane (dp).
--
-- The runtime-agent now ships dp events (per-(EPMAC, 5-tuple, policy_id) byte
-- and session aggregates from real on-wire packet inspection) into this table
-- via /api/v1/network-flows:bulk. Each row is one emit cycle from dp.
--
-- All columns are nullable so the legacy BPF-aggregator path (which only knows
-- the synthetic `bytes` / `packets` shape) keeps working — its rows will leave
-- the new columns NULL and the UI's "fade synthetic" heuristic still applies.
-- See migration 032 for the `source` column that tags rows by provenance:
--
--   'dp'         — real, from NeuVector dp (added by this migration as a valid value)
--   'bpf'        — synthetic, from the legacy BPF tcp_connect aggregator
--   'synthetic'  — seed / demo data
--   'declared'   — derived from NetworkPolicy (reserved)
--
-- The `bytes` column stays — for dp rows it equals client_bytes + server_bytes
-- so existing SUM(bytes) queries keep working without a code change.
ALTER TABLE network_flows
  ADD COLUMN IF NOT EXISTS client_bytes  BIGINT,
  ADD COLUMN IF NOT EXISTS server_bytes  BIGINT,
  ADD COLUMN IF NOT EXISTS sessions      BIGINT,
  ADD COLUMN IF NOT EXISTS application   INTEGER,
  ADD COLUMN IF NOT EXISTS policy_action TEXT,
  ADD COLUMN IF NOT EXISTS policy_id     BIGINT,
  ADD COLUMN IF NOT EXISTS threat_id     INTEGER,
  ADD COLUMN IF NOT EXISTS severity      SMALLINT,
  ADD COLUMN IF NOT EXISTS ep_mac        TEXT;

-- Index for threat-aware queries: list flows where dp tripped a signature.
-- Partial index keeps it tiny since most flows have threat_id = NULL or 0.
CREATE INDEX IF NOT EXISTS idx_flows_org_threat
  ON network_flows(org_id, threat_id, at DESC)
  WHERE threat_id IS NOT NULL AND threat_id > 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_flows_org_threat;
ALTER TABLE network_flows
  DROP COLUMN IF EXISTS client_bytes,
  DROP COLUMN IF EXISTS server_bytes,
  DROP COLUMN IF EXISTS sessions,
  DROP COLUMN IF EXISTS application,
  DROP COLUMN IF EXISTS policy_action,
  DROP COLUMN IF EXISTS policy_id,
  DROP COLUMN IF EXISTS threat_id,
  DROP COLUMN IF EXISTS severity,
  DROP COLUMN IF EXISTS ep_mac;
-- +goose StatementEnd
