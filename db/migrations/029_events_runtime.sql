-- +goose Up
-- +goose StatementBegin
-- Wave I4: runtime-agent ingest path.
--
-- The existing `events` partitioned table (see migration 005) already has the
-- columns the runtime-agent ingest needs: `kind`, `severity`, `verdict`,
-- `attack_techniques`, `payload`, `at`. This migration adds:
--
--   1. A namespace column on `events` so the UI can show pod/namespace pairs
--      without parsing them out of `workload_id`. NULLable: legacy / non-K8s
--      sources just leave it empty.
--   2. The `runtime_agent_tokens` table — per-org credentials used by the
--      node-local kernel data-plane DaemonSet to authenticate against the
--      control-plane's POST /api/v1/events:bulk endpoint. Modeled on
--      scanner_tokens (migration 008) for consistency: sha256 hash stored,
--      raw token shown once, revocable, optional expiry.
--
-- Index choice rationale:
--   - Bulk ingest path is INSERT-only; no new indexes on `events`.
--   - The read path (/api/v1/events?limit=100) hits the existing
--     idx_events_workload index ordered by `at DESC`.
ALTER TABLE events ADD COLUMN IF NOT EXISTS namespace TEXT;

CREATE TABLE IF NOT EXISTS runtime_agent_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,    -- sha256 of the raw token; never store the raw value
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_runtime_agent_tokens_org ON runtime_agent_tokens(org_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS runtime_agent_tokens;
ALTER TABLE events DROP COLUMN IF EXISTS namespace;
-- +goose StatementEnd
