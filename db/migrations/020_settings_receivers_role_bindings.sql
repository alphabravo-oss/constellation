-- +goose Up
-- +goose StatementBegin
-- Org and user settings: JSON-bag storage for UI preferences, AI toggle, feature flags,
-- onboarding completion, integration overrides. Keyed by (org_id) and (user_id).
CREATE TABLE IF NOT EXISTS org_settings (
    org_id      UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    settings    JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS user_settings (
    user_id     UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    settings    JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Receivers: integration endpoints (Slack/PagerDuty/Jira/ServiceNow/webhook).
-- secret_ref points to an external secret manager handle; the raw secret is never stored.
CREATE TABLE IF NOT EXISTS receivers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,           -- slack | pagerduty | jira | servicenow | webhook
    endpoint        TEXT NOT NULL,
    secret_ref      TEXT,
    owner           TEXT,
    environment     TEXT NOT NULL DEFAULT 'production',
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending | healthy | degraded | disabled
    supported_events JSONB NOT NULL DEFAULT '[]'::jsonb,
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_verified_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_receivers_org_kind ON receivers(org_id, kind);

-- Delivery history: real records of receiver deliveries (success/failure/retries).
CREATE TABLE IF NOT EXISTS receiver_deliveries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    receiver_id     UUID NOT NULL REFERENCES receivers(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    status          TEXT NOT NULL,           -- delivered | retrying | failed | dropped
    routing_rule_id TEXT,
    attempts        INT NOT NULL DEFAULT 0,
    latency_ms      INT NOT NULL DEFAULT 0,
    trace_id        TEXT,
    error           TEXT,
    artifacts       JSONB NOT NULL DEFAULT '[]'::jsonb,
    payload_hash    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_receiver_deliveries_org_created ON receiver_deliveries(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_receiver_deliveries_receiver    ON receiver_deliveries(receiver_id, created_at DESC);

-- Role bindings: subjects (users or service accounts) bound to a role within a scope.
-- This sits beside role_assignments; bindings carry display metadata (granted_by, expires_at)
-- the access-control UI surfaces.
CREATE TABLE IF NOT EXISTS role_bindings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    subject_id   TEXT NOT NULL,             -- users.id or api_tokens.id, stored as text for mixed kinds
    subject_type TEXT NOT NULL,             -- user | service_account
    role_id      TEXT NOT NULL,             -- GlobalAdmin | SecurityAdmin | ClusterAdmin | Analyst | Auditor
    scopes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    granted_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    UNIQUE (org_id, subject_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_bindings_org ON role_bindings(org_id);

-- Routing YAML: the raw Alertmanager-style routing tree. One row per org; updated_at + revision.
CREATE TABLE IF NOT EXISTS routing_configs (
    org_id      UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    yaml        TEXT NOT NULL DEFAULT '',
    revision    INT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Service accounts (non-user principals): tracked separately from users for the
-- access-control catalog. api_tokens may reference one of these.
CREATE TABLE IF NOT EXISTS service_accounts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT,
    owner        TEXT,
    status       TEXT NOT NULL DEFAULT 'active', -- active | disabled
    scopes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    roles        JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

-- Add service_account_id to api_tokens so the UI can group tokens by service account.
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS service_account_id UUID
    REFERENCES service_accounts(id) ON DELETE SET NULL;
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS scopes JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE api_tokens DROP COLUMN IF EXISTS service_account_id;
ALTER TABLE api_tokens DROP COLUMN IF EXISTS scopes;
ALTER TABLE api_tokens DROP COLUMN IF EXISTS status;
DROP TABLE IF EXISTS service_accounts;
DROP TABLE IF EXISTS routing_configs;
DROP TABLE IF EXISTS role_bindings;
DROP TABLE IF EXISTS receiver_deliveries;
DROP TABLE IF EXISTS receivers;
DROP TABLE IF EXISTS user_settings;
DROP TABLE IF EXISTS org_settings;
-- +goose StatementEnd
