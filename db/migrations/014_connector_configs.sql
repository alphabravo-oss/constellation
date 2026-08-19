-- +goose Up
-- +goose StatementBegin
CREATE TABLE connector_configs (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    connector_id          TEXT NOT NULL,
    connector_type        TEXT NOT NULL CHECK (connector_type IN ('registry', 'cloud')),
    provider              TEXT NOT NULL,
    display_name          TEXT NOT NULL,
    endpoint              TEXT NOT NULL,
    auth_mode             TEXT NOT NULL,
    owner                 TEXT NOT NULL,
    scan_cadence          TEXT NOT NULL DEFAULT 'daily',
    rotation_due_at       TIMESTAMPTZ,
    credential_ref        TEXT,
    credential_fingerprint TEXT,
    credential_present    BOOLEAN NOT NULL DEFAULT FALSE,
    last_test_status      TEXT NOT NULL DEFAULT 'not_tested',
    last_test_at          TIMESTAMPTZ,
    created_by            UUID REFERENCES users(id),
    updated_by            UUID REFERENCES users(id),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, connector_type, connector_id)
);

CREATE INDEX idx_connector_configs_org_type ON connector_configs(org_id, connector_type, updated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS connector_configs;
-- +goose StatementEnd
