-- Default mode for newly-discovered/created service groups (NV parity: NewServiceMode /
-- NewServiceProfileMode). NeuVector lets an operator choose whether new services start in
-- Discover, Monitor, or Protect; Constellation hardcoded 'monitor'. One row per (org,cluster).

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS service_mode_defaults (
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id   UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    policy_mode  TEXT NOT NULL DEFAULT 'monitor' CHECK (policy_mode IN ('discover', 'monitor', 'protect')),
    profile_mode TEXT NOT NULL DEFAULT 'monitor' CHECK (profile_mode IN ('discover', 'monitor', 'protect')),
    updated_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS service_mode_defaults;
-- +goose StatementEnd
