-- +goose Up
-- +goose StatementBegin
-- B1 — runtime-mutable, RBAC-gated system configuration. One row per org holds the
-- operational knobs that today require a Deployment edit + restart (egress proxy,
-- TLS verification + CA bundle, syslog/SIEM target, scanner autoscale bounds). The
-- config lives in a single validated JSONB blob (`config`) so new fields can be added
-- without a schema migration; a typed Go struct (internal/syscfg.Config) is the
-- validating gatekeeper for every read and write. `revision` is bumped on every
-- successful PATCH; the in-process accessor polls it to detect changes and hot-reload
-- the cached value WITHOUT a restart (mirrors A5's runSessionKeyReloader). Env vars
-- become bootstrap defaults: the server seeds this row from env on first boot if absent,
-- after which the DB row is the source of truth.
CREATE TABLE IF NOT EXISTS system_config (
    org_id     UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    config     JSONB NOT NULL DEFAULT '{}'::jsonb,
    revision   BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS system_config;
-- +goose StatementEnd
