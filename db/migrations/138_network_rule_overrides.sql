-- +goose Up
-- +goose StatementBegin
-- User overrides layered on top of learned network rules (NV parity). A learned rule's
-- identity is the (from -> to) workload pair; an override row edits that pair's action /
-- enabled state / priority / comment, or defines a brand-new manual (user_created) rule
-- for a pair the flow rollups have never observed. GET merges these over the learned set.
CREATE TABLE IF NOT EXISTS network_rule_overrides (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id   UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    from_ep      TEXT NOT NULL,
    to_ep        TEXT NOT NULL,
    ports        TEXT NOT NULL DEFAULT 'any',
    applications TEXT[] NOT NULL DEFAULT '{}',
    action       TEXT NOT NULL DEFAULT 'allow' CHECK (action IN ('allow', 'deny')),
    disable      BOOLEAN NOT NULL DEFAULT FALSE,
    comment      TEXT NOT NULL DEFAULT '',
    priority     INTEGER NOT NULL DEFAULT 1000,
    cfg_type     TEXT NOT NULL DEFAULT 'user_created' CHECK (cfg_type IN ('user_created', 'learned_override')),
    updated_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, from_ep, to_ep)
);

CREATE INDEX IF NOT EXISTS idx_network_rule_overrides_cluster
    ON network_rule_overrides(org_id, cluster_id, priority);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS network_rule_overrides;
-- +goose StatementEnd
