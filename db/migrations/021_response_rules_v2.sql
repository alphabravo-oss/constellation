-- +goose Up
-- +goose StatementBegin
-- response_rules_v2: NeuVector-style trigger conditions + actions.
-- Coexists with response_rule_overrides (which is the legacy override store for the v1
-- catalog). The v2 store is the user-defined rule catalog.
CREATE TABLE IF NOT EXISTS response_rules_v2 (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    event_type      TEXT NOT NULL,                          -- admission|runtime|scan|compliance|*
    conditions      JSONB NOT NULL DEFAULT '[]'::jsonb,      -- [{type,op,value}, ...]
    actions         JSONB NOT NULL DEFAULT '[]'::jsonb,      -- [{kind,target,params}, ...]
    workload_match  JSONB NOT NULL DEFAULT '{}'::jsonb,      -- {cluster,namespace,labels{...}}
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_response_rules_v2_org_enabled
    ON response_rules_v2(org_id, enabled);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS response_rules_v2;
-- +goose StatementEnd
