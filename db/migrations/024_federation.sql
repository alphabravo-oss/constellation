-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS federation_state (
    org_id          UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    state           TEXT NOT NULL DEFAULT 'standalone' CHECK (state IN ('standalone','master','joint')),
    master_id       TEXT NOT NULL DEFAULT '',
    cluster_name    TEXT NOT NULL DEFAULT '',
    revision        BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fed_members (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      TEXT NOT NULL,
    name            TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('master','joint')),
    endpoint        TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending',
    last_sync_at    TIMESTAMPTZ,
    revision        BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id)
);

CREATE INDEX IF NOT EXISTS idx_fed_members_org ON fed_members(org_id);

-- Cross-cluster modified-rule revisions for since-version sync.
CREATE TABLE IF NOT EXISTS fed_rule_revisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    rule_kind       TEXT NOT NULL,  -- policy | group | response_rule
    rule_id         TEXT NOT NULL,
    revision        BIGINT NOT NULL,
    payload         JSONB NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fed_rule_revisions_since
    ON fed_rule_revisions(org_id, revision);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS fed_rule_revisions;
DROP TABLE IF EXISTS fed_members;
DROP TABLE IF EXISTS federation_state;
-- +goose StatementEnd
