-- +goose Up
-- +goose StatementBegin
-- groups: NeuVector-style workload selectors.
CREATE TABLE IF NOT EXISTS groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('learned','ground','federated')),
    comment         TEXT NOT NULL DEFAULT '',
    -- criteria: [{key, value, op(eq|contains|regex)}]
    criteria        JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- members: cached materialization of matched workload IDs (advisory)
    members         JSONB NOT NULL DEFAULT '[]'::jsonb,
    learned_from    TEXT NOT NULL DEFAULT '',  -- workload id for learned groups
    cfg_type        TEXT NOT NULL DEFAULT 'user', -- user|learned|fed
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_groups_org_kind ON groups(org_id, kind);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS groups;
-- +goose StatementEnd
