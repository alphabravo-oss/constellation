-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS vuln_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    active          BOOLEAN NOT NULL DEFAULT FALSE,
    -- entries: [{name, name_regex, images[], days_to_fix, action(suppress|escalate),
    --           reserved("_recent"), recent_days, severity_floor, score_floor}]
    entries         JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- domain_scope: optional {cluster, namespace} for narrowing
    domain_scope    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_vuln_profiles_org_active
    ON vuln_profiles(org_id, active);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS vuln_profiles;
-- +goose StatementEnd
