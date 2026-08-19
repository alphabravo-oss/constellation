-- +goose Up
-- +goose StatementBegin
-- WAF groups + rules (userspace rule store; data plane attach handled by Wave A).
CREATE TABLE IF NOT EXISTS waf_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    mode            TEXT NOT NULL DEFAULT 'monitor' CHECK (mode IN ('learn','monitor','enforce')),
    -- rules: [{id,msg,severity,phase,transformations[],operator(rx|streq|contains|streq_ci),
    --          target(REQUEST_URI|ARGS|HEADERS:name|BODY),value}]
    rules           JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_waf_groups_org ON waf_groups(org_id);

-- DLP sensors + default rules.
CREATE TABLE IF NOT EXISTS dlp_sensors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    cfg_type        TEXT NOT NULL CHECK (cfg_type IN ('federal','predefined','user')),
    comment         TEXT NOT NULL DEFAULT '',
    -- rules: [{name,pattern(PCRE),context(header|body|url),action(alert|block)}]
    rules           JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_dlp_sensors_org ON dlp_sensors(org_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dlp_sensors;
DROP TABLE IF EXISTS waf_groups;
-- +goose StatementEnd
