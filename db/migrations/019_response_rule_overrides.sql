-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS response_rule_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('learn', 'monitor', 'enforce')),
    enabled BOOLEAN NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_response_rule_overrides_org_updated
    ON response_rule_overrides(org_id, updated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS response_rule_overrides;
-- +goose StatementEnd
