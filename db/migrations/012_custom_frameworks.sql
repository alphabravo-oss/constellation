-- +goose Up
-- +goose StatementBegin
-- Custom compliance frameworks — users compose a framework from primitive checks (the
-- pkg/compliance.CoreMappings internal IDs).
CREATE TABLE IF NOT EXISTS custom_frameworks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'custom',
    description TEXT,
    control_ids TEXT[] NOT NULL DEFAULT '{}',  -- references to pkg/compliance internal IDs
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_custom_frameworks_org ON custom_frameworks(org_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS custom_frameworks;
-- +goose StatementEnd
