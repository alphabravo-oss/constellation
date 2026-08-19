-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS compliance_exemptions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id  UUID REFERENCES clusters(id) ON DELETE CASCADE,
    framework   TEXT NOT NULL,
    control_id  TEXT NOT NULL,
    reason      TEXT NOT NULL,
    approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (btrim(framework) <> ''),
    CHECK (btrim(control_id) <> ''),
    CHECK (btrim(reason) <> '')
);

CREATE INDEX IF NOT EXISTS idx_compliance_exemptions_active
    ON compliance_exemptions (org_id, framework, control_id, cluster_id, expires_at DESC)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_compliance_exemptions_org_created
    ON compliance_exemptions (org_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS compliance_exemptions;
-- +goose StatementEnd
