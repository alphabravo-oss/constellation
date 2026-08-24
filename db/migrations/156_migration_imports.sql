-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS migration_imports (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    source            TEXT NOT NULL,
    source_hash       TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'previewed',
    preview_json      JSONB NOT NULL,
    applied_json      JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
    unsupported_json  JSONB NOT NULL DEFAULT '[]'::jsonb,
    error             TEXT NOT NULL DEFAULT '',
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    applied_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    rolled_back_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_at        TIMESTAMPTZ,
    rolled_back_at    TIMESTAMPTZ,
    CONSTRAINT migration_imports_status_chk CHECK (status IN ('previewed', 'applied', 'partial_applied', 'rolled_back', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_migration_imports_org_created ON migration_imports(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_migration_imports_org_status ON migration_imports(org_id, status);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS migration_imports;
-- +goose StatementEnd
