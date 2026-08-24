-- +goose Up
-- +goose StatementBegin
-- Preserve operator-facing provenance for DLP, WAF, and custom DPI rows.
-- NeuVector switchers need to distinguish user-authored, imported, predefined,
-- and federated rules after migration; `source_path` keeps the originating
-- export location where one exists.
ALTER TABLE runtime_dlp_rules
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS cfg_type TEXT NOT NULL DEFAULT 'user_created',
    ADD COLUMN IF NOT EXISTS source_path TEXT NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'runtime_dlp_rules_source_check'
    ) THEN
        ALTER TABLE runtime_dlp_rules
            ADD CONSTRAINT runtime_dlp_rules_source_check
                CHECK (source IN ('user', 'neuvector', 'import', 'builtin', 'federation'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'runtime_dlp_rules_cfg_type_check'
    ) THEN
        ALTER TABLE runtime_dlp_rules
            ADD CONSTRAINT runtime_dlp_rules_cfg_type_check
                CHECK (cfg_type IN ('user_created', 'imported', 'learned', 'federated', 'predefined'));
    END IF;
END $$;

UPDATE runtime_dlp_rules
   SET source='builtin', cfg_type='predefined'
 WHERE name LIKE 'builtin-%'
   AND source='user'
   AND cfg_type='user_created';

CREATE INDEX IF NOT EXISTS idx_runtime_dlp_rules_provenance
    ON runtime_dlp_rules(org_id, cluster_id, source, cfg_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_runtime_dlp_rules_provenance;
ALTER TABLE runtime_dlp_rules
    DROP CONSTRAINT IF EXISTS runtime_dlp_rules_cfg_type_check,
    DROP CONSTRAINT IF EXISTS runtime_dlp_rules_source_check,
    DROP COLUMN IF EXISTS source_path,
    DROP COLUMN IF EXISTS cfg_type,
    DROP COLUMN IF EXISTS source;
-- +goose StatementEnd
