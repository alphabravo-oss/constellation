-- +goose Up
-- +goose StatementBegin
ALTER TABLE compliance_checks
    ADD COLUMN IF NOT EXISTS tags_v2 JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_compliance_checks_tags_v2
    ON compliance_checks USING gin (tags_v2);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_compliance_checks_tags_v2;
ALTER TABLE compliance_checks DROP COLUMN IF EXISTS tags_v2;
-- +goose StatementEnd
