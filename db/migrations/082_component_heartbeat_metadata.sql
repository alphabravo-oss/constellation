-- +goose Up
-- +goose StatementBegin
ALTER TABLE component_heartbeats
    ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE component_heartbeats
    DROP COLUMN IF EXISTS metadata;
-- +goose StatementEnd
