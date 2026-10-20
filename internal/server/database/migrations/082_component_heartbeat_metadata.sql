-- +goose Up
-- +goose StatementBegin
ALTER TABLE component_heartbeats
    ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
-- +goose StatementEnd
