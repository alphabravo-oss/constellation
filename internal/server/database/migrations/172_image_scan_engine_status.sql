-- +goose Up
ALTER TABLE image_scan_results ADD COLUMN engine_status JSONB NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(engine_status) = 'object');
