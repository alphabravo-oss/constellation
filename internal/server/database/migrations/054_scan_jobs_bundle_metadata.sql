-- +goose Up
-- +goose StatementBegin
-- First-class VulnDB bundle provenance for image scan batches. Findings still
-- carry per-row detail, but job lists need batch-level provenance without
-- joining audit events or finding detail JSON.
ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS bundle_metadata JSONB;
-- +goose StatementEnd
