-- +goose Up
-- +goose StatementBegin
ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS attempt_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_attempts INT NOT NULL DEFAULT 3,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_scan_jobs_pending_retry
    ON scan_jobs(org_id, next_attempt_at, requested_at)
    WHERE status = 'pending';
-- +goose StatementEnd
