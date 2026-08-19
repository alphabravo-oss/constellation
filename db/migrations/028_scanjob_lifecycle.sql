-- +goose Up
-- +goose StatementBegin
-- Allow scan jobs to be paused or canceled from the UI. CHECK constraint widened to
-- include the new lifecycle states; the existing check is dropped first.
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_status_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check
    CHECK (status IN ('pending','running','completed','failed','paused','canceled'));

ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS paused_at   TIMESTAMPTZ;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS canceled_at TIMESTAMPTZ;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS resumed_at  TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_status_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check
    CHECK (status IN ('pending','running','completed','failed'));
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS paused_at;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS canceled_at;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS resumed_at;
-- +goose StatementEnd
