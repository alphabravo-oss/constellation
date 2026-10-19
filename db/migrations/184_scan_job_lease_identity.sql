-- +goose Up
-- Every new claim receives a fresh ID, including reclaim and manual retries.
-- Preserve NULL on existing rows to let unexpired pre-upgrade claims drain.
ALTER TABLE scan_jobs ADD COLUMN lease_id uuid;
-- +goose Down
ALTER TABLE scan_jobs DROP COLUMN lease_id;
