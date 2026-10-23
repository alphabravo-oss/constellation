-- +goose Up
-- Bound the per-enabled-schedule latest-success lookup without scanning backup
-- history. This is catalog observability, not proof of recoverable artifacts.
CREATE INDEX idx_backups_org_latest_success ON backups(org_id,finished_at DESC)
WHERE mode='org-backup' AND status='succeeded' AND finished_at IS NOT NULL;
