-- +goose NO TRANSACTION
-- +goose Up
-- Rebuild an invalid interrupted concurrent index on retry. Existing UI indexes
-- remain because they serve different organization/severity/workload queries.
DROP INDEX CONCURRENTLY IF EXISTS idx_runtime_threat_archive_cursor;
CREATE INDEX CONCURRENTLY idx_runtime_threat_archive_cursor
    ON runtime_threats(org_id,cluster_id,at,id);
