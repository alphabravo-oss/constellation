-- +goose NO TRANSACTION
-- +goose Up
-- Receipt timestamps can tie. Include UUID in the per-source index so archive
-- continuation and latest-source reads do not sort an arbitrarily large tie.
-- Recreate on retry: a failed concurrent build can leave an invalid index that
-- CREATE IF NOT EXISTS would otherwise silently retain. Keep the old index until
-- the replacement build succeeds.
DROP INDEX CONCURRENTLY IF EXISTS idx_k8s_audit_org_cluster_cursor;
CREATE INDEX CONCURRENTLY idx_k8s_audit_org_cluster_cursor
    ON k8s_audit_events(org_id,cluster_id,at,id);
DROP INDEX CONCURRENTLY IF EXISTS idx_k8s_audit_org_cluster_at;
