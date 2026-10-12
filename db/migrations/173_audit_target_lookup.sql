-- +goose NO TRANSACTION
-- +goose Up
-- Cluster audit pages read a sparse target set. Keep their lookups independent
-- of the size of the append-only log; concurrent construction permits appends.
-- A failed concurrent build can leave an invalid index before Goose records
-- this version. Rebuild either that index or a successful unrecorded build.
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_org_target_id;
CREATE INDEX CONCURRENTLY idx_audit_org_target_id
    ON audit_events (org_id, target_id, id DESC);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_org_target_id;
