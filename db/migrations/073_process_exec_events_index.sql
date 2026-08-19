-- Speed workload process-baseline joins from persisted runtime exec evidence.

-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_events_process_exec_workload
    ON events(org_id, cluster_id, workload_id, at DESC)
    WHERE kind = 'process_exec';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_events_process_exec_workload;
-- +goose StatementEnd
