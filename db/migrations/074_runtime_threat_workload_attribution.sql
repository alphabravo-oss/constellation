-- Attach runtime WAF/DLP/DPI threat rows to the workload they affected.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE runtime_threats
    ADD COLUMN IF NOT EXISTS workload_id TEXT,
    ADD COLUMN IF NOT EXISTS namespace TEXT,
    ADD COLUMN IF NOT EXISTS pod_name TEXT;

CREATE INDEX IF NOT EXISTS idx_runtime_threats_workload_at
    ON runtime_threats(org_id, cluster_id, workload_id, at DESC)
    WHERE workload_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_runtime_threats_workload_at;
ALTER TABLE runtime_threats
    DROP COLUMN IF EXISTS pod_name,
    DROP COLUMN IF EXISTS namespace,
    DROP COLUMN IF EXISTS workload_id;
-- +goose StatementEnd
