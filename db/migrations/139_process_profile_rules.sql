-- Per-process allow/deny rules attached to a workload's process baseline (NV parity).
-- NeuVector attaches an editable allow/deny process rule list to each group (Process
-- Profile Rules): name, path, action, user, and allow_update. Constellation's baselines
-- were mode-only (learn/monitor/enforce) with a read-only learned-exec list; this adds
-- the authored rule object so operators can allow or deny a specific process.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS process_profile_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    workload_id   TEXT NOT NULL,
    name          TEXT NOT NULL,
    path          TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL DEFAULT 'allow' CHECK (action IN ('allow', 'deny')),
    proc_user     TEXT NOT NULL DEFAULT '',
    allow_update  BOOLEAN NOT NULL DEFAULT FALSE,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    description   TEXT NOT NULL DEFAULT '',
    created_by    UUID REFERENCES users(id),
    updated_by    UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, workload_id, name, path)
);

CREATE INDEX IF NOT EXISTS idx_process_profile_rules_workload
    ON process_profile_rules(org_id, cluster_id, workload_id, enabled, updated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_process_profile_rules_workload;
DROP TABLE IF EXISTS process_profile_rules;
-- +goose StatementEnd
