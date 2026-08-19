-- File monitor rules for workload-scoped file profiles. These are the operator
-- authored filters that will be distributed to runtime agents for enforcement.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS file_profile_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    workload_id   TEXT NOT NULL,
    filter        TEXT NOT NULL,
    path          TEXT NOT NULL,
    regex         TEXT NOT NULL DEFAULT '',
    recursive     BOOLEAN NOT NULL DEFAULT FALSE,
    behavior      TEXT NOT NULL CHECK (behavior IN ('monitor_change', 'block_access')),
    applications  TEXT[] NOT NULL DEFAULT '{}',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    description   TEXT NOT NULL DEFAULT '',
    created_by    UUID REFERENCES users(id),
    updated_by    UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, workload_id, filter)
);

CREATE INDEX IF NOT EXISTS idx_file_profile_rules_workload
    ON file_profile_rules(org_id, cluster_id, workload_id, enabled, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_file_profile_rules_behavior
    ON file_profile_rules(org_id, cluster_id, behavior, updated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_file_profile_rules_behavior;
DROP INDEX IF EXISTS idx_file_profile_rules_workload;
DROP TABLE IF EXISTS file_profile_rules;
-- +goose StatementEnd
