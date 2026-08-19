-- Runtime-agent reported file-profile watch inventory. This is the live
-- control-plane view of which file monitor rules each agent has synced for a
-- cluster/node. It is intentionally separate from true enforcement state:
-- protect remains false until a kernel/user-space deny path exists.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS file_profile_watch_inventory (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id         UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    node               TEXT NOT NULL,
    workload_id        TEXT NOT NULL,
    rule_id            UUID NOT NULL REFERENCES file_profile_rules(id) ON DELETE CASCADE,
    filter             TEXT NOT NULL,
    path               TEXT NOT NULL,
    regex              TEXT NOT NULL DEFAULT '',
    recursive          BOOLEAN NOT NULL DEFAULT FALSE,
    behavior           TEXT NOT NULL CHECK (behavior IN ('monitor_change', 'block_access')),
    applications       TEXT[] NOT NULL DEFAULT '{}',
    profile_mode       TEXT NOT NULL CHECK (profile_mode IN ('learn', 'monitor', 'enforce')),
    desired_protect    BOOLEAN NOT NULL DEFAULT FALSE,
    protect            BOOLEAN NOT NULL DEFAULT FALSE,
    enforcement_state  TEXT NOT NULL CHECK (enforcement_state IN ('synced', 'unsupported', 'enforced', 'error')),
    files              JSONB NOT NULL DEFAULT '[]'::jsonb,
    files_count        INTEGER NOT NULL DEFAULT 0,
    sensitive_count    INTEGER NOT NULL DEFAULT 0,
    bundle_fingerprint TEXT NOT NULL DEFAULT '',
    observed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, node, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_file_profile_watch_workload
    ON file_profile_watch_inventory(org_id, cluster_id, workload_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_file_profile_watch_node
    ON file_profile_watch_inventory(org_id, cluster_id, node, observed_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_file_profile_watch_node;
DROP INDEX IF EXISTS idx_file_profile_watch_workload;
DROP TABLE IF EXISTS file_profile_watch_inventory;
-- +goose StatementEnd
