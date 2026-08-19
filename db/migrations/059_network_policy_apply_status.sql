-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS network_policy_apply_status (
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    workload        TEXT NOT NULL,
    namespace       TEXT NOT NULL DEFAULT '',
    flavor          TEXT NOT NULL,
    resource_ref    TEXT NOT NULL DEFAULT '',
    desired_mode    TEXT NOT NULL DEFAULT '',
    approval_status TEXT NOT NULL DEFAULT '',
    last_action     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,
    error           TEXT NOT NULL DEFAULT '',
    candidate_hash  TEXT,
    applied_ref     TEXT,
    rollback_ref    TEXT,
    last_applied_at TIMESTAMPTZ,
    last_deleted_at TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id, workload, flavor)
);

CREATE INDEX IF NOT EXISTS idx_network_policy_apply_status_cluster
    ON network_policy_apply_status(cluster_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_network_policy_apply_status_workload
    ON network_policy_apply_status(org_id, cluster_id, workload, updated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_network_policy_apply_status_workload;
DROP INDEX IF EXISTS idx_network_policy_apply_status_cluster;
DROP TABLE IF EXISTS network_policy_apply_status;
-- +goose StatementEnd
