-- Host CIS benchmark reports (Slice E). One row per (cluster_id, node)
-- holding the agent's most recent CIS check run.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS host_cis (
    id          UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id  UUID REFERENCES clusters(id) ON DELETE CASCADE,
    node        TEXT NOT NULL,
    profile     TEXT,
    passed      INTEGER NOT NULL DEFAULT 0,
    failed      INTEGER NOT NULL DEFAULT 0,
    warned      INTEGER NOT NULL DEFAULT 0,
    skipped     INTEGER NOT NULL DEFAULT 0,
    payload     JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_cis_cluster_node
    ON host_cis(cluster_id, node);

CREATE INDEX IF NOT EXISTS idx_host_cis_org
    ON host_cis(org_id, observed_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_host_cis_org;
DROP INDEX IF EXISTS uniq_host_cis_cluster_node;
DROP TABLE IF EXISTS host_cis;
-- +goose StatementEnd
