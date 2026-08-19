-- Host container inventory snapshots: one row per (cluster_id, node)
-- holding the agent's most recent crictl-derived container list.
-- Mirrors NeuVector's enforcer container tracker (agent/probe + CRI
-- proxy) but as a periodic snapshot.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS host_containers (
    id              UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      UUID REFERENCES clusters(id) ON DELETE CASCADE,
    node            TEXT NOT NULL,
    container_count INTEGER NOT NULL,
    runtime         TEXT,
    socket          TEXT,
    payload         JSONB NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_containers_cluster_node
    ON host_containers(cluster_id, node);

CREATE INDEX IF NOT EXISTS idx_host_containers_org
    ON host_containers(org_id, observed_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_host_containers_org;
DROP INDEX IF EXISTS uniq_host_containers_cluster_node;
DROP TABLE IF EXISTS host_containers;
-- +goose StatementEnd
