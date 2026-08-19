-- Host process snapshots: one row per (cluster_id, node) holding the
-- agent's most recent /proc walk. Mirrors NeuVector's enforcer process
-- inventory (agent/probe/process_linux.go) but as a periodic snapshot
-- rather than a streaming netlink monitor — the streaming part is
-- already covered by the BPF exec stream.
--
-- The full process list is jsonb so the schema stays stable as the
-- agent collector grows fields. A few cheap-to-query columns are
-- lifted out for indexed reads.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS host_processes (
    id            UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID REFERENCES clusters(id) ON DELETE CASCADE,
    node          TEXT NOT NULL,
    -- Lifted summary columns.
    process_count INTEGER NOT NULL,
    items_count   INTEGER NOT NULL,
    -- Full payload: hostscan.Processes JSON.
    payload       JSONB NOT NULL,
    observed_at   TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_processes_cluster_node
    ON host_processes(cluster_id, node);

CREATE INDEX IF NOT EXISTS idx_host_processes_org
    ON host_processes(org_id, observed_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_host_processes_org;
DROP INDEX IF EXISTS uniq_host_processes_cluster_node;
DROP TABLE IF EXISTS host_processes;
-- +goose StatementEnd
