-- Host facts inventory: a periodic snapshot the runtime-agent POSTs for
-- every node it runs on. Mirrors what NeuVector's enforcer collects in
-- share/system/system_linux.go (kernel/distro/cgroup/modules/CNI/CRI),
-- plus the BTF + nfqueue-safe bits constellation specifically cares
-- about for its eBPF + NFQUEUE enforcement path.
--
-- The agent upserts one row per (cluster_id, node). The full payload is
-- jsonb so adding fields doesn't require a migration; a small set of
-- frequently-queried fields are also lifted to columns for cheap UI
-- filters ("show me all kernels < 5.10", "which nodes are missing BTF").

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS host_facts (
    id              UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      UUID REFERENCES clusters(id) ON DELETE CASCADE,
    node            TEXT NOT NULL,
    -- Frequently-filtered columns lifted out of the jsonb for indexed reads.
    os_id           TEXT,           -- e.g. 'ubuntu'
    os_version_id   TEXT,           -- e.g. '24.04'
    kernel_release  TEXT,           -- e.g. '6.8.0-111-generic'
    arch            TEXT,           -- e.g. 'x86_64'
    btf_present     BOOLEAN,
    cgroup_version  SMALLINT,
    nfqueue_capable BOOLEAN,
    cni_name        TEXT,
    cri_runtime     TEXT,
    -- Full snapshot. Schema kept in pkg/runtime/hostscan.Facts.
    facts           JSONB NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One active row per (cluster, node); the agent upserts.
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_facts_cluster_node
    ON host_facts(cluster_id, node);

-- Cluster-scoped UI list query.
CREATE INDEX IF NOT EXISTS idx_host_facts_cluster
    ON host_facts(cluster_id, observed_at DESC);

-- Org-scoped (cross-cluster) UI query, also covers the "find nodes
-- with kernel < X" filter when paired with a btree on kernel_release.
CREATE INDEX IF NOT EXISTS idx_host_facts_org
    ON host_facts(org_id, observed_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_host_facts_org;
DROP INDEX IF EXISTS idx_host_facts_cluster;
DROP INDEX IF EXISTS uniq_host_facts_cluster_node;
DROP TABLE IF EXISTS host_facts;
-- +goose StatementEnd
