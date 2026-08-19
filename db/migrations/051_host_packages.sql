-- Host package inventory snapshots (Slice D.1). One row per (cluster_id,
-- node) holding the agent's most recent package enumeration. Scanner workers
-- read target-scoped package evidence and write vulnerability rows to unified
-- findings, so the agent does not ship a vulnerability scanner.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS host_packages (
    id            UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID REFERENCES clusters(id) ON DELETE CASCADE,
    node          TEXT NOT NULL,
    package_count INTEGER NOT NULL,
    -- 'dpkg' | 'rpm' | 'apk' | 'mixed' — useful for the UI to badge.
    source        TEXT,
    distro        TEXT,
    payload       JSONB NOT NULL,
    observed_at   TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_packages_cluster_node
    ON host_packages(cluster_id, node);

CREATE INDEX IF NOT EXISTS idx_host_packages_org
    ON host_packages(org_id, observed_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_host_packages_org;
DROP INDEX IF EXISTS uniq_host_packages_cluster_node;
DROP TABLE IF EXISTS host_packages;
-- +goose StatementEnd
