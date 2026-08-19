-- +goose Up
-- +goose StatementBegin
-- Latest Kubernetes/platform inventory reported by the in-cluster discoverer.
-- Scan evidence remains in scan_evidence; this table is the durable cluster
-- posture read model used by health and dashboard surfaces.
CREATE TABLE IF NOT EXISTS cluster_platform_facts (
    org_id                 UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id             UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    distro                 TEXT NOT NULL DEFAULT 'kubernetes',
    kubernetes_git_version TEXT NOT NULL DEFAULT '',
    kubernetes_major       TEXT NOT NULL DEFAULT '',
    kubernetes_minor       TEXT NOT NULL DEFAULT '',
    platform_provider      TEXT NOT NULL DEFAULT '',
    platform_version       TEXT NOT NULL DEFAULT '',
    node_count             INT NOT NULL DEFAULT 0,
    kubelet_versions       JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload                JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at            TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id)
);

CREATE INDEX IF NOT EXISTS idx_cluster_platform_facts_observed
    ON cluster_platform_facts(org_id, observed_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_cluster_platform_facts_observed;
DROP TABLE IF EXISTS cluster_platform_facts;
-- +goose StatementEnd
