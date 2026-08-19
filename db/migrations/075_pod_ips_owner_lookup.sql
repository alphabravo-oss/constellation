-- Persist exact pod-to-deployment ownership for pod-scoped workload evidence.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS pod_workload_links (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id        UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    namespace         TEXT NOT NULL,
    pod_name          TEXT NOT NULL,
    pod_uid           TEXT NOT NULL,
    pod_workload_id   TEXT NOT NULL,
    owner_kind        TEXT NOT NULL,
    owner_name        TEXT NOT NULL,
    owner_uid         TEXT,
    owner_workload_id TEXT NOT NULL,
    deployment_id     UUID REFERENCES deployments(id) ON DELETE SET NULL,
    node_name         TEXT,
    phase             TEXT NOT NULL DEFAULT '',
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, pod_uid)
);

CREATE INDEX IF NOT EXISTS idx_pod_workload_links_owner
    ON pod_workload_links(org_id, cluster_id, deployment_id, pod_workload_id)
    WHERE deployment_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_pod_workload_links_pod
    ON pod_workload_links(org_id, cluster_id, namespace, pod_name, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_pod_workload_links_owner_workload
    ON pod_workload_links(org_id, cluster_id, owner_workload_id, last_seen_at DESC);

ALTER TABLE pod_ips
    ADD COLUMN IF NOT EXISTS pod_uid TEXT,
    ADD COLUMN IF NOT EXISTS owner_uid TEXT,
    ADD COLUMN IF NOT EXISTS deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS workload_id TEXT;

UPDATE pod_ips
   SET workload_id = namespace || '/pod/' || pod_name
 WHERE workload_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_pod_ips_owner_lookup
    ON pod_ips(org_id, cluster_id, deployment_id, workload_id)
    WHERE deployment_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_pod_ips_owner_lookup;
DROP INDEX IF EXISTS idx_pod_workload_links_owner_workload;
DROP INDEX IF EXISTS idx_pod_workload_links_pod;
DROP INDEX IF EXISTS idx_pod_workload_links_owner;
ALTER TABLE pod_ips
    DROP COLUMN IF EXISTS workload_id,
    DROP COLUMN IF EXISTS deployment_id,
    DROP COLUMN IF EXISTS owner_uid,
    DROP COLUMN IF EXISTS pod_uid;
DROP TABLE IF EXISTS pod_workload_links;
-- +goose StatementEnd
