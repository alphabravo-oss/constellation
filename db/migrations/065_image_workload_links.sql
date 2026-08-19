-- Reverse index from scanned images to the workloads currently using them.
-- This lets Constellation keep one canonical image scan result while preserving
-- NeuVector-style impacted workload visibility.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS image_workload_links (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id     UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    deployment_id  UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    workload_id    TEXT NOT NULL,
    namespace      TEXT NOT NULL,
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL,
    image_ref      TEXT NOT NULL,
    image_ref_normalized TEXT NOT NULL,
    image_repository TEXT,
    image_tag      TEXT,
    image_digest   TEXT,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, workload_id, image_ref)
);

CREATE INDEX IF NOT EXISTS idx_image_workload_links_ref
    ON image_workload_links(org_id, image_ref, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_image_workload_links_normalized
    ON image_workload_links(org_id, image_ref_normalized, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_image_workload_links_digest
    ON image_workload_links(org_id, image_digest, last_seen_at DESC)
    WHERE image_digest IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_image_workload_links_cluster
    ON image_workload_links(org_id, cluster_id, namespace, name);

INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest,
    first_seen_at, last_seen_at
)
SELECT d.org_id,
       d.cluster_id,
       d.id,
       d.namespace || '/' || d.name,
       d.namespace,
       d.name,
       d.kind,
       img.ref,
       img.ref,
       NULL,
       NULL,
       CASE
         WHEN position('@sha256:' in img.ref) > 0
         THEN substring(img.ref from position('@sha256:' in img.ref) + 1)
         ELSE NULL
       END,
       d.first_seen_at,
       d.last_seen_at
  FROM deployments d
 CROSS JOIN LATERAL unnest(d.image_refs) AS img(ref)
 WHERE d.cluster_id IS NOT NULL
   AND img.ref <> ''
ON CONFLICT (org_id, cluster_id, workload_id, image_ref) DO UPDATE SET
    deployment_id        = EXCLUDED.deployment_id,
    namespace            = EXCLUDED.namespace,
    name                 = EXCLUDED.name,
    kind                 = EXCLUDED.kind,
    image_ref_normalized = EXCLUDED.image_ref_normalized,
    image_repository     = EXCLUDED.image_repository,
    image_tag            = EXCLUDED.image_tag,
    image_digest         = EXCLUDED.image_digest,
    last_seen_at         = EXCLUDED.last_seen_at;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_image_workload_links_cluster;
DROP INDEX IF EXISTS idx_image_workload_links_digest;
DROP INDEX IF EXISTS idx_image_workload_links_normalized;
DROP INDEX IF EXISTS idx_image_workload_links_ref;
DROP TABLE IF EXISTS image_workload_links;
-- +goose StatementEnd
