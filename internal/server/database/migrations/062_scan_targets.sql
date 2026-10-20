-- +goose Up
-- +goose StatementBegin
-- First-class scan targets. A scan job is an execution attempt; the target is
-- the durable object being scanned: image, workload, host, platform, registry,
-- repository, or serverless package.
CREATE TABLE IF NOT EXISTS scan_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      UUID REFERENCES clusters(id) ON DELETE SET NULL,
    type            TEXT NOT NULL,
    ref             TEXT NOT NULL,
    source_type     TEXT NOT NULL DEFAULT 'manual',
    source_ref      TEXT,
    image_ref       TEXT,
    image_digest    TEXT,
    registry_id     UUID REFERENCES registries(id) ON DELETE SET NULL,
    platform        TEXT,
    inventory_hash  TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (type IN ('image', 'workload', 'host', 'platform', 'registry', 'repository', 'serverless')),
    CHECK (source_type IN ('manual', 'registry', 'repository', 'runtime-agent', 'discoverer', 'platform', 'host'))
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_scan_targets_identity
    ON scan_targets (
        org_id,
        COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid),
        type,
        ref,
        source_type,
        COALESCE(source_ref, '')
    );

CREATE INDEX IF NOT EXISTS idx_scan_targets_org_type
    ON scan_targets(org_id, type, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_targets_cluster_type
    ON scan_targets(org_id, cluster_id, type, last_seen_at DESC)
    WHERE cluster_id IS NOT NULL;

ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES scan_targets(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

INSERT INTO scan_targets (
    org_id, type, ref, source_type, image_ref, image_digest, registry_id,
    platform, first_seen_at, last_seen_at
)
SELECT DISTINCT
       sj.org_id,
       'image',
       sj.image_ref,
       CASE WHEN sj.registry_id IS NOT NULL THEN 'registry' ELSE 'manual' END,
       sj.image_ref,
       sj.image_digest,
       sj.registry_id,
       sj.platform,
       MIN(sj.requested_at),
       MAX(COALESCE(sj.finished_at, sj.claimed_at, sj.requested_at))
  FROM scan_jobs sj
 WHERE sj.image_ref IS NOT NULL AND sj.image_ref <> ''
 GROUP BY sj.org_id, sj.image_ref, sj.image_digest, sj.registry_id, sj.platform
ON CONFLICT DO NOTHING;

UPDATE scan_jobs sj
   SET target_id = st.id
  FROM scan_targets st
 WHERE sj.target_id IS NULL
   AND st.org_id = sj.org_id
   AND st.type = 'image'
   AND st.ref = sj.image_ref
   AND st.source_type = CASE WHEN sj.registry_id IS NOT NULL THEN 'registry' ELSE 'manual' END
   AND COALESCE(st.source_ref, '') = '';

ALTER TABLE scan_jobs
    ALTER COLUMN target_id SET NOT NULL,
    ALTER COLUMN image_ref DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scan_jobs_target
    ON scan_jobs(org_id, target_id, status, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_lease
    ON scan_jobs(status, lease_expires_at)
    WHERE status = 'running' AND lease_expires_at IS NOT NULL;

DROP INDEX IF EXISTS idx_scan_jobs_registry_dedupe;
ALTER TABLE scan_jobs
    DROP COLUMN IF EXISTS image_ref,
    DROP COLUMN IF EXISTS platform,
    DROP COLUMN IF EXISTS registry_id,
    DROP COLUMN IF EXISTS image_digest;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS scan_target_id UUID REFERENCES scan_targets(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS target_type TEXT,
    ADD COLUMN IF NOT EXISTS target_ref TEXT,
    ADD COLUMN IF NOT EXISTS target_cluster_id UUID REFERENCES clusters(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS source_type TEXT;

UPDATE findings f
   SET target_type = 'image',
       target_ref = f.detail_json->>'image_ref',
       source_type = COALESCE(NULLIF(f.source_type, ''), 'manual')
 WHERE f.target_type IS NULL
   AND f.detail_json ? 'image_ref';

CREATE INDEX IF NOT EXISTS idx_findings_scan_target
    ON findings(org_id, scan_target_id, lifecycle, last_seen_at DESC)
    WHERE scan_target_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_findings_target
    ON findings(org_id, target_type, lifecycle, last_seen_at DESC)
    WHERE target_type IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_findings_target_cluster
    ON findings(org_id, target_cluster_id, target_type, lifecycle, last_seen_at DESC)
    WHERE target_cluster_id IS NOT NULL;
-- +goose StatementEnd
