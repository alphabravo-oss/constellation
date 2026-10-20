-- +goose Up
-- +goose StatementBegin
ALTER TABLE registries
    ADD COLUMN IF NOT EXISTS scan_policy JSONB NOT NULL DEFAULT '{
      "include_repos": ["*"],
      "exclude_repos": [],
      "tag_selection": "all",
      "max_age": "",
      "rescan_interval": "",
      "block_promotion_threshold": "critical"
    }'::jsonb;

ALTER TABLE registry_images
    ADD COLUMN IF NOT EXISTS digests JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS registry_id UUID REFERENCES registries(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS image_digest TEXT,
    ADD COLUMN IF NOT EXISTS enqueue_reason TEXT,
    ADD COLUMN IF NOT EXISTS registry_policy_hash TEXT,
    ADD COLUMN IF NOT EXISTS vulndb_bundle_version TEXT;

CREATE INDEX IF NOT EXISTS idx_scan_jobs_registry_dedupe
    ON scan_jobs (org_id, registry_id, image_digest, registry_policy_hash, vulndb_bundle_version, status, requested_at DESC)
    WHERE registry_id IS NOT NULL AND image_digest IS NOT NULL;
-- +goose StatementEnd
