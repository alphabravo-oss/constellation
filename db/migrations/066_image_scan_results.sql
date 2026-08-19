-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS image_scan_results (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                 UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    scan_target_id         UUID REFERENCES scan_targets(id) ON DELETE SET NULL,
    last_scan_job_id       UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    asset_id               UUID REFERENCES assets(id) ON DELETE SET NULL,
    image_ref              TEXT NOT NULL,
    image_ref_normalized   TEXT NOT NULL,
    image_repository       TEXT NOT NULL,
    image_tag              TEXT,
    image_digest           TEXT NOT NULL,
    platform               TEXT NOT NULL DEFAULT '',
    scanner_profile        TEXT NOT NULL DEFAULT 'default',
    vulndb_bundle_version  TEXT NOT NULL DEFAULT '',
    vulndb_bundle_hash     TEXT NOT NULL DEFAULT '',
    package_count          INT NOT NULL DEFAULT 0,
    finding_count          INT NOT NULL DEFAULT 0,
    bundle_metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scanned_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (image_digest LIKE 'sha256:%'),
    UNIQUE (
        org_id,
        image_digest,
        platform,
        scanner_profile,
        vulndb_bundle_version,
        vulndb_bundle_hash
    )
);

CREATE INDEX IF NOT EXISTS idx_image_scan_results_org_scanned
    ON image_scan_results(org_id, last_scanned_at DESC);

CREATE INDEX IF NOT EXISTS idx_image_scan_results_digest
    ON image_scan_results(org_id, image_digest, last_scanned_at DESC);

CREATE INDEX IF NOT EXISTS idx_image_scan_results_target
    ON image_scan_results(org_id, scan_target_id, last_scanned_at DESC)
    WHERE scan_target_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS image_scan_findings (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    image_scan_result_id  UUID NOT NULL REFERENCES image_scan_results(id) ON DELETE CASCADE,
    finding_key           TEXT NOT NULL,
    external_id           TEXT,
    title                 TEXT NOT NULL,
    description           TEXT,
    severity              TEXT NOT NULL,
    risk_score            INT NOT NULL DEFAULT 0,
    canonical_engine      TEXT,
    engines               JSONB NOT NULL DEFAULT '[]'::jsonb,
    package_ecosystem     TEXT,
    package_name          TEXT,
    package_version       TEXT,
    package_purl          TEXT,
    fixed_version         TEXT,
    detail_json           JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, image_scan_result_id, finding_key)
);

CREATE INDEX IF NOT EXISTS idx_image_scan_findings_result
    ON image_scan_findings(image_scan_result_id, severity, risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_image_scan_findings_external
    ON image_scan_findings(org_id, external_id)
    WHERE external_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS image_scan_findings;
DROP TABLE IF EXISTS image_scan_results;
-- +goose StatementEnd
